"""
WebSocket direct-connection platform adapter.

Runs an aiohttp WebSocket server that allows external clients (galgame
frontends, custom UIs, debugging tools) to connect directly to the
gateway and use its full capabilities — including streaming edit,
interrupt, approval, clarify, and media delivery.

Wire protocol
-------------
All frames are JSON text.  Each message is an object with a ``type``
field and an optional ``payload`` object.

Server → Client events:

    message.create   — first chunk of a new assistant message
    message.edit     — streaming update (finalize=true marks completion)
    message.delete   — delete a previously sent message
    message.image    — image delivery
    message.voice    — voice / audio delivery
    message.video    — video delivery
    message.document — document / file delivery
    message.animation — GIF / animation delivery
    typing.start     — agent started thinking
    typing.stop      — agent stopped thinking
    approval.request — agent asks for approval (dangerous command)
    slash.confirm    — slash command confirmation prompt
    processing.start — message processing started
    processing.complete — message processing finished
    error            — error notification

Client → Server requests:

    user.message       — send a text message (with optional images)
    user.file          — send a file (image, audio, video, document)
    approval.respond   — respond to an approval request
    slash.confirm.respond — respond to a slash-confirm prompt
    session.interrupt  — interrupt current agent processing

Authentication
--------------
If ``WS_DIRECT_KEY`` / ``platforms.ws_direct.key`` is set, clients must
send ``{"type": "auth", "payload": {"key": "..."}}`` as their first
message.  Unauthenticated connections are closed after a short grace
period.

Configuration
-------------
Environment variables:

    WS_DIRECT_ENABLED   — set to "true" / "1" / "yes" to enable
    WS_DIRECT_KEY       — authentication secret (recommended)
    WS_DIRECT_HOST      — bind address (default: 127.0.0.1)
    WS_DIRECT_PORT      — bind port (default: 8650)

config.yaml:

    platforms:
      ws_direct:
        enabled: true
        key: "your-secret-key"
        host: "127.0.0.1"
        port: 8650

Requires:
- aiohttp (already available in the gateway)
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import itertools
import json
import logging
import mimetypes
import os
import socket as _socket
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None  # type: ignore[assignment]

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    ProcessingOutcome,
    SendResult,
    SessionSource,
    is_network_accessible,
)

logger = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8650
AUTH_GRACE_SECONDS = 10
MAX_MESSAGE_LENGTH = 65536


def _coerce_port(value: Any, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def check_ws_direct_requirements() -> bool:
    return AIOHTTP_AVAILABLE


class WSDirectAdapter(BasePlatformAdapter):
    """
    WebSocket direct-connection platform adapter.

    Provides a full-duplex WebSocket endpoint so external clients can
    interact with the gateway using the same capabilities available to
    Telegram/Discord/etc.: streaming edit, interrupt, approval, clarify,
    media delivery, and session management.
    """

    REQUIRES_EDIT_FINALIZE: bool = True
    MAX_MESSAGE_LENGTH: int = MAX_MESSAGE_LENGTH

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.WS_DIRECT)
        extra = config.extra or {}
        self._host: str = extra.get("host", os.getenv("WS_DIRECT_HOST", DEFAULT_HOST))
        raw_port = extra.get("port")
        if raw_port is None:
            raw_port = os.getenv("WS_DIRECT_PORT", str(DEFAULT_PORT))
        self._port: int = _coerce_port(raw_port, DEFAULT_PORT)
        self._auth_key: str = extra.get("key", os.getenv("WS_DIRECT_KEY", ""))
        self._app: Optional[Any] = None
        self._runner: Optional[Any] = None
        self._site: Optional[Any] = None
        self._clients: Dict[str, Set[Any]] = {}
        self._approval_state: Dict[int, str] = {}
        self._approval_counter = itertools.count(1)
        self._slash_confirm_state: Dict[str, str] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._message_id_counter = itertools.count(1)
        self._last_sent_content: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> bool:
        if not AIOHTTP_AVAILABLE:
            logger.warning("[%s] aiohttp not installed", self.name)
            return False

        try:
            self._app = web.Application()
            self._app["ws_direct_adapter"] = self
            self._app.router.add_get("/ws", self._handle_ws)
            self._app.router.add_get("/health", self._handle_health)
            self._app.router.add_get("/files/{path:.*}", self._handle_file)

            if is_network_accessible(self._host) and not self._auth_key:
                logger.error(
                    "[%s] Refusing to start: binding to %s requires WS_DIRECT_KEY. "
                    "Set WS_DIRECT_KEY or use the default 127.0.0.1.",
                    self.name, self._host,
                )
                return False

            if is_network_accessible(self._host) and self._auth_key:
                try:
                    from hermes_cli.auth import has_usable_secret
                    if not has_usable_secret(self._auth_key, min_length=8):
                        logger.error(
                            "[%s] Refusing to start: WS_DIRECT_KEY is set to a "
                            "placeholder value. Generate a real secret "
                            "(e.g. `openssl rand -hex 32`) and set WS_DIRECT_KEY "
                            "before exposing the WebSocket server on %s.",
                            self.name, self._host,
                        )
                        return False
                except ImportError:
                    pass

            try:
                with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect(("127.0.0.1", self._port))
                logger.error(
                    "[%s] Port %d already in use. Set a different port via "
                    "WS_DIRECT_PORT or config.yaml: platforms.ws_direct.port",
                    self.name, self._port,
                )
                return False
            except (ConnectionRefusedError, OSError):
                pass

            self._runner = web.AppRunner(self._app)
            await self._runner.setup()
            self._site = web.TCPSite(self._runner, self._host, self._port)
            await self._site.start()

            self._loop = asyncio.get_running_loop()
            self._mark_connected()

            if not self._auth_key:
                logger.warning(
                    "[%s] No auth key configured (WS_DIRECT_KEY / platforms.ws_direct.key). "
                    "All connections will be accepted without authentication. "
                    "Set an auth key for production deployments.",
                    self.name,
                )
            logger.info(
                "[%s] WebSocket server listening on ws://%s:%d/ws",
                self.name, self._host, self._port,
            )
            return True

        except Exception as e:
            logger.error("[%s] Failed to start WebSocket server: %s", self.name, e)
            return False

    async def disconnect(self) -> None:
        for chat_id, clients in list(self._clients.items()):
            for ws in list(clients):
                try:
                    await ws.close(code=1001, message=b"Server shutting down")
                except Exception:
                    pass
            clients.clear()
        self._clients.clear()
        if self._site:
            await self._site.stop()
            self._site = None
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        self._app = None
        self._mark_disconnected()
        logger.info("[%s] WebSocket server stopped", self.name)

    # ------------------------------------------------------------------
    # HTTP / WebSocket handlers
    # ------------------------------------------------------------------

    async def _handle_health(self, request: Any) -> Any:
        return web.json_response({
            "status": "ok",
            "platform": "ws_direct",
            "host": self._host,
            "port": self._port,
            "connected_clients": sum(len(c) for c in self._clients.values()),
        })

    async def _handle_file(self, request: Any) -> Any:
        rel_path = request.match_info.get("path", "")
        file_path = urllib.parse.unquote(rel_path)

        if not os.path.isfile(file_path):
            return web.Response(status=404, text="File not found")

        if self._auth_key:
            token = request.query.get("token", "")
            if not hmac.compare_digest(token, self._auth_key):
                return web.Response(status=403, text="Forbidden")

        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = "application/octet-stream"

        try:
            return web.FileResponse(file_path)
        except Exception:
            return web.Response(status=500, text="Internal server error")

    async def _handle_ws(self, request: Any) -> Any:
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)

        chat_id = request.query.get("chat_id", "default")
        user_id = request.query.get("user_id", "player")
        user_name = request.query.get("user_name", "Player")

        authenticated = not bool(self._auth_key)

        if self._auth_key:
            try:
                auth_msg = await asyncio.wait_for(
                    ws.receive_json(), timeout=AUTH_GRACE_SECONDS,
                )
                if (
                    isinstance(auth_msg, dict)
                    and auth_msg.get("type") == "auth"
                    and hmac.compare_digest(
                        auth_msg.get("payload", {}).get("key", ""),
                        self._auth_key,
                    )
                ):
                    authenticated = True
                    await ws.send_str(json.dumps({"type": "auth.ok"}))
                else:
                    await ws.send_str(json.dumps({
                        "type": "auth.error",
                        "payload": {"message": "Invalid authentication key"},
                    }))
                    await ws.close(code=4001, message=b"Authentication failed")
                    return ws
            except (asyncio.TimeoutError, Exception):
                await ws.send_str(json.dumps({
                    "type": "auth.error",
                    "payload": {"message": "Authentication timeout"},
                }))
                await ws.close(code=4001, message=b"Authentication timeout")
                return ws

        self._clients.setdefault(chat_id, set()).add(ws)
        logger.info(
            "[%s] Client connected: chat_id=%s user_id=%s (total: %d)",
            self.name, chat_id, user_id,
            sum(len(c) for c in self._clients.values()),
        )

        await ws.send_str(json.dumps({
            "type": "connected",
            "payload": {
                "chat_id": chat_id,
                "message": "Connected to Hermes Gateway via WebSocket",
            },
        }))

        try:
            async for msg in ws:
                if msg.type == 1:  # aiohttp.WSMsgType.TEXT
                    try:
                        payload = json.loads(msg.data)
                    except (json.JSONDecodeError, TypeError):
                        await ws.send_str(json.dumps({
                            "type": "error",
                            "payload": {"message": "Invalid JSON"},
                        }))
                        continue
                    await self._on_client_message(
                        chat_id, user_id, user_name, payload,
                    )
                elif msg.type in (8, 256):  # ERROR or CLOSE
                    break
        except Exception:
            pass
        finally:
            clients = self._clients.get(chat_id)
            if clients:
                clients.discard(ws)
                if not clients:
                    del self._clients[chat_id]
            logger.info(
                "[%s] Client disconnected: chat_id=%s user_id=%s",
                self.name, chat_id, user_id,
            )

        return ws

    # ------------------------------------------------------------------
    # Client message dispatch
    # ------------------------------------------------------------------

    async def _on_client_message(
        self,
        chat_id: str,
        user_id: str,
        user_name: str,
        payload: Dict[str, Any],
    ) -> None:
        msg_type = payload.get("type")
        msg_payload = payload.get("payload", {})

        if msg_type == "user.message":
            text = msg_payload.get("text", "")
            if not text:
                return

            source = SessionSource(
                platform=Platform.WS_DIRECT,
                chat_id=chat_id,
                chat_type="dm",
                user_id=user_id,
                user_name=user_name,
                chat_name=f"WS:{chat_id}",
            )

            images = msg_payload.get("images", [])
            media_urls = []
            media_types = []
            message_type = MessageType.TEXT

            if text.startswith("/"):
                message_type = MessageType.COMMAND

            if images:
                if message_type == MessageType.TEXT:
                    message_type = MessageType.PHOTO
                for img in images:
                    if img.startswith("data:"):
                        local_path = self._cache_data_url(img)
                        if local_path:
                            media_urls.append(local_path)
                            mime = img.split(";")[0].split(":")[1] if ":" in img else "image/png"
                            media_types.append(mime)
                    else:
                        media_urls.append(img)
                        media_types.append("image/png")

            event = MessageEvent(
                text=text,
                message_type=message_type,
                source=source,
                raw_message=payload,
                media_urls=media_urls,
                media_types=media_types,
            )
            await self.handle_message(event)

        elif msg_type == "user.file":
            await self._handle_user_file(chat_id, user_id, user_name, msg_payload)

        elif msg_type == "approval.respond":
            request_id = msg_payload.get("request_id", "")
            approval_id = msg_payload.get("approval_id")
            choice = msg_payload.get("choice", "")
            session_key = self._approval_state.pop(approval_id, None) if approval_id else None
            if session_key and choice:
                try:
                    from tools.approval import resolve_gateway_approval
                    count = resolve_gateway_approval(session_key, choice)
                    logger.info(
                        "[%s] Approval resolved: %d for session %s (choice=%s)",
                        self.name, count, session_key, choice,
                    )
                except Exception as exc:
                    logger.error("[%s] Failed to resolve approval: %s", self.name, exc)

        elif msg_type == "slash.confirm.respond":
            confirm_id = msg_payload.get("confirm_id", "")
            choice = msg_payload.get("choice", "")
            session_key = self._slash_confirm_state.pop(confirm_id, None)
            if session_key and choice:
                try:
                    from tools.approval import resolve_gateway_approval
                    count = resolve_gateway_approval(session_key, choice)
                    logger.info(
                        "[%s] Slash confirm resolved: %d for session %s (choice=%s)",
                        self.name, count, session_key, choice,
                    )
                except Exception as exc:
                    logger.error("[%s] Failed to resolve slash confirm: %s", self.name, exc)

        elif msg_type == "session.interrupt":
            session_key_parts = [Platform.WS_DIRECT.value, "dm", chat_id]
            session_key = ":".join(session_key_parts)
            await self.cancel_session_processing(session_key)

    # ------------------------------------------------------------------
    # File upload handling
    # ------------------------------------------------------------------

    _MIME_TO_MESSAGE_TYPE = {
        "image": MessageType.PHOTO,
        "audio": MessageType.AUDIO,
        "video": MessageType.VIDEO,
    }

    _MIME_TO_EXT = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/gif": ".gif",
        "image/webp": ".webp",
        "audio/ogg": ".ogg",
        "audio/mpeg": ".mp3",
        "audio/wav": ".wav",
        "audio/mp4": ".m4a",
        "video/mp4": ".mp4",
        "video/webm": ".webm",
        "application/pdf": ".pdf",
        "text/plain": ".txt",
        "text/markdown": ".md",
        "application/json": ".json",
        "application/zip": ".zip",
    }

    def _cache_uploaded_file(self, data: bytes, mime_type: str, filename: str = "") -> str:
        from gateway.platforms.base import get_image_cache_dir

        ext = self._MIME_TO_EXT.get(mime_type)
        if not ext:
            guessed_ext = mimetypes.guess_extension(mime_type)
            ext = guessed_ext if guessed_ext else Path(filename).suffix or ".bin"

        if mime_type.startswith("image/"):
            cache_dir = get_image_cache_dir()
        else:
            cache_dir = get_image_cache_dir().parent / "files"
            cache_dir.mkdir(parents=True, exist_ok=True)

        safe_name = Path(filename).stem if filename else f"upload_{uuid.uuid4().hex[:8]}"
        unique_name = f"{safe_name}_{uuid.uuid4().hex[:6]}{ext}"
        filepath = cache_dir / unique_name
        filepath.write_bytes(data)
        return str(filepath)

    def _cache_data_url(self, data_url: str) -> Optional[str]:
        try:
            if ";base64," not in data_url:
                return None
            header, encoded = data_url.split(";base64,", 1)
            mime_type = header.split(":", 1)[1] if ":" in header else "image/png"
            file_data = base64.b64decode(encoded)
            return self._cache_uploaded_file(file_data, mime_type)
        except Exception as exc:
            logger.warning("[%s] Failed to cache data URL: %s", self.name, exc)
            return None

    async def _handle_user_file(
        self,
        chat_id: str,
        user_id: str,
        user_name: str,
        payload: Dict[str, Any],
    ) -> None:
        data_b64 = payload.get("data", "")
        mime_type = payload.get("mime_type", "application/octet-stream")
        filename = payload.get("filename", "")
        caption = payload.get("caption", "")

        if not data_b64:
            logger.warning("[%s] user.file missing data field", self.name)
            return

        try:
            file_data = base64.b64decode(data_b64)
        except Exception as exc:
            logger.warning("[%s] user.file base64 decode failed: %s", self.name, exc)
            return

        max_size = 50 * 1024 * 1024
        if len(file_data) > max_size:
            logger.warning("[%s] user.file too large: %d bytes", self.name, len(file_data))
            return

        local_path = self._cache_uploaded_file(file_data, mime_type, filename)

        source = SessionSource(
            platform=Platform.WS_DIRECT,
            chat_id=chat_id,
            chat_type="dm",
            user_id=user_id,
            user_name=user_name,
            chat_name=f"WS:{chat_id}",
        )

        msg_type = self._MIME_TO_MESSAGE_TYPE.get(mime_type.split("/")[0], MessageType.DOCUMENT)

        text = caption or filename or f"Uploaded file ({mime_type})"

        event = MessageEvent(
            text=text,
            message_type=msg_type,
            source=source,
            raw_message={"type": "user.file", "payload": payload},
            media_urls=[local_path],
            media_types=[mime_type],
        )
        await self.handle_message(event)

    # ------------------------------------------------------------------
    # Outbound message methods (Gateway → Client)
    # ------------------------------------------------------------------

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        if not content or not content.strip():
            return SendResult(success=True, message_id=None)

        chunks = self.truncate_message(content)
        last_message_id = None
        for chunk in chunks:
            message_id = f"msg_{next(self._message_id_counter)}"
            await self._broadcast(chat_id, {
                "type": "message.create",
                "payload": {
                    "message_id": message_id,
                    "content": chunk,
                    "finalize": True,
                },
            })
            last_message_id = message_id
            self._last_sent_content[message_id] = chunk
        return SendResult(success=True, message_id=last_message_id)

    async def edit_message(
        self,
        chat_id: str,
        message_id: str,
        content: str,
        *,
        finalize: bool = False,
    ) -> SendResult:
        last_sent = self._last_sent_content.get(message_id)
        if last_sent == content and not (finalize and self.REQUIRES_EDIT_FINALIZE):
            return SendResult(success=True, message_id=message_id)

        await self._broadcast(chat_id, {
            "type": "message.edit",
            "payload": {
                "message_id": message_id,
                "content": content,
                "finalize": finalize,
            },
        })
        self._last_sent_content[message_id] = content
        if finalize:
            self._last_sent_content.pop(message_id, None)
        return SendResult(success=True, message_id=message_id)

    async def delete_message(self, chat_id: str, message_id: str) -> bool:
        self._last_sent_content.pop(message_id, None)
        await self._broadcast(chat_id, {
            "type": "message.delete",
            "payload": {"message_id": message_id},
        })
        return True

    async def send_typing(self, chat_id: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        await self._broadcast(chat_id, {"type": "typing.start"})

    async def stop_typing(self, chat_id: str) -> None:
        await self._broadcast(chat_id, {"type": "typing.stop"})

    async def send_image(
        self,
        chat_id: str,
        image_url: str,
        caption: Optional[str] = None,
        **kwargs: Any,
    ) -> SendResult:
        url = self._local_path_to_data_url(image_url)
        if url is None:
            fallback = f"🖼️ Image: {image_url}"
            if caption:
                fallback = f"{caption}\n{fallback}"
            return await self.send(chat_id=chat_id, content=fallback)
        await self._broadcast(chat_id, {
            "type": "message.image",
            "payload": {"url": url, "caption": caption},
        })
        return SendResult(success=True)

    async def send_image_file(
        self,
        chat_id: str,
        image_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        **kwargs,
    ) -> SendResult:
        url = self._local_path_to_data_url(image_path)
        if url is None:
            fallback = f"🖼️ Image: {image_path}"
            if caption:
                fallback = f"{caption}\n{fallback}"
            return await self.send(chat_id=chat_id, content=fallback)
        await self._broadcast(chat_id, {
            "type": "message.image",
            "payload": {"url": url, "caption": caption},
        })
        return SendResult(success=True)

    async def send_animation(
        self,
        chat_id: str,
        animation_url: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        url = self._local_path_to_data_url(animation_url)
        if url is None:
            fallback = f"🎬 Animation: {animation_url}"
            if caption:
                fallback = f"{caption}\n{fallback}"
            return await self.send(chat_id=chat_id, content=fallback)
        await self._broadcast(chat_id, {
            "type": "message.animation",
            "payload": {"url": url, "caption": caption},
        })
        return SendResult(success=True)

    async def send_voice(
        self,
        chat_id: str,
        audio_path: str,
        caption: Optional[str] = None,
        **kwargs: Any,
    ) -> SendResult:
        url = self._local_path_to_data_url(audio_path)
        if url is None:
            fallback = f"🔊 Audio: {audio_path}"
            if caption:
                fallback = f"{caption}\n{fallback}"
            return await self.send(chat_id=chat_id, content=fallback)
        await self._broadcast(chat_id, {
            "type": "message.voice",
            "payload": {"url": url, "caption": caption},
        })
        return SendResult(success=True)

    async def send_video(
        self,
        chat_id: str,
        video_path: str,
        caption: Optional[str] = None,
        **kwargs: Any,
    ) -> SendResult:
        url = self._local_path_to_data_url(video_path)
        if url is None:
            fallback = f"🎬 Video: {video_path}"
            if caption:
                fallback = f"{caption}\n{fallback}"
            return await self.send(chat_id=chat_id, content=fallback)
        await self._broadcast(chat_id, {
            "type": "message.video",
            "payload": {"url": url, "caption": caption},
        })
        return SendResult(success=True)

    async def send_document(
        self,
        chat_id: str,
        file_path: str,
        caption: Optional[str] = None,
        **kwargs: Any,
    ) -> SendResult:
        url = self._local_path_to_data_url(file_path)
        if url is None:
            fallback = f"📎 File: {file_path}"
            if caption:
                fallback = f"{caption}\n{fallback}"
            return await self.send(chat_id=chat_id, content=fallback)
        await self._broadcast(chat_id, {
            "type": "message.document",
            "payload": {"url": url, "filename": Path(file_path).name, "caption": caption},
        })
        return SendResult(success=True)

    async def send_multiple_images(
        self,
        chat_id: str,
        images: List[tuple],
        metadata: Optional[Dict[str, Any]] = None,
        human_delay: float = 0.0,
    ) -> None:
        for image_url, caption in images:
            if image_url.startswith("file://"):
                image_path = urllib.parse.unquote(image_url[7:])
                if image_path.startswith("/") and len(image_path) > 2 and image_path[2] == ":":
                    image_path = image_path[1:]
                await self.send_image_file(
                    chat_id=chat_id,
                    image_path=image_path,
                    caption=caption,
                )
            elif self._is_animation_url(image_url):
                await self.send_animation(
                    chat_id=chat_id,
                    animation_url=image_url,
                    caption=caption,
                )
            else:
                await self.send_image(chat_id, image_url, caption=caption)

    async def send_exec_approval(
        self,
        chat_id: str,
        command: str,
        session_key: str,
        **kwargs: Any,
    ) -> SendResult:
        approval_id = next(self._approval_counter)
        self._approval_state[approval_id] = session_key
        request_id = f"approval_{approval_id}"
        await self._broadcast(chat_id, {
            "type": "approval.request",
            "payload": {
                "request_id": request_id,
                "approval_id": approval_id,
                "command": command,
                "choices": ["once", "session", "always", "deny"],
            },
        })
        return SendResult(success=True)

    async def send_slash_confirm(
        self,
        chat_id: str,
        title: str,
        message: str,
        session_key: str,
        confirm_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        self._slash_confirm_state[confirm_id] = session_key
        await self._broadcast(chat_id, {
            "type": "slash.confirm",
            "payload": {
                "confirm_id": confirm_id,
                "title": title,
                "message": message,
                "choices": ["once", "always", "cancel"],
            },
        })
        return SendResult(success=True)

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {
            "name": f"WS Direct:{chat_id}",
            "type": "websocket",
            "host": self._host,
            "port": self._port,
            "connected_clients": len(self._clients.get(chat_id, set())),
        }

    # ------------------------------------------------------------------
    # Lifecycle hooks (called by BasePlatformAdapter)
    # ------------------------------------------------------------------

    async def on_processing_start(self, event: MessageEvent) -> None:
        chat_id = event.source.chat_id if event and event.source else None
        if chat_id and self._loop:
            asyncio.run_coroutine_threadsafe(
                self._broadcast(chat_id, {"type": "processing.start"}),
                self._loop,
            )

    async def on_processing_complete(self, event: MessageEvent, outcome: ProcessingOutcome = None) -> None:
        chat_id = event.source.chat_id if event and event.source else None
        if chat_id and self._loop:
            asyncio.run_coroutine_threadsafe(
                self._broadcast(chat_id, {
                    "type": "processing.complete",
                    "payload": {"outcome": str(outcome.value) if outcome else "success"},
                }),
                self._loop,
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _local_path_to_data_url(self, local_path: str) -> Optional[str]:
        if not local_path:
            return None
        if local_path.startswith(("http://", "https://")):
            return local_path
        if local_path.startswith("file://"):
            local_path = urllib.parse.unquote(local_path[7:])
            if local_path.startswith("/") and len(local_path) > 2 and local_path[2] == ":":
                local_path = local_path[1:]
        try:
            if not os.path.isfile(local_path):
                logger.warning("[%s] File not found for data URL: %s", self.name, local_path)
                return None
            data = Path(local_path).read_bytes()
            mime_type, _ = mimetypes.guess_type(local_path)
            if not mime_type:
                mime_type = "application/octet-stream"
            b64 = base64.b64encode(data).decode("ascii")
            return f"data:{mime_type};base64,{b64}"
        except Exception as exc:
            logger.warning("[%s] Failed to read file as data URL: %s", self.name, exc)
            return None

    async def _broadcast(self, chat_id: str, event: Dict[str, Any]) -> None:
        clients = self._clients.get(chat_id, set())
        if not clients:
            return
        data = json.dumps(event, ensure_ascii=False)
        stale: List[Any] = []
        for ws in list(clients):
            try:
                await ws.send_str(data)
            except Exception:
                stale.append(ws)
        for ws in stale:
            clients.discard(ws)
