"""Count scan-upload body bytes before downstream multipart parsing can spool them."""

import asyncio

from fastapi import HTTPException, status
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings


class _UploadBodyTooLarge(HTTPException):
    """Raised as the downstream endpoint consumes more than the configured body budget."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Request payload exceeds the configured upload limit.",
        )


class _UploadReadTimedOut(HTTPException):
    """Raised when an upload body is not completely received before its deadline."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_408_REQUEST_TIMEOUT,
            detail="Upload body was not received before the configured timeout.",
        )


class UploadBodyLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not _is_scan_upload(scope):
            await self.app(scope, receive, send)
            return

        max_bytes = settings.max_upload_bytes
        deadline = asyncio.get_running_loop().time() + settings.upload_read_timeout_seconds
        received_bytes = 0

        async def limited_receive() -> Message:
            nonlocal received_bytes
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise _UploadReadTimedOut
            try:
                message = await asyncio.wait_for(receive(), timeout=remaining)
            except TimeoutError as exc:
                raise _UploadReadTimedOut from exc
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > max_bytes:
                    raise _UploadBodyTooLarge
            return message

        await self.app(scope, limited_receive, send)


def _is_scan_upload(scope: Scope) -> bool:
    return (
        scope.get("type") == "http"
        and scope.get("method") == "POST"
        and (scope.get("path", "").rstrip("/") == "/api/v1/scans")
    )
