"""HTTP-boundary security and authorization controls for the analyzer service."""

import hmac
import json
import logging
import time
from collections import deque
from dataclasses import dataclass

from fastapi import Header, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ClientIdentity:
    """Represents an authenticated caller identity."""

    client_id: str
    is_admin: bool = False


# In-memory test registry for dynamic fixture injection in test suites
_test_client_tokens: dict[str, ClientIdentity] = {}


def _tokens_match(presented: str, configured: str) -> bool:
    """Compare arbitrary header text safely without rejecting non-ASCII input."""
    return hmac.compare_digest(presented.encode("utf-8"), configured.encode("utf-8"))


def register_test_client_token(token: str, client_id: str, is_admin: bool = False) -> None:
    """Register an ephemeral token for testing authentication & multi-tenant isolation."""
    _test_client_tokens[token] = ClientIdentity(client_id=client_id, is_admin=is_admin)


def clear_test_client_tokens() -> None:
    """Clear all ephemeral test client tokens."""
    _test_client_tokens.clear()


def _parse_client_tokens_setting() -> dict[str, str]:
    """Parse configured client tokens into a dict of {token: client_id}."""
    raw = settings.api_client_tokens.strip()
    if not raw:
        return {}

    tokens: dict[str, str] = {}
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                for k, v in data.items():
                    # Format: {"client_id": "token"}
                    tokens[str(v)] = str(k)
        except (json.JSONDecodeError, RecursionError) as exc:
            logger.warning(
                "Ignoring malformed API_CLIENT_TOKENS JSON configuration (%s).",
                type(exc).__name__,
            )
        return tokens

    # Format: client_id:token,client_id2:token2
    for pair in raw.split(","):
        if ":" in pair:
            cid, tok = pair.split(":", 1)
            cid = cid.strip()
            tok = tok.strip()
            if cid and tok:
                tokens[tok] = cid
    return tokens


def authenticate_token(token: str) -> ClientIdentity | None:
    """Authenticate a token against configured credentials and test registries."""
    if not token:
        return None

    # 1. Ephemeral test tokens (used in integration tests)
    for test_token, identity in _test_client_tokens.items():
        if _tokens_match(token, test_token):
            return identity

    # 2. Primary configured service API key (admin / default client)
    expected_primary = settings.api_access_token
    if expected_primary and _tokens_match(token, expected_primary):
        return ClientIdentity(client_id="default", is_admin=True)

    # 3. Configured multi-client tokens
    client_tokens = _parse_client_tokens_setting()
    for configured_token, client_id in client_tokens.items():
        if _tokens_match(token, configured_token):
            return ClientIdentity(client_id=client_id, is_admin=False)

    return None


def get_current_client(
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> ClientIdentity:
    """Enforce authentication via X-API-Key or Bearer token header."""
    token: str | None = None
    if x_api_key:
        token = x_api_key.strip()
    elif authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        elif len(parts) == 1:
            token = parts[0]

    if not token:
        if settings.environment.strip().lower() == "development" and settings.local_dev_auth_bypass:
            return ClientIdentity(client_id="local-development", is_admin=True)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A valid X-API-Key or Bearer token is required.",
        )

    identity = authenticate_token(token)
    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
        )

    return identity


def require_api_access_token(
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> ClientIdentity:
    """Dependency requirement that validates caller identity and returns ClientIdentity."""
    return get_current_client(x_api_key=x_api_key, authorization=authorization)


def verify_scan_access(scan: object, client: ClientIdentity) -> None:
    """Enforce authorization boundary: a client may only access their own scans unless admin."""
    scan_client_id = getattr(scan, "client_id", None)
    # Legacy rows without an owner cannot safely be attributed to an arbitrary tenant.
    if not client.is_admin and (scan_client_id is None or scan_client_id != client.client_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this scan.",
        )


class ScanRateLimiter:
    """ASGI fixed-window limiter for expensive scan submissions.

    Valid callers are keyed by authenticated client identity; invalid credentials share one
    fixed bucket so attacker-controlled values cannot allocate buckets or evade throttling.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._requests: dict[str, deque[float]] = {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        path = scope.get("path", "")
        if method != "POST" or path != "/api/v1/scans":
            await self.app(scope, receive, send)
            return

        headers_raw = scope.get("headers", [])
        headers: dict[bytes, bytes] = {}
        if isinstance(headers_raw, list):
            for name, value in headers_raw:
                headers.setdefault(name.lower(), value)

        token: str | None = None
        api_key = headers.get(b"x-api-key")
        authorization = headers.get(b"authorization")
        if api_key:
            token = api_key.decode("latin1", errors="replace").strip()
        elif authorization:
            parts = authorization.decode("latin1", errors="replace").strip().split()
            if len(parts) == 2 and parts[0].lower() == "bearer":
                token = parts[1]
            elif len(parts) == 1:
                token = parts[0]

        identity = authenticate_token(token) if token else None
        if (
            identity is None
            and not token
            and settings.environment.strip().lower() == "development"
            and settings.local_dev_auth_bypass
        ):
            identity = ClientIdentity(client_id="local-development", is_admin=True)

        if identity is not None:
            key = f"client:{identity.client_id}"
        else:
            # Unknown credentials all share one bucket. An attacker cannot allocate a
            # fresh bucket with each invented token or rotate peer addresses to evade it.
            key = "unauthenticated"

        now = time.monotonic()
        cutoff = now - settings.scan_rate_limit_window_seconds
        # Remove every expired identity bucket on each scan submission. Authenticated
        # keys come only from configured client identities; untrusted values share one
        # fixed bucket, so request traffic cannot grow this map without bound.
        for bucket_key, bucket in tuple(self._requests.items()):
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if not bucket:
                del self._requests[bucket_key]

        timestamps = self._requests.get(key)
        if timestamps is None:
            timestamps = deque()
            self._requests[key] = timestamps

        if len(timestamps) >= settings.scan_rate_limit_requests:
            response = JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Scan submission rate limit exceeded. Try again later."},
                headers={"Retry-After": str(settings.scan_rate_limit_window_seconds)},
            )
            await response(scope, receive, send)
            return

        timestamps.append(now)
        await self.app(scope, receive, send)
