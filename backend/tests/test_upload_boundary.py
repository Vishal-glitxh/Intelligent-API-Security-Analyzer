import asyncio
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest
from app.api.v1 import scans
from app.core.config import settings
from app.core.security import clear_test_client_tokens, register_test_client_token
from app.main import app
from app.services.upload_admission import UploadAdmission
from fastapi.testclient import TestClient
from starlette.requests import ClientDisconnect, Request
from starlette.types import Message

TOKEN = settings.api_access_token or "dev-insecure-api-access-token-do-not-use-in-production"
BOUNDARY = "upload-boundary-test"
CONTENT_TYPE = f"multipart/form-data; boundary={BOUNDARY}"


@pytest.fixture(autouse=True)
def isolate_upload_tests_from_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "scan_rate_limit_requests", 1_000)


def _multipart_body(
    *,
    extra_parts: tuple[tuple[str, str | None, bytes], ...] = (),
    spec: bytes = b"openapi: 3.0.3\n",
    archive: bytes = b"PK\x05\x06" + b"\x00" * 18,
    include_archive: bool = True,
    include_project: bool = True,
) -> bytes:
    parts: list[tuple[str, str | None, bytes]] = [("openapi_file", "openapi.yaml", spec)]
    if include_archive:
        parts.append(("source_archive", "source.zip", archive))
    if include_project:
        parts.append(("project_name", None, b"Upload boundary test"))
    parts.extend(extra_parts)
    chunks: list[bytes] = []
    for name, filename, value in parts:
        chunks.append(f"--{BOUNDARY}\r\n".encode())
        disposition = f'Content-Disposition: form-data; name="{name}"'
        if filename is not None:
            disposition += f'; filename="{filename}"'
        chunks.append(f"{disposition}\r\n".encode())
        if filename is not None:
            chunks.append(b"Content-Type: application/octet-stream\r\n")
        chunks.extend((b"\r\n", value, b"\r\n"))
    chunks.append(f"--{BOUNDARY}--\r\n".encode())
    return b"".join(chunks)


@contextmanager
def _mock_scan_creation() -> Iterator[Any]:
    scan_id = uuid4()
    with (
        patch(
            "app.api.v1.scans.ScanService.create_and_submit_scan", return_value=scan_id
        ) as submit,
        patch(
            "app.api.v1.scans.ScanRepository.get_scan",
            return_value=SimpleNamespace(
                id=scan_id,
                status="QUEUED",
                project_name="Upload boundary test",
                created_at=datetime.now(UTC),
            ),
        ),
    ):
        yield submit


async def _asgi_post(
    body_chunks: list[bytes],
    *,
    token: str | None = TOKEN,
    content_length: bytes | None = None,
    pause_event: asyncio.Event | None = None,
    release_event: asyncio.Event | None = None,
    pause_at_chunk: int = 1,
    disconnect_after_chunks: int | None = None,
) -> tuple[int, bytes, int]:
    headers = [(b"content-type", CONTENT_TYPE.encode())]
    if token is not None:
        headers.append((b"x-api-key", token.encode()))
    if content_length is not None:
        headers.append((b"content-length", content_length))
    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/v1/scans",
        "raw_path": b"/api/v1/scans",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    index = 0
    received = 0
    messages: list[Message] = []

    async def receive() -> dict[str, Any]:
        nonlocal index, received
        if disconnect_after_chunks is not None and index >= disconnect_after_chunks:
            return {"type": "http.disconnect"}
        if index < len(body_chunks):
            chunk = body_chunks[index]
            index += 1
            received += len(chunk)
            if index == pause_at_chunk and pause_event is not None:
                pause_event.set()
                if release_event is not None:
                    await release_event.wait()
            return {
                "type": "http.request",
                "body": chunk,
                "more_body": index < len(body_chunks),
            }
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        messages.append(message)

    await app(scope, receive, send)
    status_code = next(m["status"] for m in messages if m["type"] == "http.response.start")
    response_body = b"".join(
        m.get("body", b"") for m in messages if m["type"] == "http.response.body"
    )
    return status_code, response_body, received


def _chunk(data: bytes, size: int = 31) -> list[bytes]:
    return [data[offset : offset + size] for offset in range(0, len(data), size)]


def test_authentication_precedes_multipart_parsing() -> None:
    client = TestClient(app)
    with patch.object(
        Request, "form", side_effect=AssertionError("form parsed before auth")
    ) as form:
        response = client.post(
            "/api/v1/scans",
            content=b"malformed unauthenticated request body",
            headers={"Content-Type": CONTENT_TYPE},
        )
    assert response.status_code == 401
    form.assert_not_called()
    assert scans.upload_admission.active_counts() == (0, {})


def test_valid_multipart_contract_and_exact_body_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    body = _multipart_body()
    monkeypatch.setattr(settings, "max_upload_bytes", len(body))
    with _mock_scan_creation() as submit:
        status_code, response_body, received = asyncio.run(
            _asgi_post(_chunk(body), content_length=str(len(body)).encode())
        )
    assert status_code == 202
    assert b"scan_id" in response_body
    assert received == len(body)
    submit.assert_called_once()
    assert scans.upload_admission.active_counts() == (0, {})


def test_openapi_only_scan_is_accepted_when_source_archive_is_omitted() -> None:
    body = _multipart_body(include_archive=False)
    with _mock_scan_creation() as submit:
        response = TestClient(app).post(
            "/api/v1/scans",
            content=body,
            headers={"X-API-Key": TOKEN, "Content-Type": CONTENT_TYPE},
        )

    assert response.status_code == 202
    submit.assert_called_once()
    assert submit.call_args.kwargs["source_filename"] == "Not provided"
    assert submit.call_args.kwargs["source_bytes"] == b""
    assert scans.upload_admission.active_counts() == (0, {})


def test_slow_scan_orchestration_does_not_block_same_event_loop() -> None:
    import httpx

    body = _multipart_body()
    scan_id = uuid4()
    event_loop_progressed = threading.Event()
    health_response: dict[str, Any] = {}
    progress_during_scan: list[bool] = []

    async def exercise() -> tuple[int, bool]:
        from app.db.session import get_db

        async def health_probe(client: httpx.AsyncClient) -> None:
            health_response["response"] = await client.get("/health")
            event_loop_progressed.set()

        def slow_scan(*args: Any, **kwargs: Any) -> Any:
            # Give the event loop time to dispatch a second request while this
            # synchronous orchestration is occupied in a worker thread.
            progress_during_scan.append(event_loop_progressed.wait(timeout=0.5))
            time.sleep(0.1)
            return scan_id

        app.dependency_overrides[get_db] = lambda: object()
        try:
            with (
                patch("app.api.v1.scans.ScanService.create_and_submit_scan", slow_scan),
                patch(
                    "app.api.v1.scans.ScanRepository.get_scan",
                    return_value=SimpleNamespace(
                        id=scan_id,
                        status="QUEUED",
                        project_name="Upload boundary test",
                        created_at=datetime.now(UTC),
                    ),
                ),
            ):
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="http://testserver"
                ) as client:
                    loop = asyncio.get_running_loop()
                    loop.call_later(0.02, lambda: asyncio.create_task(health_probe(client)))
                    response = await client.post(
                        "/api/v1/scans",
                        content=body,
                        headers={"X-API-Key": TOKEN, "Content-Type": CONTENT_TYPE},
                    )
                    if not event_loop_progressed.is_set():
                        await asyncio.wait_for(asyncio.to_thread(event_loop_progressed.wait), 1.0)
                    health_status = health_response["response"].status_code
                    return (
                        response.status_code,
                        health_status == 200 and progress_during_scan == [True],
                    )
        finally:
            app.dependency_overrides.pop(get_db, None)

    scan_status, health_served_during_scan = asyncio.run(exercise())
    assert scan_status == 202
    assert health_served_during_scan
    assert scans.upload_admission.active_counts() == (0, {})


def test_cancelled_scan_request_keeps_admission_until_orchestration_finishes() -> None:
    import httpx
    from app.db.session import get_db

    body = _multipart_body()
    scan_id = uuid4()
    entered = threading.Event()
    release = threading.Event()

    def slow_scan(*args: Any, **kwargs: Any) -> Any:
        entered.set()
        release.wait(timeout=2.0)
        return scan_id

    async def exercise() -> tuple[bool, bool]:
        app.dependency_overrides[get_db] = lambda: object()
        try:
            with (
                patch("app.api.v1.scans.ScanService.create_and_submit_scan", slow_scan),
                patch(
                    "app.api.v1.scans.ScanRepository.get_scan",
                    return_value=SimpleNamespace(
                        id=scan_id,
                        status="QUEUED",
                        project_name="Upload boundary test",
                        created_at=datetime.now(UTC),
                    ),
                ),
            ):
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="http://testserver"
                ) as client:
                    request = asyncio.create_task(
                        client.post(
                            "/api/v1/scans",
                            content=body,
                            headers={"X-API-Key": TOKEN, "Content-Type": CONTENT_TYPE},
                        )
                    )
                    assert await asyncio.wait_for(asyncio.to_thread(entered.wait), timeout=1.0)
                    request.cancel()
                    await asyncio.sleep(0.05)
                    remains_reserved = scans.upload_admission.active_counts()[0] == 1
                    remains_running = not request.done()
                    release.set()
                    with pytest.raises(asyncio.CancelledError):
                        await request
                    return remains_reserved, remains_running
        finally:
            release.set()
            app.dependency_overrides.pop(get_db, None)

    reserved, running = asyncio.run(exercise())
    assert reserved and running
    assert scans.upload_admission.active_counts() == (0, {})


@pytest.mark.parametrize("length_kind", ["missing", "malformed", "understated"])
def test_actual_body_limit_catches_chunked_and_false_lengths(
    monkeypatch: pytest.MonkeyPatch, length_kind: str
) -> None:
    body = _multipart_body(spec=b"x" * 400)
    monkeypatch.setattr(settings, "max_upload_bytes", 180)
    declared = {
        "missing": None,
        "malformed": b"not-a-number",
        "understated": b"12",
    }[length_kind]
    status_code, response_body, received = asyncio.run(
        _asgi_post(_chunk(body, 64), content_length=declared)
    )
    assert status_code == 413
    assert b"configured upload limit" in response_body
    assert received <= 180 + 64
    assert scans.upload_admission.active_counts() == (0, {})


def test_declared_oversize_is_rejected_before_reading(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "max_upload_bytes", 100)
    status_code, _, received = asyncio.run(_asgi_post([b"not-read"], content_length=b"101"))
    assert status_code == 413
    assert received == 0


def test_oversize_stream_closes_parser_tempfile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import starlette.formparsers

    real_spooled_file = vars(starlette.formparsers)["SpooledTemporaryFile"]
    opened = []

    def track_spooled_file(*args: Any, **kwargs: Any) -> Any:
        file = real_spooled_file(*args, **kwargs)
        opened.append(file)
        return file

    monkeypatch.setattr(settings, "max_upload_bytes", 300)
    monkeypatch.setattr("starlette.formparsers.SpooledTemporaryFile", track_spooled_file)
    file_header = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="openapi_file"; '
        'filename="openapi.yaml"\r\nContent-Type: application/octet-stream\r\n\r\n'
    ).encode()
    status_code, _, _ = asyncio.run(
        _asgi_post([file_header + b"a" * 40, b"b" * 200], content_length=None)
    )
    assert status_code == 413
    assert opened
    assert all(file.closed for file in opened)
    assert scans.upload_admission.active_counts() == (0, {})


@pytest.mark.parametrize(
    ("body", "expected_status"),
    [
        (
            _multipart_body(
                include_archive=False,
                extra_parts=(("openapi_file", "again.yaml", b"duplicate"),),
            ),
            422,
        ),
        (
            _multipart_body(
                include_project=False,
                extra_parts=(("unexpected", None, b"value"),),
            ),
            422,
        ),
        (_multipart_body(extra_parts=(("extra_file", "extra.txt", b"value"),)), 400),
        (_multipart_body(extra_parts=(("other_field", None, b"value"),)), 400),
    ],
)
def test_unexpected_duplicate_and_excess_parts_are_rejected(
    body: bytes, expected_status: int
) -> None:
    response = TestClient(app).post(
        "/api/v1/scans",
        content=body,
        headers={"X-API-Key": TOKEN, "Content-Type": CONTENT_TYPE},
    )
    assert response.status_code == expected_status
    assert scans.upload_admission.active_counts() == (0, {})


def test_malformed_multipart_releases_admission() -> None:
    response = TestClient(app, headers={"X-API-Key": TOKEN}).post(
        "/api/v1/scans",
        content=b"--incomplete",
        headers={"X-API-Key": TOKEN, "Content-Type": CONTENT_TYPE},
    )
    assert response.status_code == 400
    assert scans.upload_admission.active_counts() == (0, {})


@pytest.mark.parametrize("which_file", ["spec", "archive"])
def test_per_file_caps_still_reject_after_bounded_parse(
    monkeypatch: pytest.MonkeyPatch, which_file: str
) -> None:
    if which_file == "spec":
        body = _multipart_body(spec=b"x" * 9)
        monkeypatch.setattr(settings, "max_spec_bytes", 8)
    else:
        body = _multipart_body(archive=b"x" * 9)
        monkeypatch.setattr(settings, "max_archive_bytes", 8)
    response = TestClient(app, headers={"X-API-Key": TOKEN}).post(
        "/api/v1/scans",
        content=body,
        headers={"X-API-Key": TOKEN, "Content-Type": CONTENT_TYPE},
    )
    assert response.status_code == 413
    assert scans.upload_admission.active_counts() == (0, {})


def test_concurrent_global_and_per_client_admission_is_released() -> None:
    admission = UploadAdmission(max_global=2, max_per_client=1)
    body = _multipart_body()
    first_started = asyncio.Event()
    release_first = asyncio.Event()
    beta_started = asyncio.Event()
    release_beta = asyncio.Event()
    register_test_client_token("upload-alpha", "alpha")
    register_test_client_token("upload-beta", "beta")
    register_test_client_token("upload-gamma", "gamma")

    async def exercise() -> tuple[tuple[int, bytes, int], ...]:
        with patch.object(scans, "upload_admission", admission), _mock_scan_creation():
            first = asyncio.create_task(
                _asgi_post(
                    [body[:80], body[80:]],
                    token="upload-alpha",
                    content_length=str(len(body)).encode(),
                    pause_event=first_started,
                    release_event=release_first,
                )
            )
            await first_started.wait()
            same_client = await _asgi_post([body], token="upload-alpha")
            beta = asyncio.create_task(
                _asgi_post(
                    [body[:80], body[80:]],
                    token="upload-beta",
                    content_length=str(len(body)).encode(),
                    pause_event=beta_started,
                    release_event=release_beta,
                )
            )
            await beta_started.wait()
            global_full = await _asgi_post([body], token="upload-gamma")
            release_first.set()
            release_beta.set()
            first_result, beta_result = await asyncio.gather(first, beta)
            return same_client, beta_result, global_full, first_result

    try:
        same_client, other_client, global_full, first = asyncio.run(exercise())
        assert same_client[0] == 429
        assert same_client[2] == 0
        assert other_client[0] == 202
        assert global_full[0] == 429
        assert global_full[2] == 0
        assert first[0] == 202
        assert admission.active_counts() == (0, {})
    finally:
        clear_test_client_tokens()


def test_cancelled_multipart_request_closes_tempfile_and_releases_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import starlette.formparsers

    real_spooled_file = vars(starlette.formparsers)["SpooledTemporaryFile"]
    opened = []

    def track_spooled_file(*args: Any, **kwargs: Any) -> Any:
        file = real_spooled_file(*args, **kwargs)
        opened.append(file)
        return file

    monkeypatch.setattr("starlette.formparsers.SpooledTemporaryFile", track_spooled_file)
    file_header = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="openapi_file"; '
        'filename="openapi.yaml"\r\nContent-Type: application/octet-stream\r\n\r\n'
    ).encode()

    async def exercise() -> None:
        paused = asyncio.Event()
        never_release = asyncio.Event()
        request = asyncio.create_task(
            _asgi_post(
                [file_header + b"partial", b"remaining"],
                pause_event=paused,
                release_event=never_release,
                pause_at_chunk=2,
            )
        )
        await paused.wait()
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request

    asyncio.run(exercise())
    assert opened and all(file.closed for file in opened)
    assert scans.upload_admission.active_counts() == (0, {})


def test_upload_read_deadline_closes_tempfile_and_releases_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import starlette.formparsers

    real_spooled_file = vars(starlette.formparsers)["SpooledTemporaryFile"]
    opened = []

    def track_spooled_file(*args: Any, **kwargs: Any) -> Any:
        file = real_spooled_file(*args, **kwargs)
        opened.append(file)
        return file

    monkeypatch.setattr(settings, "upload_read_timeout_seconds", 0.02)
    monkeypatch.setattr("starlette.formparsers.SpooledTemporaryFile", track_spooled_file)
    file_header = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="openapi_file"; '
        'filename="openapi.yaml"\r\nContent-Type: application/octet-stream\r\n\r\n'
    ).encode()
    paused = asyncio.Event()
    never_release = asyncio.Event()
    status_code, body, _ = asyncio.run(
        _asgi_post(
            [file_header, b"partial", b"remaining"],
            pause_event=paused,
            release_event=never_release,
            pause_at_chunk=2,
        )
    )

    assert paused.is_set()
    assert status_code == 408
    assert b"configured timeout" in body
    assert opened and all(file.closed for file in opened)
    assert scans.upload_admission.active_counts() == (0, {})


def test_client_disconnect_closes_tempfile_and_releases_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import starlette.formparsers

    real_spooled_file = vars(starlette.formparsers)["SpooledTemporaryFile"]
    opened = []

    def track_spooled_file(*args: Any, **kwargs: Any) -> Any:
        file = real_spooled_file(*args, **kwargs)
        opened.append(file)
        return file

    monkeypatch.setattr("starlette.formparsers.SpooledTemporaryFile", track_spooled_file)
    file_header = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="openapi_file"; '
        'filename="openapi.yaml"\r\nContent-Type: application/octet-stream\r\n\r\n'
    ).encode()

    with pytest.raises(ClientDisconnect):
        asyncio.run(
            _asgi_post(
                [file_header + b"partial", b"unreachable remainder"],
                disconnect_after_chunks=1,
            )
        )

    assert opened and all(file.closed for file in opened)
    assert scans.upload_admission.active_counts() == (0, {})


def test_admission_tracks_only_active_clients_and_releases_idempotently() -> None:
    admission = UploadAdmission(max_global=2, max_per_client=1)
    alpha = admission.try_reserve("alpha")
    assert alpha is not None
    assert admission.try_reserve("alpha") is None
    beta = admission.try_reserve("beta")
    assert beta is not None
    assert admission.try_reserve("gamma") is None
    alpha.release()
    alpha.release()
    beta.release()
    assert admission.active_counts() == (0, {})
