from __future__ import annotations

import asyncio
import uuid

import pytest
from app.main import app
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import JSONResponse


def test_health() -> None:
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_api_v1_health() -> None:
    client = TestClient(app)
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def _readiness_request() -> Request:
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/health/ready",
            "raw_path": b"/health/ready",
            "query_string": b"",
            "headers": [],
            "client": ("test", 1),
            "server": ("test", 80),
            "app": app,
        }
    )


def test_readiness_is_distinct_from_liveness_and_checks_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import main

    class FakeSession:
        def __enter__(self) -> FakeSession:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def execute(self, statement: object) -> None:
            assert str(statement) == "SELECT 1"

    monkeypatch.setattr(app.state, "startup_recovery_complete", True, raising=False)
    monkeypatch.setattr(main, "SessionLocal", FakeSession)

    assert main.health() == {"status": "ok"}
    assert main.readiness(_readiness_request()) == {"status": "ready", "database": "ready"}


def test_readiness_returns_sanitized_503_when_database_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import main
    from sqlalchemy.exc import SQLAlchemyError

    class FakeSession:
        def __enter__(self) -> FakeSession:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def execute(self, statement: object) -> None:
            raise SQLAlchemyError("database password must not appear")

    monkeypatch.setattr(app.state, "startup_recovery_complete", True, raising=False)
    monkeypatch.setattr(main, "SessionLocal", FakeSession)
    response = main.readiness(_readiness_request())

    assert isinstance(response, JSONResponse)
    assert response.status_code == 503
    assert b"database_unavailable" in response.body
    assert b"password" not in response.body


def test_startup_recovery_cleans_only_recovered_workspaces_and_controls_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import main

    interrupted_id = uuid.uuid4()
    cleaned: list[uuid.UUID] = []

    class FakeSession:
        def close(self) -> None:
            pass

    class FakeRepository:
        def __init__(self, session: object) -> None:
            pass

        def recover_interrupted_scans(self) -> list[uuid.UUID]:
            return [interrupted_id]

    def cleanup(scan_id: uuid.UUID) -> bool:
        cleaned.append(scan_id)
        return True

    monkeypatch.setattr(main, "SessionLocal", FakeSession)
    monkeypatch.setattr(main, "ScanRepository", FakeRepository)
    monkeypatch.setattr(main, "cleanup_scan_workspace", cleanup)
    monkeypatch.setattr(main, "shutdown_default_job_runner", lambda: None)

    async def run_lifespan() -> bool:
        async with main.lifespan(app):
            return bool(app.state.startup_recovery_complete)

    assert asyncio.run(run_lifespan()) is True
    assert cleaned == [interrupted_id]


def test_failed_startup_recovery_keeps_process_live_but_not_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import main

    class FakeSession:
        def close(self) -> None:
            pass

    class FailingRepository:
        def __init__(self, session: object) -> None:
            pass

        def recover_interrupted_scans(self) -> list[uuid.UUID]:
            raise RuntimeError("sensitive database details")

    monkeypatch.setattr(main, "SessionLocal", FakeSession)
    monkeypatch.setattr(main, "ScanRepository", FailingRepository)
    monkeypatch.setattr(main, "shutdown_default_job_runner", lambda: None)

    async def run_lifespan() -> bool:
        async with main.lifespan(app):
            return bool(app.state.startup_recovery_complete)

    assert asyncio.run(run_lifespan()) is False
    assert main.health() == {"status": "ok"}
    response = main.readiness(_readiness_request())
    assert isinstance(response, JSONResponse)
    assert response.status_code == 503
    assert b"startup_recovery_incomplete" in response.body
    assert b"sensitive" not in response.body


def test_workspace_cleanup_failure_keeps_startup_unready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import main

    class FakeSession:
        def close(self) -> None:
            pass

    class RecoveringRepository:
        def __init__(self, session: object) -> None:
            pass

        def recover_interrupted_scans(self) -> list[uuid.UUID]:
            return [uuid.uuid4()]

    monkeypatch.setattr(main, "SessionLocal", FakeSession)
    monkeypatch.setattr(main, "ScanRepository", RecoveringRepository)
    monkeypatch.setattr(main, "cleanup_scan_workspace", lambda scan_id: False)
    monkeypatch.setattr(main, "shutdown_default_job_runner", lambda: None)

    async def run_lifespan() -> bool:
        async with main.lifespan(app):
            return bool(app.state.startup_recovery_complete)

    assert asyncio.run(run_lifespan()) is False
    response = main.readiness(_readiness_request())
    assert isinstance(response, JSONResponse)
    assert response.status_code == 503
    assert b"startup_recovery_incomplete" in response.body
