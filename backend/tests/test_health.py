import asyncio
from typing import cast

import pytest
from app.main import app
from fastapi.testclient import TestClient


def test_liveness_does_not_require_database() -> None:
    client = TestClient(app)
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_api_v1_health_compatibility_path() -> None:
    client = TestClient(app)
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_requires_current_migration_head(monkeypatch: pytest.MonkeyPatch) -> None:
    from app import main

    class Result:
        def scalar_one_or_none(self) -> str:
            return "2af81c6e9b40"

    class FakeSession:
        def __enter__(self) -> FakeSession:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def execute(self, statement: object) -> Result:
            assert "alembic_version" in str(statement)
            return Result()

    monkeypatch.setattr(main, "SessionLocal", FakeSession)
    assert main.readiness() == {"status": "ready", "database": "ready"}


def test_readiness_rejects_an_old_database_revision(monkeypatch: pytest.MonkeyPatch) -> None:
    from app import main
    from fastapi.responses import JSONResponse

    class Result:
        def scalar_one_or_none(self) -> str:
            return "7b8e1a9c3f2d"

    class FakeSession:
        def __enter__(self) -> FakeSession:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def execute(self, statement: object) -> Result:
            return Result()

    monkeypatch.setattr(main, "SessionLocal", FakeSession)
    response = main.readiness()
    assert isinstance(response, JSONResponse)
    assert response.status_code == 503
    assert b"database_migrations_incomplete" in response.body


def test_readiness_returns_sanitized_503_when_database_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import main
    from fastapi.responses import JSONResponse
    from sqlalchemy.exc import SQLAlchemyError

    class FakeSession:
        def __enter__(self) -> FakeSession:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def execute(self, statement: object) -> None:
            raise SQLAlchemyError("database password must not appear")

    monkeypatch.setattr(main, "SessionLocal", FakeSession)
    response = main.readiness()

    assert isinstance(response, JSONResponse)
    assert response.status_code == 503
    assert b"database_unavailable" in response.body
    assert b"password" not in response.body


def test_lifespan_does_not_fail_active_jobs_during_replica_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import main
    from app.core.config import settings

    monkeypatch.setattr(settings, "scan_workers_enabled", False)
    monkeypatch.setattr(main, "shutdown_default_job_runner", lambda: None)

    async def enter_and_exit() -> list[asyncio.Task[None]]:
        async with main.lifespan(app):
            return cast(list[asyncio.Task[None]], app.state.worker_tasks)

    assert asyncio.run(enter_and_exit()) == []
