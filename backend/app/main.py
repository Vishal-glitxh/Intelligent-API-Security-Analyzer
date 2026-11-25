import asyncio
import logging
import os
import socket
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from app.api.router import api_router
from app.core.config import settings
from app.core.security import ScanRateLimiter
from app.db.session import SessionLocal
from app.middleware.upload_body_limit import UploadBodyLimitMiddleware
from app.services.scan_service import shutdown_default_job_runner
from app.services.scan_worker import process_one_claim

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    stop_workers = asyncio.Event()
    app.state.worker_stop_event = stop_workers
    worker_tasks: list[asyncio.Task[None]] = []
    if settings.scan_workers_enabled:
        base_worker_id = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:12]}"
        worker_tasks = [
            asyncio.create_task(
                _scan_worker_loop(f"{base_worker_id}-{index + 1}", stop_workers),
                name=f"scan-worker-{index + 1}",
            )
            for index in range(settings.scan_worker_count)
        ]
    app.state.worker_tasks = worker_tasks
    try:
        yield
    finally:
        stop_workers.set()
        if worker_tasks:
            await asyncio.gather(*worker_tasks, return_exceptions=True)
        shutdown_default_job_runner()


async def _scan_worker_loop(worker_id: str, stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        try:
            claimed = await run_in_threadpool(process_one_claim, worker_id)
        except Exception as exc:
            logger.error("Scan worker iteration failed (%s).", type(exc).__name__)
            claimed = False
        if not claimed:
            try:
                await asyncio.wait_for(
                    stop_event.wait(), timeout=settings.scan_worker_poll_interval_seconds
                )
            except TimeoutError:
                pass


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
cors_origins = [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
)
app.add_middleware(ScanRateLimiter)
app.add_middleware(UploadBodyLimitMiddleware)
app.include_router(api_router, prefix="/api/v1")


@app.get("/health", tags=["system"])
@app.get("/health/live", tags=["system"])
def health() -> dict[str, str]:
    """Liveness only: the process is running; dependencies may still be unavailable."""
    return {"status": "ok"}


@app.get("/health/ready", tags=["system"], response_model=None)
def readiness() -> dict[str, str] | JSONResponse:
    """Readiness requires the shared PostgreSQL coordination store to be reachable."""
    try:
        with SessionLocal() as db:
            revision = db.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one_or_none()
            if revision != "2af81c6e9b40":
                return JSONResponse(
                    status_code=503,
                    content={"status": "not_ready", "reason": "database_migrations_incomplete"},
                )
    except SQLAlchemyError, OSError:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "reason": "database_unavailable"},
        )
    return {"status": "ready", "database": "ready"}
