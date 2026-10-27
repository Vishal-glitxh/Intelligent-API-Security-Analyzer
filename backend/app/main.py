import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.api.router import api_router
from app.core.config import settings
from app.core.security import ScanRateLimiter
from app.db.session import SessionLocal
from app.middleware.upload_body_limit import UploadBodyLimitMiddleware
from app.repositories.scan import ScanRepository
from app.services.scan_service import cleanup_scan_workspace, shutdown_default_job_runner

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    app.state.startup_recovery_complete = False
    db = None
    try:
        db = SessionLocal()
        repo = ScanRepository(db)
        interrupted_scan_ids = repo.recover_interrupted_scans()
        for scan_id in interrupted_scan_ids:
            if not cleanup_scan_workspace(scan_id):
                raise OSError("Recovered scan workspace cleanup failed.")
        app.state.startup_recovery_complete = True
    except Exception as exc:
        # Keep liveness available for diagnosis, but readiness stays false until the
        # process is restarted and recovery succeeds. Do not log DB exception details.
        logger.error(
            "Startup scan recovery failed (%s); readiness is disabled.", type(exc).__name__
        )
    finally:
        if db is not None:
            db.close()
    yield
    shutdown_default_job_runner()


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
app.state.startup_recovery_complete = False
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
def readiness(request: Request) -> dict[str, str] | JSONResponse:
    """Readiness requires successful startup recovery and a live database connection."""
    if not getattr(request.app.state, "startup_recovery_complete", False):
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "reason": "startup_recovery_incomplete"},
        )

    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
    except SQLAlchemyError, OSError:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "reason": "database_unavailable"},
        )
    return {"status": "ready", "database": "ready"}
