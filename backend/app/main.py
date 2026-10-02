from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.security import ScanRateLimiter
from app.db.session import SessionLocal
from app.repositories.scan import ScanRepository
from app.services.scan_service import shutdown_default_job_runner


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    db = SessionLocal()
    try:
        repo = ScanRepository(db)
        repo.recover_interrupted_scans()
    except Exception as exc:
        print(f"Startup scan recovery warning: {exc}")
    finally:
        db.close()
    yield
    shutdown_default_job_runner()


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
app.include_router(api_router, prefix="/api/v1")


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok"}
