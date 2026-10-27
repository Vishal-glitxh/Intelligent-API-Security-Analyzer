from fastapi import APIRouter

from app.api.v1 import ai, research, scans

api_router = APIRouter()
api_router.include_router(scans.router)
api_router.include_router(research.router)
api_router.include_router(ai.router)


@api_router.get("/health", tags=["system"])
def api_health() -> dict[str, str]:
    return {"status": "ok"}
