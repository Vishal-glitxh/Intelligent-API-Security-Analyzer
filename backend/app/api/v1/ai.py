from app.core.security import ClientIdentity, get_current_client, require_api_access_token
from app.schemas.scan import AuthSessionResponse, LocalAIStatusResponse
from app.services.local_ai import get_local_ai_status
from fastapi import APIRouter, Depends

router = APIRouter(
    prefix="/ai",
    tags=["local AI"],
    dependencies=[Depends(require_api_access_token)],
)


@router.get("/session", response_model=AuthSessionResponse)
def get_auth_session(client: ClientIdentity = Depends(get_current_client)) -> AuthSessionResponse:
    auth_mode = "local-development" if client.client_id == "local-development" else "token"
    return AuthSessionResponse(authenticated=True, auth_mode=auth_mode)


@router.get("/status", response_model=LocalAIStatusResponse)
def get_ai_status() -> LocalAIStatusResponse:
    """Report local Ollama/model availability without exposing internal URLs."""
    return LocalAIStatusResponse(**get_local_ai_status())
