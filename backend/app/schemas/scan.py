import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ScanCreateResponse(BaseModel):
    scan_id: uuid.UUID
    status: str
    project_name: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanResponse(BaseModel):
    scan_id: uuid.UUID
    status: str
    project_name: str
    spec_filename: str
    source_filename: str
    spec_hash: str | None
    source_hash: str | None
    engine_version: str
    rule_set_version: str
    config_version: str
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class ScanResultsResponse(BaseModel):
    scan_id: uuid.UUID
    metrics_summary: dict[str, Any]
    matched_endpoints: list[dict[str, Any]]


class ScanFindingsResponse(BaseModel):
    scan_id: uuid.UUID
    spec_only_findings: list[dict[str, Any]]
    source_only_findings: list[dict[str, Any]]
    correlated_findings: list[dict[str, Any]]


class ScanAssistantRequest(BaseModel):
    question: str = Field(min_length=3, max_length=500)
    limit: int = Field(default=5, ge=1, le=8)


class ScanAssistantSource(BaseModel):
    id: str
    title: str
    source_type: str
    citation: str
    source_url: str | None = None
    license: str | None = None
    endpoint: str | None = None
    excerpt: str
    relevance: float


class ScanAssistantResponse(BaseModel):
    scan_id: uuid.UUID
    answer: str
    sources: list[ScanAssistantSource]
    retrieval: str
    external_network_used: bool
    notice: str
    ai_status: str
    model_name: str | None = None
    ai_used: bool
    ai_explanation: str | None = None
    recommendations: list[str] = Field(default_factory=list)
    cited_source_ids: list[str] = Field(default_factory=list)


class LocalAIStatusResponse(BaseModel):
    status: str
    model_name: str | None = None
    available_models: list[str]
    embedding_model: str | None = None
    embedding_available: bool
    retrieval_available: bool
    message: str


class AuthSessionResponse(BaseModel):
    authenticated: bool
    auth_mode: str
