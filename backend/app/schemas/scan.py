import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


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
