from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


@dataclass(frozen=True)
class SourceLocation:
    """Precise location pointer in a specification document or source file."""

    file: str
    line: int | None = None
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    json_pointer: str | None = None


@dataclass(frozen=True)
class NormalizedProperty:
    """Normalized schema field/property representation."""

    name: str
    property_type: str | None = None
    format: str | None = None
    required: bool = False
    description: str | None = None
    location: SourceLocation | None = None


@dataclass(frozen=True)
class NormalizedSchema:
    """Normalized data contract schema for requests or responses."""

    name: str | None = None
    schema_type: str = "object"
    properties: tuple[NormalizedProperty, ...] = ()
    required_properties: tuple[str, ...] = ()
    items_schema: Any | None = None
    location: SourceLocation | None = None
    ref_status: str | None = None


@dataclass(frozen=True)
class NormalizedParameter:
    """Normalized API parameter definition."""

    name: str
    param_in: str  # e.g., 'query', 'header', 'path', 'cookie'
    required: bool = False
    schema_type: str | None = None
    description: str | None = None
    constraints: dict[str, Any] = field(default_factory=dict)
    location: SourceLocation | None = None


@dataclass(frozen=True)
class NormalizedOperation:
    """Normalized API operation definition (e.g. GET /users)."""

    method: str
    path: str
    operation_id: str | None = None
    summary: str | None = None
    description: str | None = None
    tags: tuple[str, ...] = ()
    deprecated: bool = False
    parameters: tuple[NormalizedParameter, ...] = ()
    security_requirements: tuple[dict[str, list[str]], ...] = ()
    effective_security: tuple[dict[str, list[str]], ...] = ()
    has_explicit_security_override: bool = False
    request_body_schema: NormalizedSchema | None = None
    response_schemas: dict[str, NormalizedSchema] = field(default_factory=dict)
    location: SourceLocation | None = None


@dataclass(frozen=True)
class NormalizedEndpoint:
    """Normalized API path endpoint grouping operations."""

    path: str
    operations: tuple[NormalizedOperation, ...] = ()
    location: SourceLocation | None = None


@dataclass(frozen=True)
class NormalizedSecurityScheme:
    """Normalized security scheme definition (e.g. Bearer, OAuth2, ApiKey)."""

    name: str
    scheme_type: str
    scheme: str | None = None
    bearer_format: str | None = None
    param_in: str | None = None
    param_name: str | None = None
    description: str | None = None
    flows: dict[str, Any] = field(default_factory=dict)
    location: SourceLocation | None = None


@dataclass(frozen=True)
class NormalizedOpenAPI:
    """Normalized specification domain model establishing the stable rule interface."""

    title: str = ""
    version: str = "3.0.0"
    openapi_version: str = "3.0.0"
    servers: tuple[str, ...] = ()
    endpoints: tuple[NormalizedEndpoint, ...] = ()
    security_schemes: tuple[NormalizedSecurityScheme, ...] = ()
    global_security: tuple[dict[str, list[str]], ...] = ()
    spec_hash: str | None = None
    provenance: str | None = None
    unresolved_refs: tuple[str, ...] = ()
    unsupported_external_refs: tuple[str, ...] = ()
    circular_refs: tuple[str, ...] = ()


class EvidenceStrength(StrEnum):
    STRONG = "STRONG"
    MEDIUM = "MEDIUM"
    WEAK = "WEAK"


class EvidenceCategory(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    OBJECT_ACCESS = "object_access"
    TENANT_ISOLATION = "tenant_isolation"
    INPUT_VALIDATION = "input_validation"
    DATABASE_ACCESS = "database_access"
    SECRET = "secret"
    CONFIGURATION = "configuration"


class AuthState(StrEnum):
    AUTH_PRESENT = "AUTH_PRESENT"
    AUTH_ABSENT_IN_ANALYZABLE_SCOPE = "AUTH_ABSENT_IN_ANALYZABLE_SCOPE"
    AUTH_UNKNOWN = "AUTH_UNKNOWN"


@dataclass(frozen=True)
class SourceSecurityEvidence:
    """Structured, immutable evidence extracted from source code."""

    category: EvidenceCategory
    strength: EvidenceStrength
    message: str
    location: SourceLocation | None = None
    symbol: str | None = None
    endpoint_path: str | None = None
    endpoint_method: str | None = None
    handler_name: str | None = None
    extracted_value: str | None = None
    rationale: str | None = None


@dataclass(frozen=True)
class NormalizedSourceParameter:
    """Normalized function/endpoint parameter."""

    name: str
    param_type: str | None = None
    default_value: str | None = None
    is_path_param: bool = False
    has_validation: bool = False
    validation_details: str | None = None
    location: SourceLocation | None = None


@dataclass(frozen=True)
class NormalizedSourceEndpoint:
    """Normalized API endpoint definition recovered from source code."""

    method: str  # Lowercase, e.g. "get", "post"
    path: str  # Canonical OpenAPI-compatible, e.g. "/users/{user_id}"
    raw_path: str  # Original framework path before normalization
    handler_name: str
    file_path: str
    framework: str  # "fastapi" or "flask"
    location: SourceLocation | None = None
    parameters: tuple[NormalizedSourceParameter, ...] = ()
    auth_state: AuthState = AuthState.AUTH_UNKNOWN
    auth_evidence: tuple[SourceSecurityEvidence, ...] = ()
    authz_evidence: tuple[SourceSecurityEvidence, ...] = ()
    object_access_evidence: tuple[SourceSecurityEvidence, ...] = ()
    tenant_evidence: tuple[SourceSecurityEvidence, ...] = ()
    validation_evidence: tuple[SourceSecurityEvidence, ...] = ()
    router_prefix: str | None = None


@dataclass(frozen=True)
class SourceDiagnostic:
    """Diagnostic message from parser or loader (e.g. syntax error or decode failure)."""

    file_path: str
    message: str
    line: int | None = None
    column: int | None = None
    severity: str = "warning"


@dataclass(frozen=True)
class NormalizedSourceFile:
    """Normalized source file representation with AST, endpoints, and diagnostics."""

    path: str
    content_hash: str
    language: str = "python"
    framework: str = "generic"
    detected_routes: tuple[str, ...] = ()
    endpoints: tuple[NormalizedSourceEndpoint, ...] = ()
    evidence: tuple[SourceSecurityEvidence, ...] = ()
    diagnostics: tuple[SourceDiagnostic, ...] = ()
    ast_root: Any | None = None
    provenance: str | None = None


@dataclass(frozen=True)
class NormalizedSourceTree:
    """Normalized source tree representation across a repository or module."""

    files: tuple[NormalizedSourceFile, ...] = ()
    endpoints: tuple[NormalizedSourceEndpoint, ...] = ()
    evidence: tuple[SourceSecurityEvidence, ...] = ()
    diagnostics: tuple[SourceDiagnostic, ...] = ()
    source_hash: str | None = None
    provenance: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanMetadata:
    """Metadata capturing engine, rule-set, and configuration versions for reproducibility."""

    engine_version: str
    rule_set_version: str
    config_version: str = "1.0.0"
    spec_hash: str | None = None
    source_hash: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class AnalysisContext:
    """Normalized rule-facing analysis input containing specification, source, and scan metadata."""

    specification: NormalizedOpenAPI | None = None
    source: NormalizedSourceTree | None = None
    metadata: ScanMetadata | None = None
