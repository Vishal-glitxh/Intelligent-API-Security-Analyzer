from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


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
    source_types: (
        list[
            Literal[
                "scan_finding",
                "endpoint_mapping",
                "security_knowledge",
                "public_security_documentation",
                "internal_iasa_knowledge",
            ]
        ]
        | None
    ) = Field(default=None, max_length=5)

    @model_validator(mode="after")
    def validate_unique_source_types(self) -> ScanAssistantRequest:
        if self.source_types is not None and len(self.source_types) != len(set(self.source_types)):
            raise ValueError("Assistant source filters must be unique.")
        return self


class ScanAssistantSource(BaseModel):
    id: str
    document_id: str | None = None
    chunk_id: str | None = None
    title: str
    source_type: str
    citation: str
    source_location: str | None = None
    source_url: str | None = None
    license: str | None = None
    endpoint: str | None = None
    excerpt: str
    relevance: float
    retrieval_method: str | None = None
    source_category: str | None = None
    original_filename: str | None = None
    source_identity: str | None = None
    source_sha256: str | None = None
    document_sha256: str | None = None
    char_start: int | None = None
    char_end: int | None = None
    page: int | None = None
    section: str | None = None


class ScanAssistantClaimCitation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_id: str = Field(min_length=1, max_length=120)
    text: str = Field(min_length=1, max_length=2000)
    source_ids: list[str] = Field(default_factory=list, max_length=8)
    origin: Literal["local_model", "deterministic_fallback"]
    kind: Literal[
        "scan_observation",
        "general_guidance",
        "qualification",
        "recommendation",
        "policy_refusal",
        "abstention",
    ]


class ScanAssistantResponse(BaseModel):
    scan_id: uuid.UUID
    answer: str
    sources: list[ScanAssistantSource]
    retrieval: str
    ranking_policy: str
    ranking_method: str
    external_network_used: bool
    notice: str
    ai_status: str
    model_name: str | None = None
    model_digest: str | None = None
    ai_used: bool
    ai_explanation: str | None = None
    policy_refusal: str | None = None
    recommendations: list[str] = Field(default_factory=list)
    cited_source_ids: list[str] = Field(default_factory=list)
    claim_citations: list[ScanAssistantClaimCitation] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_claim_citations(self) -> ScanAssistantResponse:
        from app.services.assistant_policy import POLICY_REFUSAL_TEXT

        if not self.claim_citations:
            raise ValueError("Assistant responses require attributed claims.")
        if self.policy_refusal not in {None, POLICY_REFUSAL_TEXT}:
            raise ValueError("Assistant policy refusal is not canonical.")
        claim_ids = [claim.claim_id for claim in self.claim_citations]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("Assistant claim IDs must be unique within a response.")
        if any(
            not claim.claim_id.startswith(
                "model-claim-" if claim.origin == "local_model" else "fallback-claim-"
            )
            for claim in self.claim_citations
        ):
            raise ValueError("Assistant claim IDs must be assigned by the server.")
        if any(
            len(claim.source_ids) != len(set(claim.source_ids)) for claim in self.claim_citations
        ):
            raise ValueError("Assistant claim source IDs must be unique within a claim.")
        available_source_ids = {source.id for source in self.sources}
        if any(
            source_id not in available_source_ids
            for claim in self.claim_citations
            for source_id in claim.source_ids
        ):
            raise ValueError("Assistant claim citation references an unavailable source.")
        if any(source_id not in available_source_ids for source_id in self.cited_source_ids):
            raise ValueError("Assistant citation references an unavailable source.")
        model_claims = [claim for claim in self.claim_citations if claim.origin == "local_model"]
        fallback_claims = [
            claim for claim in self.claim_citations if claim.origin == "deterministic_fallback"
        ]
        expected_model_ids = list(
            dict.fromkeys(source_id for claim in model_claims for source_id in claim.source_ids)
        )
        if self.cited_source_ids != expected_model_ids:
            raise ValueError("Model citations must match source IDs on local-model claims.")
        if self.ai_used != bool(model_claims) or self.ai_used != bool(self.ai_explanation):
            raise ValueError("Assistant AI state must match model claims and explanation.")
        if model_claims and self.ai_explanation != " ".join(claim.text for claim in model_claims):
            raise ValueError("Assistant explanation must match its model claims.")
        if any(
            claim.kind != "general_guidance"
            or len(claim.source_ids) != 1
            or not any(
                source.id == claim.source_ids[0]
                and source.source_type
                in {
                    "security_knowledge",
                    "public_security_documentation",
                    "internal_iasa_knowledge",
                }
                and _model_claim_matches_source(claim.text, source)
                for source in self.sources
            )
            for claim in model_claims
        ):
            raise ValueError("Model claims must quote one retrieved security guidance source.")
        if any(claim.origin != "deterministic_fallback" for claim in fallback_claims):
            raise ValueError("Assistant fallback claim origin is invalid.")
        if any(
            claim.origin == "deterministic_fallback" and claim.kind == "general_guidance"
            for claim in fallback_claims
        ):
            raise ValueError("General guidance claims must originate from validated model quotes.")
        if not fallback_claims or self.answer != " ".join(claim.text for claim in fallback_claims):
            raise ValueError("Assistant answer must match its deterministic claims.")
        source_types = {source.id: source.source_type for source in self.sources}
        if any(
            claim.kind == "scan_observation"
            and (
                not claim.source_ids
                or any(
                    source_types.get(source_id) != "scan_finding" for source_id in claim.source_ids
                )
            )
            for claim in fallback_claims
        ):
            raise ValueError("Scan observations must cite retrieved scan findings.")
        if any(
            claim.kind in {"qualification", "recommendation"} and not claim.source_ids
            for claim in fallback_claims
        ):
            raise ValueError("Evidence-bound fallback claims require source references.")
        abstention_claims = [claim for claim in self.claim_citations if claim.kind == "abstention"]
        refusal_claims = [claim for claim in self.claim_citations if claim.kind == "policy_refusal"]
        if self.policy_refusal is None and refusal_claims:
            raise ValueError("Policy-refusal claims require a sensitive-request refusal.")
        if self.policy_refusal is not None and (
            len(refusal_claims) != 1
            or refusal_claims[0].origin != "deterministic_fallback"
            or refusal_claims[0].text != POLICY_REFUSAL_TEXT
            or refusal_claims[0].source_ids
        ):
            raise ValueError(
                "Sensitive requests require the canonical deterministic refusal claim."
            )
        if abstention_claims and (
            len(abstention_claims) != 1
            or len(self.claim_citations) != 1 + len(refusal_claims)
            or abstention_claims[0].origin != "deterministic_fallback"
            or abstention_claims[0].text != self.answer
            and self.answer != " ".join(claim.text for claim in self.claim_citations)
            or self.ai_explanation is not None
            or self.ai_used
            or self.sources
            or self.recommendations
            or self.cited_source_ids
        ):
            raise ValueError("Assistant abstention must match the deterministic answer.")
        if refusal_claims and self.ai_used:
            raise ValueError("Sensitive-request responses cannot include model-generated claims.")
        if not abstention_claims and not self.sources:
            raise ValueError("Evidence-free responses must be deterministic abstentions.")
        return self


def _model_claim_matches_source(claim_text: str, source: ScanAssistantSource) -> bool:
    from app.services.local_ai import normalize_model_excerpt
    from app.services.rag_index import trusted_knowledge_excerpts

    normalized = normalize_model_excerpt(source.excerpt)
    return claim_text == normalized and trusted_knowledge_excerpts().get(source.id) == normalized


class LocalAIStatusResponse(BaseModel):
    status: str
    model_name: str | None = None
    available_models: list[str]
    embedding_model: str | None = None
    embedding_model_digest: str | None = None
    embedding_dimensions: int | None = None
    embedding_available: bool
    retrieval_available: bool
    message: str
    rag_index_status: str
    rag_index_version: str | None = None
    rag_index_embedding_model: str | None = None
    rag_index_embedding_model_digest: str | None = None
    rag_index_embedding_dimensions: int | None = None
    rag_index_document_count: int = 0
    rag_index_chunk_count: int = 0


class AuthSessionResponse(BaseModel):
    authenticated: bool
    auth_mode: str
