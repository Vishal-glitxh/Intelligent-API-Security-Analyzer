from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from app.analysis.context import (
    NormalizedOperation,
    NormalizedSourceEndpoint,
    SourceLocation,
    SourceSecurityEvidence,
)
from app.analysis.findings import Evidence, Finding


class EndpointMatchState(StrEnum):
    EXACT_MATCH = "EXACT_MATCH"
    PARAMETER_NORMALIZED_MATCH = "PARAMETER_NORMALIZED_MATCH"
    AMBIGUOUS_MATCH = "AMBIGUOUS_MATCH"
    NO_MATCH = "NO_MATCH"


class CorrelationState(StrEnum):
    """Correlation state representing the relationship between specification and source evidence.

    SUPPORTED: Cross-layer evidence is mutually consistent with the evaluated proposition.
               Does not inherently mean 'secure' or 'vulnerable'; the security rule determines
               whether the supported proposition affirms a control or a vulnerability.
    CONTRADICTED: Layers directly conflict (e.g. spec claims auth, source lacks evidence).
    COMPLEMENTARY: Layers provide distinct, non-overlapping facts that together form a
                   complete risk profile.
    INCONCLUSIVE: Evidence exists but cross-layer correspondence cannot be established statically.
    """

    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    COMPLEMENTARY = "COMPLEMENTARY"
    INCONCLUSIVE = "INCONCLUSIVE"


class AnalysisLayer(StrEnum):
    SPEC_ONLY = "SPEC_ONLY"
    SOURCE_ONLY = "SOURCE_ONLY"
    CORRELATED = "CORRELATED"


@dataclass(frozen=True)
class MatchedEndpointPair:
    """Deterministic pairing of an OpenAPI operation with a source code endpoint handler.

    Preserves original raw paths, parameter names, canonical matching paths, and locations.
    """

    spec_path: str
    spec_method: str
    source_path: str | None
    source_method: str | None
    match_state: EndpointMatchState
    canonical_matching_path: str
    spec_operation: NormalizedOperation | None = None
    source_endpoint: NormalizedSourceEndpoint | None = None
    spec_operation_id: str | None = None
    source_handler_name: str | None = None
    match_rationale: str = ""
    spec_location: SourceLocation | None = None
    source_location: SourceLocation | None = None


@dataclass(frozen=True)
class CorrelatedEvidencePair:
    """Pairing of a specification evidence item with a source evidence item."""

    category: str
    correlation_state: CorrelationState
    spec_evidence: Evidence | None
    source_evidence: SourceSecurityEvidence | None
    rationale: str


@dataclass(frozen=True)
class CorrelatedFinding(Finding):
    """Security finding enriched with multi-layer lineage, correlation state, and evidence pairs."""

    correlation_state: CorrelationState = CorrelationState.INCONCLUSIVE
    layer: AnalysisLayer = AnalysisLayer.CORRELATED
    matched_endpoint: MatchedEndpointPair | None = None
    spec_findings: tuple[Finding, ...] = ()
    source_findings: tuple[Finding, ...] = ()
    evidence_pairs: tuple[CorrelatedEvidencePair, ...] = ()
    divergence_details: str | None = None


@dataclass(frozen=True)
class MultiLayerAnalysisResult:
    """Preserves all three independent research result sets alongside correlation synthesis."""

    spec_only_findings: tuple[Finding, ...]
    source_only_findings: tuple[Finding, ...]
    correlated_findings: tuple[CorrelatedFinding, ...]
    matched_endpoints: tuple[MatchedEndpointPair, ...]
    unmatched_spec_endpoints: tuple[NormalizedOperation, ...]
    unmatched_source_endpoints: tuple[NormalizedSourceEndpoint, ...]
    metrics_summary: dict[str, Any] = field(default_factory=dict)
