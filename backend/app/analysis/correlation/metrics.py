from dataclasses import dataclass, field
from typing import Any

from app.analysis.correlation.models import (
    CorrelatedFinding,
    CorrelationState,
    EndpointMatchState,
    MatchedEndpointPair,
)
from app.analysis.findings import Finding


@dataclass(frozen=True)
class ResearchEvaluationMetrics:
    """Evaluation metrics structure designed for experimental benchmarking (Phase 6).

    Preserves precision/recall/confusion matrix slots alongside surface parity metrics.
    """

    # Surface Alignment Metrics
    total_spec_endpoints: int = 0
    total_source_endpoints: int = 0
    matched_endpoints_count: int = 0
    exact_matches_count: int = 0
    parameter_normalized_matches_count: int = 0
    ambiguous_matches_count: int = 0
    shadow_endpoints_count: int = 0  # in source, missing from spec
    zombie_endpoints_count: int = 0  # in spec, missing from source

    # Findings Preservation Counts
    spec_only_findings_count: int = 0
    source_only_findings_count: int = 0
    correlated_findings_count: int = 0

    # Correlation State Counts
    supported_count: int = 0
    contradicted_count: int = 0
    complementary_count: int = 0
    inconclusive_count: int = 0

    # Ground-truth evaluation slots (for Phase 6 experimental evaluation)
    true_positives: int | None = None
    false_positives: int | None = None
    false_negatives: int | None = None
    true_negatives: int | None = None
    precision: float | None = None
    recall: float | None = None
    f1_score: float | None = None
    false_positive_rate: float | None = None
    false_negative_rate: float | None = None

    custom_metadata: dict[str, Any] = field(default_factory=dict)


def compute_correlation_metrics(
    matched_pairs: tuple[MatchedEndpointPair, ...],
    unmatched_spec_count: int,
    unmatched_source_count: int,
    spec_findings: tuple[Finding, ...],
    source_findings: tuple[Finding, ...],
    correlated_findings: tuple[CorrelatedFinding, ...],
) -> ResearchEvaluationMetrics:
    """Calculates summary metrics across matched endpoints and correlation findings."""
    exact_count = sum(1 for p in matched_pairs if p.match_state == EndpointMatchState.EXACT_MATCH)
    norm_count = sum(
        1 for p in matched_pairs if p.match_state == EndpointMatchState.PARAMETER_NORMALIZED_MATCH
    )
    ambig_count = sum(
        1 for p in matched_pairs if p.match_state == EndpointMatchState.AMBIGUOUS_MATCH
    )

    supported = sum(
        1 for f in correlated_findings if f.correlation_state == CorrelationState.SUPPORTED
    )
    contradicted = sum(
        1 for f in correlated_findings if f.correlation_state == CorrelationState.CONTRADICTED
    )
    complementary = sum(
        1 for f in correlated_findings if f.correlation_state == CorrelationState.COMPLEMENTARY
    )
    inconclusive = sum(
        1 for f in correlated_findings if f.correlation_state == CorrelationState.INCONCLUSIVE
    )

    matched_actual = exact_count + norm_count

    return ResearchEvaluationMetrics(
        total_spec_endpoints=matched_actual + ambig_count + unmatched_spec_count,
        total_source_endpoints=matched_actual + unmatched_source_count,
        matched_endpoints_count=matched_actual,
        exact_matches_count=exact_count,
        parameter_normalized_matches_count=norm_count,
        ambiguous_matches_count=ambig_count,
        shadow_endpoints_count=unmatched_source_count,
        zombie_endpoints_count=unmatched_spec_count,
        spec_only_findings_count=len(spec_findings),
        source_only_findings_count=len(source_findings),
        correlated_findings_count=len(correlated_findings),
        supported_count=supported,
        contradicted_count=contradicted,
        complementary_count=complementary,
        inconclusive_count=inconclusive,
    )
