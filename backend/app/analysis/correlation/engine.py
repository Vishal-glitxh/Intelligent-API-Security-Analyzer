from collections.abc import Sequence

from app.analysis.context import AnalysisContext
from app.analysis.correlation.matcher import match_endpoints
from app.analysis.correlation.metrics import compute_correlation_metrics
from app.analysis.correlation.models import CorrelatedFinding, MultiLayerAnalysisResult
from app.analysis.findings import Finding
from app.analysis.rules.correlation import (
    AuthenticationCorrelationRule,
    CorrelationRule,
    InputConstraintsCorrelationRule,
    ObjectAuthorizationCorrelationRule,
    SensitiveDataCorrelationRule,
    SurfaceDivergenceCorrelationRule,
)

DEFAULT_CORRELATION_RULES: tuple[CorrelationRule, ...] = (
    AuthenticationCorrelationRule(),
    ObjectAuthorizationCorrelationRule(),
    SensitiveDataCorrelationRule(),
    InputConstraintsCorrelationRule(),
    SurfaceDivergenceCorrelationRule(),
)


class CorrelationEngine:
    """Orchestrates deterministic multi-layer evidence correlation and finding synthesis."""

    def __init__(
        self,
        rules: Sequence[CorrelationRule] | None = None,
    ) -> None:
        self.rules: tuple[CorrelationRule, ...] = (
            tuple(rules) if rules is not None else DEFAULT_CORRELATION_RULES
        )

    def correlate(
        self,
        context: AnalysisContext,
        spec_findings: Sequence[Finding],
        source_findings: Sequence[Finding],
    ) -> MultiLayerAnalysisResult:
        """Executes cross-layer matching, aligns evidence, and produces a MultiLayerAnalysisResult.

        Strictly preserves the underlying SPEC_ONLY and SOURCE_ONLY findings unchanged.
        """
        # 1. Deterministic endpoint matching
        matched_pairs, unmatched_spec, unmatched_source = match_endpoints(
            specification=context.specification,
            source_tree=context.source,
        )

        # 2. Evaluate correlation rules
        raw_correlated_findings: list[CorrelatedFinding] = []
        for rule in self.rules:
            findings = rule.correlate(
                context=context,
                matched_pairs=matched_pairs,
                spec_findings=spec_findings,
                source_findings=source_findings,
            )
            raw_correlated_findings.extend(findings)

        # 3. Deterministic finding sorting
        sorted_correlated_findings = sorted(
            raw_correlated_findings,
            key=lambda f: (
                f.rule_id,
                f.title,
                f.evidence[0].file or "" if f.evidence else "",
                f.evidence[0].line or 0 if f.evidence else 0,
            ),
        )

        corr_tuple = tuple(sorted_correlated_findings)
        spec_tuple = tuple(spec_findings)
        source_tuple = tuple(source_findings)

        # 4. Compile metrics metadata
        metrics = compute_correlation_metrics(
            matched_pairs=matched_pairs,
            unmatched_spec_count=len(unmatched_spec),
            unmatched_source_count=len(unmatched_source),
            spec_findings=spec_tuple,
            source_findings=source_tuple,
            correlated_findings=corr_tuple,
        )

        return MultiLayerAnalysisResult(
            spec_only_findings=spec_tuple,
            source_only_findings=source_tuple,
            correlated_findings=corr_tuple,
            matched_endpoints=matched_pairs,
            unmatched_spec_endpoints=unmatched_spec,
            unmatched_source_endpoints=unmatched_source,
            metrics_summary={
                "total_spec_endpoints": metrics.total_spec_endpoints,
                "total_source_endpoints": metrics.total_source_endpoints,
                "matched_endpoints_count": metrics.matched_endpoints_count,
                "exact_matches_count": metrics.exact_matches_count,
                "parameter_normalized_matches_count": metrics.parameter_normalized_matches_count,
                "ambiguous_matches_count": metrics.ambiguous_matches_count,
                "shadow_endpoints_count": metrics.shadow_endpoints_count,
                "zombie_endpoints_count": metrics.zombie_endpoints_count,
                "spec_only_findings_count": metrics.spec_only_findings_count,
                "source_only_findings_count": metrics.source_only_findings_count,
                "correlated_findings_count": metrics.correlated_findings_count,
                "supported_count": metrics.supported_count,
                "contradicted_count": metrics.contradicted_count,
                "complementary_count": metrics.complementary_count,
                "inconclusive_count": metrics.inconclusive_count,
            },
        )
