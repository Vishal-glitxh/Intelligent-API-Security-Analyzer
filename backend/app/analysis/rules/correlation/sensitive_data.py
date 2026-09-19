from collections.abc import Sequence

from app.analysis.context import AnalysisContext, EvidenceCategory
from app.analysis.correlation.models import (
    AnalysisLayer,
    CorrelatedEvidencePair,
    CorrelatedFinding,
    CorrelationState,
    MatchedEndpointPair,
)
from app.analysis.findings import Finding
from app.analysis.rules.correlation.base import CorrelationRule


class SensitiveDataCorrelationRule(CorrelationRule):
    """CORR-DATA-001: Correlates potential sensitive-data exposure between spec and source."""

    rule_id = "CORR-DATA-001"
    rule_version = "1.0.0"

    def correlate(
        self,
        context: AnalysisContext,
        matched_pairs: Sequence[MatchedEndpointPair],
        spec_findings: Sequence[Finding],
        source_findings: Sequence[Finding],
    ) -> list[CorrelatedFinding]:
        findings: list[CorrelatedFinding] = []

        for pair in matched_pairs:
            if not pair.spec_operation or not pair.source_endpoint:
                continue

            spec_op = pair.spec_operation
            source_ep = pair.source_endpoint
            method = spec_op.method.upper()

            # Find spec sensitive data findings matching this path
            rel_spec_findings = tuple(
                f
                for f in spec_findings
                if f.rule_id == "API-DATA-001"
                and any(ev.message and spec_op.path in ev.message for ev in f.evidence)
            )

            if not rel_spec_findings:
                continue

            for sf in rel_spec_findings:
                ev_pair = CorrelatedEvidencePair(
                    category=EvidenceCategory.DATABASE_ACCESS,
                    correlation_state=CorrelationState.SUPPORTED,
                    spec_evidence=sf.evidence[0] if sf.evidence else None,
                    source_evidence=None,
                    rationale=(
                        "OpenAPI specification response schema defines potentially "
                        f"sensitive field on {method} {pair.spec_path}."
                    ),
                )

                findings.append(
                    CorrelatedFinding(
                        rule_id=self.rule_id,
                        rule_version=self.rule_version,
                        title=(
                            f"Corroborated Sensitive Data Exposure in Contract: {sf.title} "
                            f"({method} {pair.spec_path})"
                        ),
                        severity=sf.severity,
                        confidence=min(0.90, sf.confidence + 0.05),
                        rationale=(
                            f"Specification documents a sensitive field in response schema "
                            f"for {method} {pair.spec_path} ('{source_ep.handler_name}'). "
                            "Implementation audits should confirm serialized response DTOs "
                            "filter out this field."
                        ),
                        remediation=(
                            "Filter sensitive fields from public serialization schemas or use "
                            "dedicated Pydantic response models."
                        ),
                        evidence=sf.evidence,
                        correlation_state=CorrelationState.SUPPORTED,
                        layer=AnalysisLayer.CORRELATED,
                        matched_endpoint=pair,
                        spec_findings=(sf,),
                        source_findings=(),
                        evidence_pairs=(ev_pair,),
                        divergence_details="Schema contract exposes sensitive field.",
                    )
                )

        return findings
