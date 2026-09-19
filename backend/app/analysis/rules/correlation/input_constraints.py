from collections.abc import Sequence

from app.analysis.context import AnalysisContext
from app.analysis.correlation.aligner import align_input_validation_evidence
from app.analysis.correlation.models import (
    AnalysisLayer,
    CorrelatedFinding,
    CorrelationState,
    MatchedEndpointPair,
)
from app.analysis.findings import Finding, Severity
from app.analysis.rules.correlation.base import CorrelationRule


class InputConstraintsCorrelationRule(CorrelationRule):
    """CORR-INPUT-001: Correlates OpenAPI parameter constraints with source validation checks.

    Adheres strictly to the evidence-driven requirement:
    Only correlates when a specific relationship is established between:
      endpoint -> parameter/field -> constraint -> source validation evidence
    If relationship cannot be established statically, remains INCONCLUSIVE without guessing.
    """

    rule_id = "CORR-INPUT-001"
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

            corr_state, ev_pairs, rationale = align_input_validation_evidence(
                pair=pair,
                spec_findings=list(spec_findings),
                source_findings=list(source_findings),
            )

            rel_spec_findings = tuple(
                f
                for f in spec_findings
                if f.rule_id == "API-INPUT-001"
                and any(ev.message and spec_op.path in ev.message for ev in f.evidence)
            )

            # Case 1: Spec lacks constraint AND source implements validation in code (CONTRADICTED)
            if corr_state == CorrelationState.CONTRADICTED and rel_spec_findings:
                findings.append(
                    CorrelatedFinding(
                        rule_id=self.rule_id,
                        rule_version=self.rule_version,
                        title=(
                            "Input Validation Contract Drift: Missing Spec Constraint Enforced "
                            f"in Code ({method} {pair.spec_path})"
                        ),
                        severity=Severity.LOW,
                        confidence=0.75,
                        rationale=(
                            f"OpenAPI specification lacks parameter constraints on {method} "
                            f"{pair.spec_path}, but source handler '{source_ep.handler_name}' "
                            "implements explicit conditional validation checks in code. The "
                            "contract should be updated to reflect implementation boundaries."
                        ),
                        remediation=(
                            "Document parameter validation constraints (e.g. maximum, pattern) "
                            "in the OpenAPI specification to align the contract with code checks."
                        ),
                        evidence=rel_spec_findings[0].evidence,
                        correlation_state=CorrelationState.CONTRADICTED,
                        layer=AnalysisLayer.CORRELATED,
                        matched_endpoint=pair,
                        spec_findings=rel_spec_findings,
                        source_findings=(),
                        evidence_pairs=ev_pairs,
                        divergence_details=rationale,
                    )
                )

            # Case 2: Spec lacks constraint AND source code has NO validation (Corroborated)
            elif corr_state == CorrelationState.SUPPORTED and rel_spec_findings:
                orig = rel_spec_findings[0]
                findings.append(
                    CorrelatedFinding(
                        rule_id=self.rule_id,
                        rule_version=self.rule_version,
                        title=(
                            f"Corroborated Missing Input Constraints ({method} {pair.spec_path})"
                        ),
                        severity=orig.severity,
                        confidence=min(0.85, orig.confidence + 0.10),
                        rationale=(
                            "Both specification and source code confirm absence of validation "
                            f"constraints for {method} {pair.spec_path}. The contract omits limits "
                            f"and handler '{source_ep.handler_name}' contains no manual validation."
                        ),
                        remediation=orig.remediation,
                        evidence=orig.evidence,
                        correlation_state=CorrelationState.SUPPORTED,
                        layer=AnalysisLayer.CORRELATED,
                        matched_endpoint=pair,
                        spec_findings=rel_spec_findings,
                        source_findings=(),
                        evidence_pairs=ev_pairs,
                        divergence_details=rationale,
                    )
                )

        return findings
