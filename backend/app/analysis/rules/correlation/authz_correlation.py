from collections.abc import Sequence

from app.analysis.context import AnalysisContext, SourceLocation
from app.analysis.correlation.aligner import align_authorization_evidence
from app.analysis.correlation.models import (
    AnalysisLayer,
    CorrelatedEvidencePair,
    CorrelatedFinding,
    CorrelationState,
    MatchedEndpointPair,
)
from app.analysis.findings import Evidence, Finding, Severity
from app.analysis.rules.correlation.base import CorrelationRule


def _resolve_evidence(
    ev_pairs: Sequence[CorrelatedEvidencePair],
    rel_spec_findings: tuple[Finding, ...],
    rel_source_findings: tuple[Finding, ...],
    fallback_kind: str,
    fallback_msg: str,
    fallback_loc: SourceLocation | None,
) -> tuple[Evidence, ...]:
    evs: list[Evidence] = []
    for p in ev_pairs:
        if p.spec_evidence:
            evs.append(p.spec_evidence)
    if not evs and rel_spec_findings:
        evs.extend(rel_spec_findings[0].evidence)
    if not evs and rel_source_findings:
        evs.extend(rel_source_findings[0].evidence)
    if not evs:
        evs.append(
            Evidence(
                kind=fallback_kind,
                message=fallback_msg,
                file=fallback_loc.file if fallback_loc else None,
                line=fallback_loc.line if fallback_loc else None,
                column=fallback_loc.column if fallback_loc else None,
                provenance=f"correlated:{fallback_kind}",
            )
        )
    return tuple(evs)


class ObjectAuthorizationCorrelationRule(CorrelationRule):
    """CORR-AUTHZ-001: Correlates Broken Object Level Authorization (BOLA/IDOR) evidence.

    Preserves explicit evidence chain:
      endpoint param -> identifier usage -> object lookup -> authz/ownership/tenant evidence

    Synthesizes:
    - Spec exposes user-controlled path parameter
    - Source handler performs direct data store query with that parameter
    - Source handler exhibits absence of recognizable authz/ownership/tenant checks in scope
    """

    rule_id = "CORR-AUTHZ-001"
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

            corr_state, ev_pairs, rationale = align_authorization_evidence(
                pair=pair,
                spec_findings=list(spec_findings),
                source_findings=list(source_findings),
            )

            # Retrieve contributing single-layer findings
            rel_spec_findings = tuple(
                f
                for f in spec_findings
                if f.rule_id == "API-AUTHZ-001"
                and any(ev.message and spec_op.path in ev.message for ev in f.evidence)
            )
            rel_source_findings = tuple(
                f
                for f in source_findings
                if f.rule_id == "API-SOURCE-AUTHZ-001"
                and any(ev.message and spec_op.path in ev.message for ev in f.evidence)
            )

            # When spec exposes direct ID and source queries DB without authorization check:
            if corr_state == CorrelationState.COMPLEMENTARY:
                findings.append(
                    CorrelatedFinding(
                        rule_id=self.rule_id,
                        rule_version=self.rule_version,
                        title=(
                            "Correlated Potential BOLA Indicator: Public Identifier Reaches "
                            f"Unprotected Object Lookup ({method} {pair.spec_path})"
                        ),
                        severity=Severity.HIGH,
                        confidence=0.85,  # Synthesized multi-layer confidence
                        rationale=(
                            f"Multi-layer evidence synthesis identifies a potential BOLA/IDOR "
                            f"condition: OpenAPI specification defines an object identifier in "
                            f"path {pair.spec_path}, and static source analysis reveals that "
                            f"handler '{source_ep.handler_name}' directly queries a database "
                            "entity using that identifier without recognizable caller ownership "
                            "comparison, role check, or tenant filter in the analyzable scope. "
                            "While authorization might be enforced at a lower ORM or gateway "
                            "layer, this unprotected direct object reference warrants verification."
                        ),
                        remediation=(
                            f"Ensure that handler '{source_ep.handler_name}' enforces object-level "
                            "access control by verifying that the authenticated caller owns the "
                            "requested object or possesses sufficient tenant/role permissions."
                        ),
                        evidence=_resolve_evidence(
                            ev_pairs,
                            rel_spec_findings,
                            rel_source_findings,
                            fallback_kind="correlated_bola_indicator",
                            fallback_msg=(
                                f"Public identifier on {method} {pair.spec_path} reaches "
                                f"data store in handler '{source_ep.handler_name}' without "
                                "authorization check."
                            ),
                            fallback_loc=pair.source_location or pair.spec_location,
                        ),
                        correlation_state=CorrelationState.COMPLEMENTARY,
                        layer=AnalysisLayer.CORRELATED,
                        matched_endpoint=pair,
                        spec_findings=rel_spec_findings,
                        source_findings=rel_source_findings,
                        evidence_pairs=ev_pairs,
                        divergence_details=rationale,
                    )
                )

        return findings
