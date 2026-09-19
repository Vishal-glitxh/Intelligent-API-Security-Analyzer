from collections.abc import Sequence

from app.analysis.context import AnalysisContext, AuthState, SourceLocation
from app.analysis.correlation.aligner import align_authentication_evidence
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


class AuthenticationCorrelationRule(CorrelationRule):
    """CORR-AUTH-001: Evaluates cross-layer authentication consistency and divergence.

    Detects:
    1. Spec requires security, but source lacks recognizable auth in scope (CONTRADICTED).
    2. Spec documents public endpoint, but source enforces auth (Drift / CONTRADICTED).
    3. Both layers affirm lack of auth on mutation operations (Corroborated / SUPPORTED).
    """

    rule_id = "CORR-AUTH-001"
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
            is_mutation = method in ("POST", "PUT", "DELETE", "PATCH")

            corr_state, ev_pairs, rationale = align_authentication_evidence(
                pair=pair,
                spec_findings=list(spec_findings),
                source_findings=list(source_findings),
            )

            # Find matching single-layer findings for lineage
            rel_spec_findings = tuple(
                f
                for f in spec_findings
                if f.rule_id in ("API-AUTH-001", "API-AUTH-002")
                and any(ev.message and spec_op.path in ev.message for ev in f.evidence)
            )
            rel_source_findings = tuple(
                f
                for f in source_findings
                if f.rule_id == "API-SOURCE-AUTH-001"
                and any(ev.message and spec_op.path in ev.message for ev in f.evidence)
            )

            # Case 1: Spec declares security, but source code lacks evidence in analyzable scope
            if (
                len(spec_op.effective_security) > 0
                and source_ep.auth_state == AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE
            ):
                sev = Severity.HIGH if is_mutation else Severity.MEDIUM
                findings.append(
                    CorrelatedFinding(
                        rule_id=self.rule_id,
                        rule_version=self.rule_version,
                        title=(
                            "Potential Authentication Divergence: Spec Claims Security, "
                            f"Source Lacks Recognizable Evidence ({method} {pair.spec_path})"
                        ),
                        severity=sev,
                        confidence=0.80,  # Explicit research metadata baseline
                        rationale=(
                            f"The OpenAPI specification declares security requirements "
                            f"({spec_op.effective_security}) for {method} {pair.spec_path}, "
                            f"but static source analysis of handler '{source_ep.handler_name}' "
                            "found no recognizable authentication dependencies or route "
                            "decorators in the analyzable scope. While authentication might be "
                            "enforced by an upstream API gateway, service mesh, or unanalyzed "
                            "middleware, this specification-implementation divergence warrants "
                            "security verification."
                        ),
                        remediation=(
                            f"Verify whether {method} {pair.spec_path} is protected upstream or "
                            "requires an explicit in-code authentication dependency "
                            "(e.g. Depends(get_current_user)) or decorator (e.g. @login_required)."
                        ),
                        evidence=_resolve_evidence(
                            ev_pairs,
                            rel_spec_findings,
                            rel_source_findings,
                            fallback_kind="correlated_auth_divergence",
                            fallback_msg=(
                                f"Specification requires security {spec_op.effective_security} but "
                                f"source handler '{source_ep.handler_name}' lacks evidence."
                            ),
                            fallback_loc=pair.source_location or pair.spec_location,
                        ),
                        correlation_state=CorrelationState.CONTRADICTED,
                        layer=AnalysisLayer.CORRELATED,
                        matched_endpoint=pair,
                        spec_findings=rel_spec_findings,
                        source_findings=rel_source_findings,
                        evidence_pairs=ev_pairs,
                        divergence_details=rationale,
                    )
                )

            # Case 2: Spec claims public, but source enforces authentication (Documentation drift)
            elif (
                len(spec_op.effective_security) == 0
                and source_ep.auth_state == AuthState.AUTH_PRESENT
            ):
                findings.append(
                    CorrelatedFinding(
                        rule_id=self.rule_id,
                        rule_version=self.rule_version,
                        title=(
                            "API Documentation Drift: Spec Claims Public Endpoint, "
                            f"Source Implements Authentication ({method} {pair.spec_path})"
                        ),
                        severity=Severity.LOW,
                        confidence=0.80,
                        rationale=(
                            f"OpenAPI specification defines {method} {pair.spec_path} without "
                            f"security schemes (public access), but source handler "
                            f"'{source_ep.handler_name}' enforces authentication dependencies "
                            "in code. The API documentation has drifted from the implementation."
                        ),
                        remediation=(
                            f"Update the OpenAPI specification for {method} {pair.spec_path} to "
                            "document the security requirements enforced by the source code."
                        ),
                        evidence=_resolve_evidence(
                            ev_pairs,
                            rel_spec_findings,
                            rel_source_findings,
                            fallback_kind="correlated_auth_drift",
                            fallback_msg=(
                                f"Specification documents {method} {pair.spec_path} as public but "
                                f"source handler '{source_ep.handler_name}' enforces auth."
                            ),
                            fallback_loc=pair.source_location or pair.spec_location,
                        ),
                        correlation_state=CorrelationState.CONTRADICTED,
                        layer=AnalysisLayer.CORRELATED,
                        matched_endpoint=pair,
                        spec_findings=rel_spec_findings,
                        source_findings=rel_source_findings,
                        evidence_pairs=ev_pairs,
                        divergence_details=rationale,
                    )
                )

            # Case 3: Both layers affirm lack of authentication on sensitive operations
            elif (
                len(spec_op.effective_security) == 0
                and source_ep.auth_state == AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE
                and is_mutation
            ):
                findings.append(
                    CorrelatedFinding(
                        rule_id=self.rule_id,
                        rule_version=self.rule_version,
                        title=(
                            "Corroborated Potential Missing Authentication on Mutation "
                            f"({method} {pair.spec_path})"
                        ),
                        severity=Severity.HIGH,
                        confidence=0.90,  # Corroboration elevates confidence
                        rationale=(
                            f"Both specification and source implementation independently affirm "
                            f"that state-changing operation {method} {pair.spec_path} lacks "
                            f"authentication. OpenAPI defines no security schemes, and handler "
                            f"'{source_ep.handler_name}' exhibits no recognizable authentication "
                            "checks in analyzable scope."
                        ),
                        remediation=(
                            f"Add appropriate authentication requirements to {method} "
                            f"{pair.spec_path} in both the OpenAPI document and the backend "
                            "route handler."
                        ),
                        evidence=_resolve_evidence(
                            ev_pairs,
                            rel_spec_findings,
                            rel_source_findings,
                            fallback_kind="correlated_unauthenticated_mutation",
                            fallback_msg=(
                                f"Both layers confirm missing authentication for mutation "
                                f"{method} {pair.spec_path}."
                            ),
                            fallback_loc=pair.source_location or pair.spec_location,
                        ),
                        correlation_state=CorrelationState.SUPPORTED,
                        layer=AnalysisLayer.CORRELATED,
                        matched_endpoint=pair,
                        spec_findings=rel_spec_findings,
                        source_findings=rel_source_findings,
                        evidence_pairs=ev_pairs,
                        divergence_details=rationale,
                    )
                )

        return findings
