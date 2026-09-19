from app.analysis.context import AnalysisContext
from app.analysis.findings import Evidence, Finding, Severity
from app.analysis.rules.base import SecurityRule

_STATE_CHANGING_METHODS = {"post", "put", "delete", "patch"}


class InconsistentAuthRule(SecurityRule):
    """API-AUTH-002: Potential inconsistent authentication coverage.

    Identifies resource endpoints where sibling operations on the same path differ
    unexpectedly in security coverage, using sibling operations as evidence.
    """

    rule_id = "API-AUTH-002"
    rule_version = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        spec = context.specification
        if not spec:
            return findings

        for endpoint in spec.endpoints:
            if len(endpoint.operations) < 2:
                continue

            auth_ops = [op for op in endpoint.operations if len(op.effective_security) > 0]
            unauth_ops = [op for op in endpoint.operations if len(op.effective_security) == 0]

            # Inconsistency requires both authenticated and unauthenticated
            # operations on the same path
            if not auth_ops or not unauth_ops:
                continue

            for unauth_op in unauth_ops:
                # Reference sibling authenticated operation as evidence
                auth_sibling = auth_ops[0]
                auth_schemes_list = [
                    list(s.keys()) for s in auth_sibling.effective_security if isinstance(s, dict)
                ]
                scheme_summary = ", ".join(sum(auth_schemes_list, [])) or "configured security"

                unauth_pointer = (
                    unauth_op.location.json_pointer
                    if unauth_op.location
                    else f"/paths/{unauth_op.path}/{unauth_op.method}"
                )
                auth_pointer = (
                    auth_sibling.location.json_pointer
                    if auth_sibling.location
                    else f"/paths/{auth_sibling.path}/{auth_sibling.method}"
                )

                ev_unauth = Evidence(
                    kind="openapi_unauthenticated_operation",
                    message=(
                        f"Operation {unauth_op.method.upper()} {unauth_op.path} has no effective "
                        f"security requirement."
                    ),
                    file=unauth_op.location.file if unauth_op.location else None,
                    line=unauth_op.location.line if unauth_op.location else None,
                    column=unauth_op.location.column if unauth_op.location else None,
                    provenance=f"spec:{unauth_pointer}",
                )
                ev_sibling = Evidence(
                    kind="openapi_sibling_security_baseline",
                    message=(
                        f"Sibling operation {auth_sibling.method.upper()} {auth_sibling.path} on "
                        f"the same resource requires {scheme_summary}."
                    ),
                    file=auth_sibling.location.file if auth_sibling.location else None,
                    line=auth_sibling.location.line if auth_sibling.location else None,
                    column=auth_sibling.location.column if auth_sibling.location else None,
                    provenance=f"spec:{auth_pointer}",
                )

                is_mutation = unauth_op.method in _STATE_CHANGING_METHODS
                severity = Severity.HIGH if is_mutation else Severity.MEDIUM
                confidence = 0.80

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        rule_version=self.rule_version,
                        title=(
                            "Potential Inconsistent Authentication Coverage "
                            f"({unauth_op.method.upper()} {unauth_op.path})"
                        ),
                        severity=severity,
                        confidence=confidence,
                        rationale=(
                            f"Resource {endpoint.path} defines authentication on "
                            f"{auth_sibling.method.upper()}, but sibling operation "
                            f"{unauth_op.method.upper()} lacks security requirements. "
                            "Related operations on the same entity typically share consistent "
                            "security boundaries unless explicitly segmented."
                        ),
                        remediation=(
                            f"Verify whether {unauth_op.method.upper()} {unauth_op.path} "
                            f"should require the same security scheme ({scheme_summary}) "
                            "as its sibling operation."
                        ),
                        evidence=(ev_unauth, ev_sibling),
                    )
                )

        return findings
