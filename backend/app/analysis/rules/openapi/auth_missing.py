from app.analysis.context import AnalysisContext
from app.analysis.findings import Evidence, Finding, Severity
from app.analysis.rules.base import SecurityRule

_STATE_CHANGING_METHODS = {"post", "put", "delete", "patch"}


class MissingAuthRule(SecurityRule):
    """API-AUTH-001: Potential missing authentication requirement.

    Detects operations that have no effective security requirements in the specification,
    prioritizing explicit OpenAPI security semantics (operation-level and global security).
    """

    rule_id = "API-AUTH-001"
    rule_version = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        spec = context.specification
        if not spec:
            return findings

        # Check if specification defines security schemes or global security
        has_schemes = len(spec.security_schemes) > 0
        has_global_sec = len(spec.global_security) > 0

        for endpoint in spec.endpoints:
            for op in endpoint.operations:
                # Primary condition: no effective security requirement
                if len(op.effective_security) > 0:
                    continue

                is_mutation = op.method in _STATE_CHANGING_METHODS

                # Determine provenance and exact evidence details
                if op.has_explicit_security_override and len(op.security_requirements) == 0:
                    evidence_msg = (
                        f"Operation {op.method.upper()} {op.path} explicitly overrides "
                        f"security with an empty requirement list (security: [])."
                    )
                    rationale = (
                        "The operation explicitly disables authentication by overriding "
                        "global security with an empty list. State-changing or sensitive "
                        "operations without authentication can be invoked by untrusted clients."
                    )
                elif has_schemes or has_global_sec:
                    evidence_msg = (
                        f"Operation {op.method.upper()} {op.path} has no effective security "
                        f"requirement while specification defines security schemes."
                    )
                    rationale = (
                        "The specification defines security schemes, but this operation lacks "
                        "both operation-level security and global security coverage."
                    )
                else:
                    evidence_msg = (
                        f"Operation {op.method.upper()} {op.path} lacks security requirements; "
                        f"no security schemes or global security are defined in specification."
                    )
                    rationale = (
                        "The API specification contains no authentication schemes or global "
                        "security requirements for this operation."
                    )

                # Assign severity: state-changing mutations represent higher potential impact
                severity = Severity.HIGH if is_mutation else Severity.MEDIUM
                # Initial implementation default confidence; subject to research calibration
                confidence = 0.85 if is_mutation else 0.70

                pointer = (
                    op.location.json_pointer if op.location else f"/paths/{op.path}/{op.method}"
                )
                ev = Evidence(
                    kind="openapi_security",
                    message=evidence_msg,
                    file=op.location.file if op.location else None,
                    line=op.location.line if op.location else None,
                    column=op.location.column if op.location else None,
                    provenance=f"spec:{pointer}",
                )

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        rule_version=self.rule_version,
                        title=(
                            "Potential Missing Authentication Requirement "
                            f"({op.method.upper()} {op.path})"
                        ),
                        severity=severity,
                        confidence=confidence,
                        rationale=rationale,
                        remediation=(
                            "Define an appropriate security scheme (e.g. Bearer, OAuth2, "
                            f"or ApiKey) and apply it to operation {op.method.upper()} {op.path} "
                            "or at the global level."
                        ),
                        evidence=(ev,),
                    )
                )

        return findings
