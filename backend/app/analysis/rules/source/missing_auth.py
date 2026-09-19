from app.analysis.context import AnalysisContext, AuthState
from app.analysis.findings import Evidence, Finding, Severity
from app.analysis.rules.base import SecurityRule

_STATE_MUTATION_METHODS = {"post", "put", "delete", "patch"}


class SourceMissingAuthRule(SecurityRule):
    """API-SOURCE-AUTH-001: Potential missing recognizable authentication evidence.

    Flags endpoints where static analysis did not identify recognizable authentication
    decorators, dependencies, or router-level security policies within analyzable scope.
    """

    rule_id = "API-SOURCE-AUTH-001"
    rule_version = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        source = context.source
        if not source:
            return findings

        for ep in source.endpoints:
            # Only flag when authentication is absent in analyzable scope
            if ep.auth_state != AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE:
                continue

            is_mutation = ep.method in _STATE_MUTATION_METHODS
            severity = Severity.HIGH if is_mutation else Severity.MEDIUM
            confidence = 0.70  # Baseline default; reflects static analyzable scope

            file_path = ep.location.file if ep.location else ep.file_path
            line = ep.location.line if ep.location else None
            col = ep.location.column if ep.location else None

            ev = Evidence(
                kind="source_endpoint_auth_absent",
                message=(
                    f"Endpoint {ep.method.upper()} {ep.path} in handler '{ep.handler_name}' "
                    "has no recognizable authentication decorator or dependency."
                ),
                file=file_path,
                line=line,
                column=col,
                provenance=f"source:{file_path}:{line}" if line else f"source:{file_path}",
            )

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    rule_version=self.rule_version,
                    title=(
                        "Potential Missing Recognizable Authentication Evidence "
                        f"({ep.method.upper()} {ep.path})"
                    ),
                    severity=severity,
                    confidence=confidence,
                    rationale=(
                        f"Static source inspection of handler '{ep.handler_name}' found no "
                        "recognizable authentication dependencies or decorators. While "
                        "authentication may be enforced by upstream gateways or middleware, "
                        "handlers without explicit security declarations warrant verification."
                    ),
                    remediation=(
                        f"Verify if operation {ep.method.upper()} {ep.path} "
                        "requires authentication. If so, attach an explicit "
                        "authentication dependency (e.g. Depends(get_current_user)) "
                        "or route decorator (e.g. @login_required)."
                    ),
                    evidence=(ev,),
                )
            )

        return findings
