from app.analysis.context import AnalysisContext
from app.analysis.findings import Evidence, Finding, Severity
from app.analysis.rules.base import SecurityRule


class SourceMissingAuthzRule(SecurityRule):
    """API-SOURCE-AUTHZ-001: Potential missing object-level authorization evidence.

    Models explicit evidence relationship:
      endpoint parameter -> identifier usage -> object lookup -> authorization evidence.
    Triggers when user-controlled identifier reaches object lookup but handler contains
    no recognizable role, ownership, permission, or tenant checks.
    """

    rule_id = "API-SOURCE-AUTHZ-001"
    rule_version = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        source = context.source
        if not source:
            return findings

        for ep in source.endpoints:
            # 1. Check if endpoint accepts an object identifier that reaches a resource lookup
            if not ep.object_access_evidence:
                continue

            # 2. Check if handler contains recognizable authorization or tenant isolation checks
            if len(ep.authz_evidence) > 0:
                continue

            # Evidence relationship: parameter -> lookup without authz check
            obj_ev = ep.object_access_evidence[0]
            param_name = obj_ev.symbol or "object_id"
            file_path = obj_ev.location.file if obj_ev.location else ep.file_path
            line = obj_ev.location.line if obj_ev.location else None
            col = obj_ev.location.column if obj_ev.location else None

            ev = Evidence(
                kind="source_missing_object_authorization",
                message=(
                    f"Parameter '{param_name}' on {ep.method.upper()} {ep.path} queries data store "
                    f"in handler '{ep.handler_name}' without recognizable authorization or "
                    "ownership checks."
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
                        "Potential Missing Object-Level Authorization Evidence "
                        f"({ep.method.upper()} {ep.path})"
                    ),
                    severity=Severity.HIGH,
                    confidence=0.65,
                    rationale=(
                        f"Handler '{ep.handler_name}' takes resource identifier '{param_name}' "
                        "and queries the underlying database, but static analysis detected no "
                        "ownership comparisons (e.g. current_user.id == obj.user_id), role "
                        "checks, or tenant-isolation filters within the handler. Absence of "
                        "static evidence does not prove vulnerability, as authorization may "
                        "be enforced at the ORM or repository level."
                    ),
                    remediation=(
                        f"Ensure handler '{ep.handler_name}' verifies that the authenticated "
                        f"caller has ownership or authorization permissions for the requested "
                        f"'{param_name}' resource before returning or modifying the object."
                    ),
                    evidence=(ev,),
                )
            )

        return findings
