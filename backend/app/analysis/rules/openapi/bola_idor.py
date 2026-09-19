import re

from app.analysis.context import AnalysisContext
from app.analysis.findings import Evidence, Finding, Severity
from app.analysis.rules.base import SecurityRule

_ID_PATH_PATTERN = re.compile(
    r"\{([a-zA-Z0-9_]*(?:id|uuid|key|account|user|order|item|doc))\}", re.IGNORECASE
)
_OBJECT_ACCESS_METHODS = {"get", "put", "delete", "patch"}


class BolaIdorIndicatorRule(SecurityRule):
    """API-AUTHZ-001: Potential BOLA/IDOR architectural indicator.

    Identifies endpoints with object/resource path identifiers exposing direct object
    access patterns where the specification exhibits coarse or missing
    object-level authorization semantics.
    """

    rule_id = "API-AUTHZ-001"
    rule_version = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        spec = context.specification
        if not spec:
            return findings

        for endpoint in spec.endpoints:
            # Check if path contains an object/resource identifier template
            id_matches = _ID_PATH_PATTERN.findall(endpoint.path)
            if not id_matches:
                continue

            matched_param_name = id_matches[0]

            for op in endpoint.operations:
                if op.method not in _OBJECT_ACCESS_METHODS:
                    continue

                # Check if operation specifies fine-grained object-level scopes
                has_scopes = False
                for req in op.effective_security:
                    for _scheme_name, scopes in req.items():
                        if any("self" in sc or "own" in sc or "tenant" in sc for sc in scopes):
                            has_scopes = True

                # If coarse authentication or no authentication is used without fine-grained scopes
                if not has_scopes:
                    pointer = (
                        op.location.json_pointer if op.location else f"/paths/{op.path}/{op.method}"
                    )

                    has_auth = len(op.effective_security) > 0
                    auth_state = (
                        "coarse authentication without object-scoping requirements"
                        if has_auth
                        else "no authentication requirement"
                    )

                    ev = Evidence(
                        kind="openapi_object_access_pattern",
                        message=(
                            f"Operation {op.method.upper()} {op.path} exposes direct object access "
                            f"via path identifier '{{{matched_param_name}}}' with {auth_state}."
                        ),
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
                                "Potential Broken Object Level Authorization (BOLA/IDOR) "
                                f"architectural indicator ({op.method.upper()} {op.path})"
                            ),
                            severity=Severity.HIGH,
                            confidence=0.65,
                            rationale=(
                                f"The endpoint path '{op.path}' exposes a direct object "
                                f"reference pattern via '{{{matched_param_name}}}'. Because static "
                                "OpenAPI analysis only models the API contract, this finding "
                                "reports an architectural indicator rather than confirmed "
                                "exploitation. An API endpoint with object parameters requires "
                                "the underlying service to verify that the requesting subject "
                                "possesses access rights for that specific object identifier."
                            ),
                            remediation=(
                                "Ensure backend handlers enforce object-level authorization checks "
                                "validating that the authenticated caller has ownership or "
                                f"tenant permissions for the requested '{{{matched_param_name}}}' "
                                f"resource before executing {op.method.upper()}."
                            ),
                            evidence=(ev,),
                        )
                    )

        return findings
