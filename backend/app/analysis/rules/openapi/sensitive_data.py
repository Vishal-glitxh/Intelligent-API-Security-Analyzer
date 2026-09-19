import re

from app.analysis.context import AnalysisContext, NormalizedProperty, NormalizedSchema
from app.analysis.findings import Evidence, Finding, Severity
from app.analysis.rules.base import SecurityRule

_STRONG_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^password$|_password$|^passwd$"), "password"),
    (re.compile(r"^secret$|_secret$|^client_secret$"), "secret"),
    (re.compile(r"^private_key$|_private_key$"), "private key"),
    (re.compile(r"^api_key$|^apikey$|_api_key$"), "API key"),
    (re.compile(r"^access_token$|^refresh_token$"), "authentication token"),
]

_MODERATE_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^credential$|_credential$"), "credential"),
    (re.compile(r"^auth_token$"), "auth token"),
    (re.compile(r"^ssn$|^social_security_number$"), "Social Security Number"),
]


def _classify_property_sensitivity(
    prop: NormalizedProperty,
) -> tuple[str, str, str] | None:
    """Classify property into strong or moderate sensitivity indicator.

    Returns (indicator_level, category, matched_text) or None.
    """
    clean_name = prop.name.strip().lower()

    # Format password check
    if prop.format == "password":
        return ("strong", "password format", prop.name)

    # Strong pattern match
    for pattern, label in _STRONG_SENSITIVE_PATTERNS:
        if pattern.search(clean_name):
            return ("strong", label, prop.name)

    # Moderate pattern match
    for pattern, label in _MODERATE_SENSITIVE_PATTERNS:
        if pattern.search(clean_name):
            return ("moderate", label, prop.name)

    return None


class SensitiveDataExposureRule(SecurityRule):
    """API-DATA-001: Potential sensitive-data exposure in response schemas.

    Identifies response properties whose names or formats indicate sensitive
    information (passwords, secrets, tokens, private keys) returned in HTTP responses.
    """

    rule_id = "API-DATA-001"
    rule_version = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        spec = context.specification
        if not spec:
            return findings

        for endpoint in spec.endpoints:
            for op in endpoint.operations:
                for status_code, resp_schema in op.response_schemas.items():
                    # Focus on success responses (2xx) or explicit payload responses
                    if not status_code.startswith("2"):
                        continue

                    self._check_schema_properties(
                        schema=resp_schema,
                        endpoint_path=op.path,
                        method=op.method,
                        status_code=status_code,
                        has_auth=len(op.effective_security) > 0,
                        findings=findings,
                    )

        return findings

    def _check_schema_properties(
        self,
        schema: NormalizedSchema,
        endpoint_path: str,
        method: str,
        status_code: str,
        has_auth: bool,
        findings: list[Finding],
        visited_schemas: frozenset[str] = frozenset(),
    ) -> None:
        if schema.name and schema.name in visited_schemas:
            return
        current_visited = visited_schemas | ({schema.name} if schema.name else set())

        for prop in schema.properties:
            classification = _classify_property_sensitivity(prop)
            if not classification:
                continue

            level, category, prop_name = classification
            is_strong = level == "strong"

            # Severity and confidence based on indicator strength and endpoint authentication
            severity = Severity.HIGH if is_strong else Severity.MEDIUM
            confidence = 0.85 if is_strong else 0.70
            if not has_auth:
                # Unauthenticated endpoint exposing sensitive fields is more acute
                confidence = min(1.0, confidence + 0.05)

            pointer = (
                prop.location.json_pointer
                if prop.location
                else (
                    f"/paths/{endpoint_path}/{method}/responses/"
                    f"{status_code}/properties/{prop_name}"
                )
            )

            auth_desc = "authenticated" if has_auth else "unauthenticated"
            ev = Evidence(
                kind="openapi_response_schema_property",
                message=(
                    f"Response {status_code} on {auth_desc} operation {method.upper()} "
                    f"{endpoint_path} includes field '{prop_name}' matching {level} sensitive "
                    f"indicator ({category})."
                ),
                file=prop.location.file if prop.location else None,
                line=prop.location.line if prop.location else None,
                column=prop.location.column if prop.location else None,
                provenance=f"spec:{pointer}",
            )

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    rule_version=self.rule_version,
                    title=(
                        f"Potential Sensitive-Data Exposure in Response '{prop_name}' "
                        f"({method.upper()} {endpoint_path} [{status_code}])"
                    ),
                    severity=severity,
                    confidence=confidence,
                    rationale=(
                        f"Response schema for {method.upper()} {endpoint_path} contains "
                        f"property '{prop_name}' indicating {category}. While OpenAPI models the "
                        "intended data contract and cannot prove runtime exposure, sensitive "
                        "values such as credentials or tokens should generally not be returned "
                        "in API response bodies."
                    ),
                    remediation=(
                        f"Verify if property '{prop_name}' is necessary in the {status_code} "
                        "response. Mark as 'writeOnly: true' if required on input, or redact "
                        "sensitive values from response serialization DTOs."
                    ),
                    evidence=(ev,),
                )
            )

        # Recurse into nested items schema if present
        if schema.items_schema:
            self._check_schema_properties(
                schema=schema.items_schema,
                endpoint_path=endpoint_path,
                method=method,
                status_code=status_code,
                has_auth=has_auth,
                findings=findings,
                visited_schemas=current_visited,
            )
