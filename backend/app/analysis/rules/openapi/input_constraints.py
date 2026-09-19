from app.analysis.context import AnalysisContext, NormalizedParameter
from app.analysis.findings import Evidence, Finding, Severity
from app.analysis.rules.base import SecurityRule

_PAGINATION_NAMES = {
    "limit",
    "pagesize",
    "page_size",
    "count",
    "max_results",
    "size",
    "per_page",
}
_REDIRECT_NAMES = {
    "redirect",
    "redirect_url",
    "return_to",
    "callback_url",
    "next",
    "target_url",
    "dest",
    "destination",
}
_FILE_PATH_NAMES = {
    "file",
    "filename",
    "filepath",
}


def _check_security_relevant_parameter(
    param: NormalizedParameter,
) -> tuple[bool, str, str, str] | None:
    """Evaluate if a parameter is security-relevant and lacks essential boundary constraints.

    Returns (is_vulnerable, category, missing_constraint, rationale) or None.
    """
    clean_name = param.name.strip().lower()
    schema_type = (param.schema_type or "").lower()
    c = param.constraints

    # 1. Pagination / Limit integer parameters
    if clean_name in _PAGINATION_NAMES and schema_type in ("integer", "number"):
        has_max = "maximum" in c or "exclusiveMaximum" in c
        if not has_max:
            return (
                True,
                "pagination_limit",
                "maximum",
                (
                    f"Parameter '{param.name}' controls result pagination or quantity "
                    "but lacks an upper bound ('maximum'). Without a ceiling, clients "
                    "can request excessively large result sets, risking database "
                    "strain and denial-of-service."
                ),
            )

    # 2. Redirect URL parameters
    if clean_name in _REDIRECT_NAMES and (schema_type == "string" or not schema_type):
        has_pattern = "pattern" in c
        has_format = c.get("format") in ("uri", "url")
        has_enum = "enum" in c
        if not (has_pattern or has_format or has_enum):
            return (
                True,
                "redirect_url",
                "format: uri, pattern, or enum",
                (
                    f"Parameter '{param.name}' appears to specify a redirect destination "
                    "or callback URL but lacks validation constraints ('format: uri', "
                    "'pattern', or 'enum'). Unvalidated redirect targets expose "
                    "applications to open-redirection attacks."
                ),
            )

    # 3. File / Path parameters
    if clean_name in _FILE_PATH_NAMES and (schema_type == "string" or not schema_type):
        has_pattern = "pattern" in c
        has_max_len = "maxLength" in c
        has_enum = "enum" in c
        if not (has_pattern or has_max_len or has_enum):
            return (
                True,
                "file_path",
                "pattern, maxLength, or enum",
                (
                    f"Parameter '{param.name}' accepts file or system path inputs "
                    "without structural constraints ('pattern', 'maxLength', or 'enum'). "
                    "Unconstrained path arguments increase the risk of path traversal "
                    "if passed directly to file-system operations."
                ),
            )

    return None


class InputConstraintsRule(SecurityRule):
    """API-INPUT-001: Potential weak/missing input constraints.

    Narrowly inspects well-defined security-relevant parameters (pagination limits,
    redirect targets, file paths) for missing boundary and format constraints.
    """

    rule_id = "API-INPUT-001"
    rule_version = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        spec = context.specification
        if not spec:
            return findings

        for endpoint in spec.endpoints:
            for op in endpoint.operations:
                for param in op.parameters:
                    res = _check_security_relevant_parameter(param)
                    if not res:
                        continue
                    _, category, missing_constraint, rationale = res

                    pointer = (
                        param.location.json_pointer
                        if param.location
                        else f"/paths/{op.path}/{op.method}/parameters/{param.name}"
                    )

                    ev = Evidence(
                        kind="openapi_parameter_constraint",
                        message=(
                            f"Parameter '{param.name}' in {param.param_in} on {op.method.upper()} "
                            f"{op.path} is security-relevant ({category}) but lacks expected "
                            f"constraint: {missing_constraint}."
                        ),
                        file=param.location.file if param.location else None,
                        line=param.location.line if param.location else None,
                        column=param.location.column if param.location else None,
                        provenance=f"spec:{pointer}",
                    )

                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            rule_version=self.rule_version,
                            title=(
                                f"Potential Missing Input Constraint on '{param.name}' "
                                f"({op.method.upper()} {op.path})"
                            ),
                            severity=Severity.MEDIUM,
                            confidence=0.75,
                            rationale=rationale,
                            remediation=(
                                f"Define explicit validation constraints for '{param.name}', "
                                f"such as adding '{missing_constraint}' in the parameter schema."
                            ),
                            evidence=(ev,),
                        )
                    )

        return findings
