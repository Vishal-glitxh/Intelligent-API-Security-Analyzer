import ast
import re

from app.analysis.context import (
    AuthState,
    EvidenceCategory,
    EvidenceStrength,
    NormalizedSourceEndpoint,
    NormalizedSourceParameter,
    SourceSecurityEvidence,
)
from app.analysis.source.parser import ParsedFunction, ParsedModule

_FLASK_PARAM_PATTERN = re.compile(r"<(?:[a-zA-Z_][a-zA-Z0-9_]*:)?([a-zA-Z_][a-zA-Z0-9_]*)>")
_AUTH_DECORATOR_NAMES = {
    "login_required",
    "jwt_required",
    "auth_required",
    "token_required",
    "require_auth",
    "require_login",
}


def normalize_flask_path(raw_path: str, prefix: str = "") -> str:
    """Normalizes Flask route parameter syntax to canonical OpenAPI `{param}` format.

    Examples:
      - /users/<user_id> -> /users/{user_id}
      - /items/<int:item_id> -> /items/{item_id}
      - /files/<path:filepath> -> /files/{filepath}
    """
    clean_prefix = prefix.strip()
    clean_path = raw_path.strip()

    if clean_prefix and clean_path:
        combined = f"/{clean_prefix.strip('/')}/{clean_path.strip('/')}".rstrip("/")
    elif clean_prefix:
        combined = f"/{clean_prefix.strip('/')}"
    else:
        combined = f"/{clean_path.strip('/')}"

    if not combined:
        combined = "/"

    # Replace <converter:param> or <param> with {param}
    canonical = _FLASK_PARAM_PATTERN.sub(r"{\1}", combined)
    return canonical


def _extract_string_constant(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _find_blueprint_prefixes(module: ParsedModule) -> dict[str, str]:
    """Scans module assignments for Blueprint definitions with url_prefix."""
    blueprints: dict[str, str] = {}

    if not module.ast_root:
        return blueprints

    for stmt in ast.walk(module.ast_root):
        if isinstance(stmt, ast.Assign):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name) and isinstance(stmt.value, ast.Call):
                    func_name = ""
                    if isinstance(stmt.value.func, ast.Name):
                        func_name = stmt.value.func.id
                    elif isinstance(stmt.value.func, ast.Attribute):
                        func_name = stmt.value.func.attr

                    if func_name == "Blueprint":
                        prefix = ""
                        for kw in stmt.value.keywords:
                            if kw.arg == "url_prefix":
                                val = _extract_string_constant(kw.value)
                                if val:
                                    prefix = val
                        blueprints[tgt.id] = prefix

    return blueprints


def _extract_flask_auth(fn: ParsedFunction) -> list[SourceSecurityEvidence]:
    """Detects authentication decorators on Flask handler functions."""
    evidence_list: list[SourceSecurityEvidence] = []

    for dec in fn.decorators:
        dec_name = dec.name.split(".")[-1].lower()
        if dec_name in _AUTH_DECORATOR_NAMES:
            loc = dec.location or fn.location
            evidence_list.append(
                SourceSecurityEvidence(
                    category=EvidenceCategory.AUTHENTICATION,
                    strength=EvidenceStrength.STRONG,
                    message=f"Authentication decorator detected: @{dec.name}",
                    location=loc,
                    symbol=dec.name,
                    handler_name=fn.name,
                    extracted_value=dec.name,
                    rationale="Flask endpoint enforces authentication via route decorator.",
                )
            )

    return evidence_list


def extract_flask_endpoints(module: ParsedModule) -> list[NormalizedSourceEndpoint]:
    """Extracts all Flask endpoints, parameters, and authentication states from a parsed module."""
    endpoints: list[NormalizedSourceEndpoint] = []
    blueprints = _find_blueprint_prefixes(module)

    for fn in module.functions:
        for dec in fn.decorators:
            dec_name = dec.name.lower()
            if not dec_name.endswith(".route") and dec_name != "route":
                continue

            parts = dec_name.split(".")
            bp_var = parts[0] if len(parts) > 1 else ""

            # Extract raw path
            raw_path = "/"
            if dec.args:
                extracted = _extract_string_constant(dec.args[0])
                if extracted is not None:
                    raw_path = extracted

            # Apply Blueprint prefix if present
            prefix = blueprints.get(bp_var, "")
            canonical_path = normalize_flask_path(raw_path, prefix)

            # Determine HTTP methods
            methods: list[str] = ["get"]
            if "methods" in dec.keywords:
                methods_node = dec.keywords["methods"]
                if isinstance(methods_node, (ast.List, ast.Tuple)):
                    parsed_methods = [
                        val.lower()
                        for elt in methods_node.elts
                        if (val := _extract_string_constant(elt)) is not None
                    ]
                    if parsed_methods:
                        methods = parsed_methods

            # Extract parameters
            params: list[NormalizedSourceParameter] = []
            for arg in fn.parameters:
                is_path = f"{{{arg.name}}}" in canonical_path
                params.append(
                    NormalizedSourceParameter(
                        name=arg.name,
                        param_type=arg.annotation,
                        is_path_param=is_path,
                        location=arg.location,
                    )
                )

            # Extract authentication
            auth_ev = _extract_flask_auth(fn)
            auth_state = (
                AuthState.AUTH_PRESENT
                if len(auth_ev) > 0
                else AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE
            )

            for m in methods:
                endpoints.append(
                    NormalizedSourceEndpoint(
                        method=m,
                        path=canonical_path,
                        raw_path=raw_path,
                        handler_name=fn.name,
                        file_path=module.file_path,
                        framework="flask",
                        location=dec.location or fn.location,
                        parameters=tuple(params),
                        auth_state=auth_state,
                        auth_evidence=tuple(auth_ev),
                        authz_evidence=(),
                        object_access_evidence=(),
                        tenant_evidence=(),
                        validation_evidence=(),
                        router_prefix=prefix if prefix else None,
                    )
                )

    return endpoints
