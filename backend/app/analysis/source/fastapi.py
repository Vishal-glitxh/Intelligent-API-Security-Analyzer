import ast

from app.analysis.context import (
    AuthState,
    EvidenceCategory,
    EvidenceStrength,
    NormalizedSourceEndpoint,
    NormalizedSourceParameter,
    SourceLocation,
    SourceSecurityEvidence,
)
from app.analysis.source.parser import ParsedFunction, ParsedModule

_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}


def _normalize_fastapi_path(prefix: str, path: str) -> str:
    """Concatenates router prefix and route path into a canonical clean path."""
    clean_prefix = prefix.strip()
    clean_path = path.strip()

    if clean_prefix and clean_path:
        p = f"/{clean_prefix.strip('/')}/{clean_path.strip('/')}".rstrip("/")
    elif clean_prefix:
        p = f"/{clean_prefix.strip('/')}"
    else:
        p = f"/{clean_path.strip('/')}"
    return p if p else "/"


def _extract_string_constant(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _find_router_prefixes(module: ParsedModule) -> dict[str, tuple[str, tuple[str, ...]]]:
    """Scans module assignments for APIRouter definitions with prefix and dependencies.

    Returns dict mapping router variable name -> (prefix_string, dependencies_tuple).
    """
    routers: dict[str, tuple[str, tuple[str, ...]]] = {}

    if not module.ast_root:
        return routers

    for stmt in ast.walk(module.ast_root):
        if isinstance(stmt, ast.Assign):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name) and isinstance(stmt.value, ast.Call):
                    func_name = ""
                    if isinstance(stmt.value.func, ast.Name):
                        func_name = stmt.value.func.id
                    elif isinstance(stmt.value.func, ast.Attribute):
                        func_name = stmt.value.func.attr

                    if func_name == "APIRouter":
                        prefix = ""
                        deps: list[str] = []

                        for kw in stmt.value.keywords:
                            if kw.arg == "prefix":
                                val = _extract_string_constant(kw.value)
                                if val:
                                    prefix = val
                            elif kw.arg == "dependencies" and isinstance(kw.value, ast.List):
                                for elt in kw.value.elts:
                                    deps.append(ast.unparse(elt))

                        routers[tgt.id] = (prefix, tuple(deps))

    return routers


def _extract_auth_from_params(fn: ParsedFunction) -> list[SourceSecurityEvidence]:
    """Detects Depends/Security authentication dependencies in function parameters."""
    evidence_list: list[SourceSecurityEvidence] = []

    # Inspect all default values in function definition
    defaults = fn.node.args.defaults
    num_args = len(fn.node.args.args)
    num_defaults = len(defaults)
    offset = num_args - num_defaults

    for i, default_node in enumerate(defaults):
        arg = fn.node.args.args[offset + i]
        default_str = ast.unparse(default_node)
        loc = SourceLocation(
            file=fn.location.file,
            line=default_node.lineno,
            column=default_node.col_offset + 1,
        )

        if "Depends" in default_str or "Security" in default_str:
            evidence_list.append(
                SourceSecurityEvidence(
                    category=EvidenceCategory.AUTHENTICATION,
                    strength=EvidenceStrength.STRONG,
                    message=(
                        f"Authentication dependency detected on parameter "
                        f"'{arg.arg}': {default_str}"
                    ),
                    location=loc,
                    symbol=arg.arg,
                    handler_name=fn.name,
                    extracted_value=default_str,
                    rationale="FastAPI endpoint enforces authentication via dependency injection.",
                )
            )

    return evidence_list


def extract_fastapi_endpoints(module: ParsedModule) -> list[NormalizedSourceEndpoint]:
    """Extracts all FastAPI endpoints and authentication states from a module."""
    endpoints: list[NormalizedSourceEndpoint] = []
    routers = _find_router_prefixes(module)

    for fn in module.functions:
        for dec in fn.decorators:
            # Check decorator pattern: @app.get(...), @router.post(...)
            dec_name = dec.name.lower()
            parts = dec_name.split(".")
            router_var = parts[0] if len(parts) > 1 else ""
            method = parts[-1] if len(parts) > 1 else ""

            if method not in _HTTP_METHODS and method != "api_route":
                continue

            # Extract path string
            path_val = "/"
            if dec.args:
                extracted = _extract_string_constant(dec.args[0])
                if extracted is not None:
                    path_val = extracted

            # Apply router prefix if known
            prefix, router_deps = routers.get(router_var, ("", ()))
            canonical_path = _normalize_fastapi_path(prefix, path_val)

            # Determine HTTP methods
            methods_to_add = [method]
            if method == "api_route" and "methods" in dec.keywords:
                methods_node = dec.keywords["methods"]
                if isinstance(methods_node, (ast.List, ast.Tuple)):
                    parsed_methods = [
                        val.lower()
                        for elt in methods_node.elts
                        if (val := _extract_string_constant(elt)) is not None
                    ]
                    if parsed_methods:
                        methods_to_add = parsed_methods

            # Extract parameters
            params: list[NormalizedSourceParameter] = []
            for arg in fn.parameters:
                is_path = f"{{{arg.name}}}" in canonical_path
                has_val = bool(
                    arg.annotation
                    and any(
                        k in arg.annotation
                        for k in ("Query", "Path", "Field", "le=", "ge=", "min_length=")
                    )
                )
                params.append(
                    NormalizedSourceParameter(
                        name=arg.name,
                        param_type=arg.annotation,
                        default_value=arg.default_str,
                        is_path_param=is_path,
                        has_validation=has_val,
                        validation_details=arg.annotation if has_val else None,
                        location=arg.location,
                    )
                )

            # Extract authentication evidence
            auth_ev: list[SourceSecurityEvidence] = []

            # 1. Parameter-level auth
            param_auth = _extract_auth_from_params(fn)
            auth_ev.extend(param_auth)

            # 2. Decorator-level dependencies: dependencies=[Depends(...)]
            if "dependencies" in dec.keywords:
                deps_node = dec.keywords["dependencies"]
                dep_str = ast.unparse(deps_node)
                loc = dec.location or fn.location
                auth_ev.append(
                    SourceSecurityEvidence(
                        category=EvidenceCategory.AUTHENTICATION,
                        strength=EvidenceStrength.STRONG,
                        message=f"Authentication dependency detected on route decorator: {dep_str}",
                        location=loc,
                        symbol=dec.name,
                        endpoint_path=canonical_path,
                        endpoint_method=method,
                        handler_name=fn.name,
                        extracted_value=dep_str,
                        rationale=(
                            "FastAPI route declares explicit security dependencies on decorator."
                        ),
                    )
                )

            # 3. Router-level dependencies
            for r_dep in router_deps:
                auth_ev.append(
                    SourceSecurityEvidence(
                        category=EvidenceCategory.AUTHENTICATION,
                        strength=EvidenceStrength.STRONG,
                        message=f"Router-level authentication dependency detected: {r_dep}",
                        location=dec.location or fn.location,
                        symbol=router_var,
                        endpoint_path=canonical_path,
                        endpoint_method=method,
                        handler_name=fn.name,
                        extracted_value=r_dep,
                        rationale=(
                            f"APIRouter '{router_var}' enforces security across all enclosed "
                            "endpoints."
                        ),
                    )
                )

            auth_state = (
                AuthState.AUTH_PRESENT
                if len(auth_ev) > 0
                else AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE
            )

            for m in methods_to_add:
                if m not in _HTTP_METHODS:
                    continue
                endpoints.append(
                    NormalizedSourceEndpoint(
                        method=m,
                        path=canonical_path,
                        raw_path=path_val,
                        handler_name=fn.name,
                        file_path=module.file_path,
                        framework="fastapi",
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
