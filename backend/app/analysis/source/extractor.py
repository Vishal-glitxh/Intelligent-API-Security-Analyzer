import ast

from app.analysis.context import (
    EvidenceCategory,
    EvidenceStrength,
    SourceLocation,
    SourceSecurityEvidence,
)
from app.analysis.source.parser import ParsedFunction

_AUTHZ_CALL_NAMES = {
    "require_role",
    "require_permission",
    "check_permission",
    "has_permission",
    "authorize",
    "can_access",
    "verify_ownership",
    "enforce_tenant",
}

_ROLE_ATTR_NAMES = {"role", "roles", "is_admin", "is_superuser", "permissions", "scopes"}
_TENANT_ATTR_NAMES = {"tenant_id", "organization_id", "org_id", "account_id"}
_LOOKUP_CALL_NAMES = {"get", "filter", "filter_by", "get_by_id", "find_by_id", "find_one"}


def _ast_to_source_location(file_path: str, node: ast.AST) -> SourceLocation:
    col = getattr(node, "col_offset", None)
    end_col = getattr(node, "end_col_offset", None)
    return SourceLocation(
        file=file_path,
        line=getattr(node, "lineno", None),
        column=(col + 1) if col is not None else None,
        end_line=getattr(node, "end_lineno", None),
        end_column=(end_col + 1) if end_col is not None else None,
    )


def extract_function_security_evidence(
    fn: ParsedFunction,
    file_path: str,
    path_parameters: tuple[str, ...],
) -> tuple[
    list[SourceSecurityEvidence],  # authz
    list[SourceSecurityEvidence],  # object_access
    list[SourceSecurityEvidence],  # tenant
    list[SourceSecurityEvidence],  # validation
    list[SourceSecurityEvidence],  # database
]:
    """Inspects AST statements within a function body for authorization, object lookup,

    tenant isolation, validation, and database access evidence.
    """
    authz_ev: list[SourceSecurityEvidence] = []
    object_ev: list[SourceSecurityEvidence] = []
    tenant_ev: list[SourceSecurityEvidence] = []
    val_ev: list[SourceSecurityEvidence] = []
    db_ev: list[SourceSecurityEvidence] = []

    for node in ast.walk(fn.node):
        # 1. Calls: check for authz helpers, object lookups, tenant filtering, raw SQL
        if isinstance(node, ast.Call):
            call_str = ast.unparse(node)
            loc = _ast_to_source_location(file_path, node)

            # Check authorization helper call
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in _AUTHZ_CALL_NAMES:
                authz_ev.append(
                    SourceSecurityEvidence(
                        category=EvidenceCategory.AUTHORIZATION,
                        strength=EvidenceStrength.STRONG,
                        message=f"Authorization helper call detected: {func_name}()",
                        location=loc,
                        symbol=func_name,
                        handler_name=fn.name,
                        extracted_value=call_str,
                        rationale=(
                            "Explicit access-control or permission check executed before returning "
                            "resource."
                        ),
                    )
                )

            # Check tenant-scoped filter query: .filter(Model.tenant_id == ...)
            if any(t in call_str for t in _TENANT_ATTR_NAMES) and func_name in (
                "filter",
                "filter_by",
            ):
                tenant_ev.append(
                    SourceSecurityEvidence(
                        category=EvidenceCategory.TENANT_ISOLATION,
                        strength=EvidenceStrength.STRONG,
                        message=f"Tenant-scoped database query detected: {call_str}",
                        location=loc,
                        symbol=func_name,
                        handler_name=fn.name,
                        extracted_value=call_str,
                        rationale=(
                            "Database query explicitly constrains results by tenant or "
                            "organization identifier."
                        ),
                    )
                )

            # Check object-level resource lookup using path parameter
            if func_name in _LOOKUP_CALL_NAMES:
                for param in path_parameters:
                    # Check if param identifier appears in arguments of lookup call
                    arg_str = " ".join(ast.unparse(a) for a in node.args)
                    kw_str = " ".join(f"{kw.arg}={ast.unparse(kw.value)}" for kw in node.keywords)
                    if param in arg_str or param in kw_str:
                        object_ev.append(
                            SourceSecurityEvidence(
                                category=EvidenceCategory.OBJECT_ACCESS,
                                strength=EvidenceStrength.STRONG,
                                message=(
                                    f"Object identifier '{param}' used in "
                                    f"resource lookup: {call_str}"
                                ),
                                location=loc,
                                symbol=param,
                                handler_name=fn.name,
                                extracted_value=call_str,
                                rationale=(
                                    "User-controlled path parameter directly queries object "
                                    "from data store."
                                ),
                            )
                        )

            # Check raw SQL string concatenation
            if func_name in ("execute", "raw", "text"):
                for arg in node.args:
                    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                        arg_unparse = ast.unparse(arg)
                        if any(
                            sql_kw in arg_unparse.upper()
                            for sql_kw in ("SELECT", "UPDATE", "DELETE", "INSERT")
                        ):
                            db_ev.append(
                                SourceSecurityEvidence(
                                    category=EvidenceCategory.DATABASE_ACCESS,
                                    strength=EvidenceStrength.MEDIUM,
                                    message=(
                                        f"Potential unparameterized SQL concatenation in "
                                        f"{func_name}(): {arg_unparse}"
                                    ),
                                    location=loc,
                                    symbol=func_name,
                                    handler_name=fn.name,
                                    extracted_value=arg_unparse,
                                    rationale=(
                                        "Dynamic string concatenation detected in SQL "
                                        "execution call."
                                    ),
                                )
                            )
                    elif isinstance(arg, ast.JoinedStr):
                        arg_unparse = ast.unparse(arg)
                        if any(
                            sql_kw in arg_unparse.upper()
                            for sql_kw in ("SELECT", "UPDATE", "DELETE", "INSERT")
                        ):
                            db_ev.append(
                                SourceSecurityEvidence(
                                    category=EvidenceCategory.DATABASE_ACCESS,
                                    strength=EvidenceStrength.MEDIUM,
                                    message=(
                                        f"Potential f-string SQL query construction in "
                                        f"{func_name}(): {arg_unparse}"
                                    ),
                                    location=loc,
                                    symbol=func_name,
                                    handler_name=fn.name,
                                    extracted_value=arg_unparse,
                                    rationale=(
                                        "Formatted string literal detected in SQL execution call."
                                    ),
                                )
                            )

        # 2. Comparisons: ownership check (current_user.id == obj.user_id) or role check
        elif isinstance(node, ast.Compare):
            cmp_str = ast.unparse(node)
            loc = _ast_to_source_location(file_path, node)

            # Check role comparison: user.role == "admin"
            if any(r in cmp_str for r in _ROLE_ATTR_NAMES):
                authz_ev.append(
                    SourceSecurityEvidence(
                        category=EvidenceCategory.AUTHORIZATION,
                        strength=EvidenceStrength.STRONG,
                        message=f"Role or permission check detected in conditional: {cmp_str}",
                        location=loc,
                        symbol="role_check",
                        handler_name=fn.name,
                        extracted_value=cmp_str,
                        rationale=(
                            "Conditional statement verifies user role or permission attribute."
                        ),
                    )
                )

            # Check ownership comparison: current_user.id == resource.owner_id
            is_ownership = any(
                k in cmp_str
                for k in (
                    "current_user",
                    "user.id",
                    "caller_id",
                    "owner_id",
                    "creator_id",
                    "user_id",
                )
            ) and any(op_sym in cmp_str for op_sym in ("==", "!="))
            if is_ownership and not any(r in cmp_str for r in _ROLE_ATTR_NAMES):
                authz_ev.append(
                    SourceSecurityEvidence(
                        category=EvidenceCategory.AUTHORIZATION,
                        strength=EvidenceStrength.STRONG,
                        message=f"Ownership comparison detected: {cmp_str}",
                        location=loc,
                        symbol="ownership_check",
                        handler_name=fn.name,
                        extracted_value=cmp_str,
                        rationale=(
                            "Explicit comparison between caller identity and resource owner "
                            "identifier."
                        ),
                    )
                )

            # Check tenant comparison: resource.tenant_id == current_user.tenant_id
            if any(t in cmp_str for t in _TENANT_ATTR_NAMES):
                tenant_ev.append(
                    SourceSecurityEvidence(
                        category=EvidenceCategory.TENANT_ISOLATION,
                        strength=EvidenceStrength.STRONG,
                        message=f"Tenant ownership comparison detected: {cmp_str}",
                        location=loc,
                        symbol="tenant_check",
                        handler_name=fn.name,
                        extracted_value=cmp_str,
                        rationale=(
                            "Conditional comparison enforces tenant boundary between resource "
                            "and caller."
                        ),
                    )
                )

        # 3. Manual input validation: if not param: raise ...
        elif isinstance(node, ast.If):
            test_str = ast.unparse(node.test)
            for param in path_parameters:
                if param in test_str:
                    loc = _ast_to_source_location(file_path, node.test)
                    val_ev.append(
                        SourceSecurityEvidence(
                            category=EvidenceCategory.INPUT_VALIDATION,
                            strength=EvidenceStrength.MEDIUM,
                            message=(
                                f"Manual validation check detected on parameter "
                                f"'{param}': {test_str}"
                            ),
                            location=loc,
                            symbol=param,
                            handler_name=fn.name,
                            extracted_value=test_str,
                            rationale=(
                                "Function contains explicit conditional validation on input "
                                "parameter."
                            ),
                        )
                    )

    return authz_ev, object_ev, tenant_ev, val_ev, db_ev
