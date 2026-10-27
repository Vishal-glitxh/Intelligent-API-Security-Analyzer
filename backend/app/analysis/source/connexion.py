"""Static extraction for Connexion APIs registered from OpenAPI operation IDs."""

import ast
from pathlib import PurePosixPath

from app.analysis.context import (
    AuthState,
    EvidenceCategory,
    EvidenceStrength,
    NormalizedOpenAPI,
    NormalizedSourceEndpoint,
    NormalizedSourceParameter,
    SourceLocation,
    SourceSecurityEvidence,
)
from app.analysis.source.parser import ParsedModule

_AUTH_CALLS = {
    "authenticate",
    "check_authentication",
    "jwt_required",
    "login_required",
    "require_auth",
    "token_validator",
    "validate_token",
    "verify_token",
}


def has_connexion_registration(module: ParsedModule) -> bool:
    """Recognize ``add_api`` calls whose receiver is statically a Connexion App.

    This intentionally handles only direct ``App`` construction and simple name
    assignments. Dynamic factories, attribute mutation, and control-flow-dependent
    aliases remain unsupported rather than being guessed from an import or method name.
    """
    if not isinstance(module.ast_root, ast.Module):
        return False

    def is_app_constructor(node: ast.AST, module_aliases: set[str], app_symbols: set[str]) -> bool:
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        return (isinstance(func, ast.Name) and func.id in app_symbols) or (
            isinstance(func, ast.Attribute)
            and func.attr == "App"
            and isinstance(func.value, ast.Name)
            and func.value.id in module_aliases
        )

    def assigned_names(target: ast.AST) -> set[str]:
        if isinstance(target, ast.Name):
            return {target.id}
        if isinstance(target, (ast.Tuple, ast.List)):
            return set().union(*(assigned_names(item) for item in target.elts))
        return set()

    def names_bound_in(statements: list[ast.stmt]) -> set[str]:
        """Collect names that may be rebound by a conditional suite."""
        bound: set[str] = set()
        pending: list[ast.AST] = list(statements)
        while pending:
            statement = pending.pop()
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # A nested scope cannot rebind names in its containing scope.
                bound.add(statement.name)
                continue
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets = (
                    statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                )
                for target in targets:
                    bound.update(assigned_names(target))
            elif isinstance(statement, (ast.For, ast.AsyncFor)):
                bound.update(assigned_names(statement.target))
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                for item in statement.items:
                    if item.optional_vars is not None:
                        bound.update(assigned_names(item.optional_vars))
            elif isinstance(statement, ast.ExceptHandler) and statement.name:
                bound.add(statement.name)
            elif isinstance(statement, ast.Import):
                bound.update(alias.asname or alias.name.split(".")[0] for alias in statement.names)
            elif isinstance(statement, ast.ImportFrom):
                bound.update(alias.asname or alias.name for alias in statement.names)
            elif isinstance(statement, ast.Delete):
                for target in statement.targets:
                    bound.update(assigned_names(target))
            pending.extend(ast.iter_child_nodes(statement))
        return bound

    def inspect_scope(
        statements: list[ast.stmt],
        inherited: set[str],
        inherited_modules: set[str],
        inherited_symbols: set[str],
        shadowed_names: set[str] | None = None,
    ) -> bool:
        shadowed = shadowed_names or set()
        app_names = set(inherited) - shadowed
        module_aliases = set(inherited_modules) - shadowed
        app_symbols = set(inherited_symbols) - shadowed
        for statement in statements:
            # Analyze function bodies with the aliases currently visible in the
            # enclosing scope. Class bodies are not treated as application setup.
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                arguments = statement.args
                parameters = {
                    argument.arg
                    for argument in (
                        *arguments.posonlyargs,
                        *arguments.args,
                        *arguments.kwonlyargs,
                    )
                }
                if arguments.vararg:
                    parameters.add(arguments.vararg.arg)
                if arguments.kwarg:
                    parameters.add(arguments.kwarg.arg)
                if inspect_scope(
                    statement.body,
                    app_names,
                    module_aliases,
                    app_symbols,
                    parameters,
                ):
                    return True
                continue

            if isinstance(statement, ast.Import):
                for imported in statement.names:
                    if imported.name == "connexion":
                        module_aliases.add(imported.asname or "connexion")
            elif isinstance(statement, ast.ImportFrom) and statement.module == "connexion":
                for imported in statement.names:
                    if imported.name == "App":
                        app_symbols.add(imported.asname or imported.name)

            assignments: list[tuple[set[str], ast.AST | None]] = []
            if isinstance(statement, ast.Assign):
                assignments.extend(
                    (assigned_names(target), statement.value) for target in statement.targets
                )
            elif isinstance(statement, ast.AnnAssign):
                assignments.append((assigned_names(statement.target), statement.value))
            elif isinstance(statement, ast.NamedExpr):
                assignments.append((assigned_names(statement.target), statement.value))

            for names, value in assignments:
                inherited_alias = isinstance(value, ast.Name) and value.id in app_names
                for name in names:
                    app_names.discard(name)
                    module_aliases.discard(name)
                    app_symbols.discard(name)
                    if (
                        value is not None and is_app_constructor(value, module_aliases, app_symbols)
                    ) or inherited_alias:
                        app_names.add(name)

            # Inspect calls in this statement's expressions, but do not walk into
            # nested suites where assignments have a separate static scope.
            pending = list(ast.iter_child_nodes(statement))
            while pending:
                node = pending.pop()
                if isinstance(node, ast.stmt):
                    continue
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == "add_api":
                        receiver = node.func.value
                        if isinstance(receiver, ast.Name) and receiver.id in app_names:
                            return True
                        if is_app_constructor(receiver, module_aliases, app_symbols):
                            return True
                pending.extend(ast.iter_child_nodes(node))

            if isinstance(statement, ast.If):
                conditional = statement
                if inspect_scope(
                    conditional.body, app_names, module_aliases, app_symbols
                ) or inspect_scope(conditional.orelse, app_names, module_aliases, app_symbols):
                    return True
                rebound = names_bound_in([*conditional.body, *conditional.orelse])
                app_names.difference_update(rebound)
                module_aliases.difference_update(rebound)
                app_symbols.difference_update(rebound)
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                if inspect_scope(
                    statement.body, app_names, module_aliases, app_symbols
                ) or inspect_scope(statement.orelse, app_names, module_aliases, app_symbols):
                    return True
                rebound = names_bound_in([*statement.body, *statement.orelse])
                if isinstance(statement, (ast.For, ast.AsyncFor)):
                    rebound.update(assigned_names(statement.target))
                app_names.difference_update(rebound)
                module_aliases.difference_update(rebound)
                app_symbols.difference_update(rebound)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                if inspect_scope(statement.body, app_names, module_aliases, app_symbols):
                    return True
                rebound = names_bound_in(statement.body)
                for item in statement.items:
                    if item.optional_vars is not None:
                        rebound.update(assigned_names(item.optional_vars))
                app_names.difference_update(rebound)
                module_aliases.difference_update(rebound)
                app_symbols.difference_update(rebound)
            elif isinstance(statement, ast.Try):
                try_statement = statement
                suites = [try_statement.body, try_statement.orelse, try_statement.finalbody]
                suites.extend(handler.body for handler in try_statement.handlers)
                if any(
                    inspect_scope(suite, app_names, module_aliases, app_symbols) for suite in suites
                ):
                    return True
                rebound = names_bound_in([stmt for suite in suites for stmt in suite])
                rebound.update(handler.name for handler in try_statement.handlers if handler.name)
                app_names.difference_update(rebound)
                module_aliases.difference_update(rebound)
                app_symbols.difference_update(rebound)
        return False

    return inspect_scope(module.ast_root.body, set(), set(), set())


def _operation_module_path(operation_id: str) -> tuple[str, str] | None:
    parts = operation_id.split(".")
    if len(parts) < 2 or any(not part.isidentifier() for part in parts):
        return None
    module = PurePosixPath(*parts[:-1]).with_suffix(".py").as_posix()
    return module, parts[-1]


def _extract_authentication_evidence(
    module: ParsedModule,
    handler_name: str,
) -> tuple[SourceSecurityEvidence, ...]:
    handler = next(
        (function for function in module.functions if function.name == handler_name), None
    )
    if handler is None:
        return ()

    evidence: list[SourceSecurityEvidence] = []
    for node in ast.walk(handler.node):
        if isinstance(node, ast.Call):
            call_name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else (node.func.attr if isinstance(node.func, ast.Attribute) else "")
            )
            if call_name.lower() not in _AUTH_CALLS:
                continue
            location = SourceLocation(
                file=module.file_path,
                line=getattr(node, "lineno", None),
                column=getattr(node, "col_offset", 0) + 1,
                end_line=getattr(node, "end_lineno", None),
                end_column=getattr(node, "end_col_offset", None),
            )
            evidence.append(
                SourceSecurityEvidence(
                    category=EvidenceCategory.AUTHENTICATION,
                    strength=EvidenceStrength.MEDIUM,
                    message=f"Recognized authentication helper call: {call_name}().",
                    location=location,
                    symbol=call_name,
                    handler_name=handler_name,
                    extracted_value=ast.unparse(node),
                    rationale=(
                        "A known authentication helper is called in the route handler; "
                        "static analysis cannot determine whether its result is enforced correctly."
                    ),
                )
            )
    return tuple(evidence)


def extract_connexion_endpoints(
    module: ParsedModule,
    specification: NormalizedOpenAPI,
) -> list[NormalizedSourceEndpoint]:
    """Map explicitly dotted OpenAPI operation IDs to source functions without execution."""
    if module.ast_root is None:
        return []

    functions = {function.name: function for function in module.functions}
    endpoints: list[NormalizedSourceEndpoint] = []

    for normalized_endpoint in specification.endpoints:
        for operation in normalized_endpoint.operations:
            operation_id = operation.operation_id
            if not operation_id:
                continue
            module_path = _operation_module_path(operation_id)
            if module_path is None:
                continue
            expected_path, handler_name = module_path
            # Operation IDs resolve from the source root. Suffix matching could
            # bind the same ID to an unrelated nested package with a matching tail.
            if PurePosixPath(module.file_path).as_posix() != expected_path:
                continue
            handler = functions.get(handler_name)
            if handler is None:
                continue

            auth_evidence = _extract_authentication_evidence(module, handler_name)
            auth_state = (
                AuthState.AUTH_PRESENT
                if auth_evidence
                else AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE
            )
            parameters = tuple(
                NormalizedSourceParameter(
                    name=parameter.name,
                    param_type=parameter.annotation,
                    is_path_param=("{" + parameter.name + "}") in operation.path,
                    location=parameter.location,
                )
                for parameter in handler.parameters
            )
            endpoints.append(
                NormalizedSourceEndpoint(
                    method=operation.method.lower(),
                    path=operation.path,
                    raw_path=operation.path,
                    handler_name=handler_name,
                    file_path=module.file_path,
                    framework="connexion",
                    location=handler.location,
                    parameters=parameters,
                    auth_state=auth_state,
                    auth_evidence=auth_evidence,
                )
            )

    return endpoints
