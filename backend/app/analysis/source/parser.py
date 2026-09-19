import ast
from dataclasses import dataclass, field
from typing import Any

import tree_sitter_python
from tree_sitter import Language, Parser

from app.analysis.context import SourceDiagnostic, SourceLocation

# Initialize tree-sitter Python language and parser
_PY_LANGUAGE = Language(tree_sitter_python.language())


def _get_tree_sitter_parser() -> Parser:
    parser = Parser(_PY_LANGUAGE)
    return parser


@dataclass(frozen=True)
class ParsedParameter:
    name: str
    annotation: str | None = None
    default_str: str | None = None
    location: SourceLocation | None = None


@dataclass(frozen=True)
class ParsedDecorator:
    name: str  # e.g. "app.get", "router.post", "login_required"
    call_node: ast.Call | ast.Name | ast.Attribute
    args: tuple[Any, ...] = ()
    keywords: dict[str, Any] = field(default_factory=dict)
    location: SourceLocation | None = None


@dataclass(frozen=True)
class ParsedFunction:
    name: str
    is_async: bool
    decorators: tuple[ParsedDecorator, ...]
    parameters: tuple[ParsedParameter, ...]
    return_annotation: str | None
    node: ast.FunctionDef | ast.AsyncFunctionDef
    location: SourceLocation


@dataclass(frozen=True)
class ParsedClass:
    name: str
    bases: tuple[str, ...]
    methods: tuple[ParsedFunction, ...]
    location: SourceLocation


@dataclass(frozen=True)
class ParsedAssignment:
    target_name: str
    value_node: ast.AST
    value_str: str | None
    location: SourceLocation


@dataclass(frozen=True)
class ParsedModule:
    file_path: str
    content: str
    content_hash: str
    ast_root: ast.AST | None
    imports: tuple[str, ...]
    imported_symbols: dict[str, str]  # symbol -> module, e.g. {"Depends": "fastapi"}
    classes: tuple[ParsedClass, ...]
    functions: tuple[ParsedFunction, ...]
    assignments: tuple[ParsedAssignment, ...]
    diagnostics: tuple[SourceDiagnostic, ...]
    has_syntax_error: bool = False


def _ast_to_source_location(
    file_path: str,
    node: ast.AST,
) -> SourceLocation:
    col = getattr(node, "col_offset", None)
    end_col = getattr(node, "end_col_offset", None)
    return SourceLocation(
        file=file_path,
        line=getattr(node, "lineno", None),
        column=(col + 1) if col is not None else None,
        end_line=getattr(node, "end_lineno", None),
        end_column=(end_col + 1) if end_col is not None else None,
    )


def _get_node_name(node: ast.AST) -> str:
    """Extract string identifier from Name, Attribute, or Call."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_get_node_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _get_node_name(node.func)
    return ""


def _extract_decorator(dec_node: ast.AST, file_path: str) -> ParsedDecorator:
    loc = _ast_to_source_location(file_path, dec_node)
    args: list[Any] = []
    keywords: dict[str, Any] = {}

    if isinstance(dec_node, ast.Call):
        name = _get_node_name(dec_node.func)
        args = list(dec_node.args)
        keywords = {kw.arg: kw.value for kw in dec_node.keywords if kw.arg}
        return ParsedDecorator(
            name=name,
            call_node=dec_node,
            args=tuple(args),
            keywords=keywords,
            location=loc,
        )

    name = _get_node_name(dec_node)
    return ParsedDecorator(
        name=name,
        call_node=dec_node,  # type: ignore[arg-type]
        args=(),
        keywords={},
        location=loc,
    )


def parse_source_file(
    content: str,
    file_path: str,
    content_hash: str,
) -> ParsedModule:
    """Parses Python source text using ast and tree-sitter, handling syntax errors gracefully."""
    diagnostics: list[SourceDiagnostic] = []

    try:
        root_node = ast.parse(content, filename=file_path)
    except SyntaxError as exc:
        diagnostics.append(
            SourceDiagnostic(
                file_path=file_path,
                message=f"Python syntax error: {exc.msg}",
                line=exc.lineno,
                column=exc.offset,
                severity="error",
            )
        )
        return ParsedModule(
            file_path=file_path,
            content=content,
            content_hash=content_hash,
            ast_root=None,
            imports=(),
            imported_symbols={},
            classes=(),
            functions=(),
            assignments=(),
            diagnostics=tuple(diagnostics),
            has_syntax_error=True,
        )

    imports: list[str] = []
    imported_symbols: dict[str, str] = {}
    classes: list[ParsedClass] = []
    functions: list[ParsedFunction] = []
    assignments: list[ParsedAssignment] = []

    for stmt in root_node.body:
        # Imports: import x, from x import y
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                imports.append(alias.name)
                imported_symbols[alias.asname or alias.name] = alias.name
        elif isinstance(stmt, ast.ImportFrom):
            mod_name = stmt.module or ""
            imports.append(mod_name)
            for alias in stmt.names:
                imported_symbols[alias.asname or alias.name] = mod_name

        # Variable assignments: X = ...
        elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            loc = _ast_to_source_location(file_path, stmt)
            val_node = stmt.value if isinstance(stmt, ast.AnnAssign) else stmt.value
            val_str = None
            if isinstance(val_node, ast.Constant) and isinstance(val_node.value, str):
                val_str = val_node.value

            targets = [stmt.target] if isinstance(stmt, ast.AnnAssign) else stmt.targets
            for tgt in targets:
                if isinstance(tgt, ast.Name):
                    assignments.append(
                        ParsedAssignment(
                            target_name=tgt.id,
                            value_node=val_node,  # type: ignore[arg-type]
                            value_str=val_str,
                            location=loc,
                        )
                    )

        # Classes
        elif isinstance(stmt, ast.ClassDef):
            class_loc = _ast_to_source_location(file_path, stmt)
            base_names = tuple(_get_node_name(b) for b in stmt.bases)
            class_methods: list[ParsedFunction] = []

            for item in stmt.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn_loc = _ast_to_source_location(file_path, item)
                    fn_decs = tuple(_extract_decorator(d, file_path) for d in item.decorator_list)
                    fn_params: list[ParsedParameter] = []
                    for arg in item.args.args:
                        ann_str = ast.unparse(arg.annotation) if arg.annotation else None
                        fn_params.append(
                            ParsedParameter(
                                name=arg.arg,
                                annotation=ann_str,
                                location=_ast_to_source_location(file_path, arg),
                            )
                        )
                    ret_str = ast.unparse(item.returns) if item.returns else None
                    method_obj = ParsedFunction(
                        name=item.name,
                        is_async=isinstance(item, ast.AsyncFunctionDef),
                        decorators=fn_decs,
                        parameters=tuple(fn_params),
                        return_annotation=ret_str,
                        node=item,
                        location=fn_loc,
                    )
                    class_methods.append(method_obj)
                    functions.append(method_obj)

            classes.append(
                ParsedClass(
                    name=stmt.name,
                    bases=base_names,
                    methods=tuple(class_methods),
                    location=class_loc,
                )
            )

        # Top-level Functions
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn_loc = _ast_to_source_location(file_path, stmt)
            fn_decs = tuple(_extract_decorator(d, file_path) for d in stmt.decorator_list)
            fn_params = []
            for arg in stmt.args.args:
                ann_str = ast.unparse(arg.annotation) if arg.annotation else None
                fn_params.append(
                    ParsedParameter(
                        name=arg.arg,
                        annotation=ann_str,
                        location=_ast_to_source_location(file_path, arg),
                    )
                )
            ret_str = ast.unparse(stmt.returns) if stmt.returns else None
            functions.append(
                ParsedFunction(
                    name=stmt.name,
                    is_async=isinstance(stmt, ast.AsyncFunctionDef),
                    decorators=fn_decs,
                    parameters=tuple(fn_params),
                    return_annotation=ret_str,
                    node=stmt,
                    location=fn_loc,
                )
            )

    return ParsedModule(
        file_path=file_path,
        content=content,
        content_hash=content_hash,
        ast_root=root_node,
        imports=tuple(imports),
        imported_symbols=imported_symbols,
        classes=tuple(classes),
        functions=tuple(functions),
        assignments=tuple(assignments),
        diagnostics=tuple(diagnostics),
        has_syntax_error=False,
    )
