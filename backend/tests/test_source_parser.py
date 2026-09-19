import os
from pathlib import Path

from app.analysis.source.parser import _get_tree_sitter_parser, parse_source_file

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "source"


def test_parser_extracts_functions_and_classes() -> None:
    code = """
import os
from fastapi import Depends

class ItemService:
    def process(self, item_id: str) -> bool:
        return True

def standalone_func(x: int = 10) -> int:
    return x * 2
"""
    mod = parse_source_file(code, "sample.py", "hash123")
    assert mod.has_syntax_error is False
    assert len(mod.diagnostics) == 0
    assert "os" in mod.imports
    assert "Depends" in mod.imported_symbols
    assert len(mod.classes) == 1
    assert mod.classes[0].name == "ItemService"
    assert len(mod.functions) == 2


def test_parser_resilience_on_syntax_error() -> None:
    malformed_path = FIXTURES_DIR / "malformed.py"
    code = malformed_path.read_text(encoding="utf-8")
    mod = parse_source_file(code, str(malformed_path), "badhash")

    assert mod.has_syntax_error is True
    assert mod.ast_root is None
    assert len(mod.diagnostics) == 1
    assert "Python syntax error" in mod.diagnostics[0].message
    assert mod.diagnostics[0].line is not None


def test_tree_sitter_parser_initialized() -> None:
    ts_parser = _get_tree_sitter_parser()
    assert ts_parser is not None
    tree = ts_parser.parse(b"def foo(): pass\n")
    assert tree.root_node.type == "module"


def test_static_only_boundary_never_executes_target_code() -> None:
    # Ensure environment variable is not present initially
    if "STATIC_ANALYZER_TEST_EXECUTED" in os.environ:
        del os.environ["STATIC_ANALYZER_TEST_EXECUTED"]

    side_effect_path = FIXTURES_DIR / "side_effect.py"
    content = side_effect_path.read_text(encoding="utf-8")

    # Parse file statically
    mod = parse_source_file(content, str(side_effect_path), "side_hash")
    assert mod.has_syntax_error is False

    # Assert that parsing never executed the Python code
    assert "STATIC_ANALYZER_TEST_EXECUTED" not in os.environ
