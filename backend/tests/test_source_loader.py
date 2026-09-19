from pathlib import Path

import pytest
from app.analysis.source.loader import (
    SourceLoadingError,
    load_source_from_disk,
    load_source_from_memory,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "source"


def test_load_source_from_disk_success() -> None:
    loaded = load_source_from_disk(FIXTURES_DIR)
    assert len(loaded.files) >= 4
    assert len(loaded.tree_hash) == 64

    paths = [f.relative_path for f in loaded.files]
    assert "fastapi_vulnerable.py" in paths
    assert "fastapi_secure.py" in paths
    assert "flask_sample.py" in paths


def test_load_source_from_memory_success() -> None:
    files = {
        "main.py": "print('hello')",
        "utils.py": "def add(a, b): return a + b",
    }
    loaded = load_source_from_memory(files)
    assert len(loaded.files) == 2
    assert loaded.files[0].relative_path == "main.py"
    assert loaded.files[1].relative_path == "utils.py"
    assert len(loaded.tree_hash) == 64


def test_load_source_rejects_excessive_file_count() -> None:
    files = {f"file_{i}.py": "x = 1" for i in range(10)}
    with pytest.raises(SourceLoadingError, match="exceeds maximum allowed"):
        load_source_from_memory(files, max_file_count=5)


def test_load_source_rejects_excessive_aggregate_size() -> None:
    files = {
        "big1.py": "x = '" + ("a" * 100) + "'",
        "big2.py": "y = '" + ("b" * 100) + "'",
    }
    with pytest.raises(SourceLoadingError, match="exceeds limit"):
        load_source_from_memory(files, max_total_size=50)


def test_load_source_skips_excessive_single_file_size() -> None:
    files = {
        "normal.py": "x = 1",
        "giant.py": "x = 'long text string'",
    }
    loaded = load_source_from_memory(files, max_file_size=10)
    assert len(loaded.files) == 1
    assert loaded.files[0].relative_path == "normal.py"
    assert len(loaded.diagnostics) == 1
    assert "exceeds maximum limit" in loaded.diagnostics[0].message


def test_load_source_from_disk_nonexistent_dir() -> None:
    with pytest.raises(SourceLoadingError, match="does not exist"):
        load_source_from_disk("/non/existent/directory/path/12345")
