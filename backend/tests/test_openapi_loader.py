from pathlib import Path

import pytest
from app.analysis.openapi.loader import (
    LoadedSpec,
    SpecParsingError,
    load_openapi_spec,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "openapi"


def test_load_valid_yaml() -> None:
    yaml_path = FIXTURES_DIR / "valid_v30.yaml"
    content = yaml_path.read_text(encoding="utf-8")
    loaded = load_openapi_spec(content, file_path=str(yaml_path))

    assert isinstance(loaded, LoadedSpec)
    assert loaded.raw_data["openapi"] == "3.0.3"
    assert loaded.raw_data["info"]["title"] == "Sample Valid 3.0 API"
    assert len(loaded.spec_hash) == 64
    assert "" in loaded.location_map
    assert "/info/title" in loaded.location_map

    title_loc = loaded.location_map["/info/title"]
    assert title_loc.line is not None
    assert title_loc.line >= 1
    assert title_loc.column is not None


def test_load_valid_json() -> None:
    json_path = FIXTURES_DIR / "valid_v31.json"
    content = json_path.read_text(encoding="utf-8")
    loaded = load_openapi_spec(content, file_path=str(json_path))

    assert isinstance(loaded, LoadedSpec)
    assert loaded.raw_data["openapi"] == "3.1.0"
    assert loaded.raw_data["info"]["title"] == "Sample Valid 3.1 JSON API"
    assert len(loaded.spec_hash) == 64


def test_load_rejects_empty_content() -> None:
    with pytest.raises(SpecParsingError, match="Specification content is empty"):
        load_openapi_spec("")

    with pytest.raises(SpecParsingError, match="Specification content is empty"):
        load_openapi_spec("   \n\t  ")


def test_load_rejects_excessive_size() -> None:
    small_limit = 20
    with pytest.raises(SpecParsingError, match="exceeds the maximum limit"):
        load_openapi_spec(
            "openapi: 3.0.3\ninfo:\n  title: Excessive Size Test",
            max_size_bytes=small_limit,
        )


def test_load_rejects_invalid_yaml_syntax() -> None:
    malformed_yaml = "openapi: 3.0.3\n  invalid_indent: [unclosed_list"
    with pytest.raises(SpecParsingError, match="Failed to parse OpenAPI document"):
        load_openapi_spec(malformed_yaml)


def test_load_rejects_non_mapping_root() -> None:
    with pytest.raises(SpecParsingError, match="OpenAPI root must be an object/mapping"):
        load_openapi_spec("- item1\n- item2\n")
