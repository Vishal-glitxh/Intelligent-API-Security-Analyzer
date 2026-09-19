from pathlib import Path

import pytest
import yaml
from app.analysis.openapi.validator import (
    SpecValidationError,
    validate_openapi_spec,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "openapi"


def test_validate_valid_v30_success() -> None:
    yaml_path = FIXTURES_DIR / "valid_v30.yaml"
    spec_dict = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    result = validate_openapi_spec(spec_dict)
    assert result.is_valid is True
    assert result.openapi_version == "3.0.3"


def test_validate_valid_v31_success() -> None:
    json_path = FIXTURES_DIR / "valid_v31.json"
    spec_dict = yaml.safe_load(json_path.read_text(encoding="utf-8"))
    result = validate_openapi_spec(spec_dict)
    assert result.is_valid is True
    assert result.openapi_version == "3.1.0"


def test_validate_rejects_missing_version() -> None:
    spec_dict = {"info": {"title": "Missing Version", "version": "1.0"}}
    with pytest.raises(SpecValidationError, match="Missing or invalid 'openapi' version"):
        validate_openapi_spec(spec_dict)


def test_validate_rejects_unsupported_version() -> None:
    spec_dict = {"openapi": "2.0", "info": {"title": "Swagger 2.0", "version": "1.0"}}
    with pytest.raises(SpecValidationError, match="Unsupported OpenAPI version '2.0'"):
        validate_openapi_spec(spec_dict)


def test_validate_rejects_schema_violation() -> None:
    # Missing required 'paths' element
    spec_dict = {"openapi": "3.0.3", "info": {"title": "No paths", "version": "1.0"}}
    with pytest.raises(SpecValidationError, match="validation failed"):
        validate_openapi_spec(spec_dict)
