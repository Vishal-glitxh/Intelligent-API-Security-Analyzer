from dataclasses import dataclass
from typing import Any

from openapi_spec_validator import validate
from openapi_spec_validator.validation.exceptions import OpenAPIValidationError

from app.core.exceptions import InvalidInputError


class SpecValidationError(InvalidInputError):
    """Raised when an OpenAPI specification violates schema or semantic requirements."""

    def __init__(self, message: str, details: list[str] | None = None) -> None:
        super().__init__(message)
        self.details = details or []


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of OpenAPI specification validation."""

    is_valid: bool
    openapi_version: str
    errors: tuple[str, ...] = ()


def validate_openapi_spec(spec_data: dict[str, Any]) -> ValidationResult:
    """Validate an OpenAPI specification dictionary against 3.0.x or 3.1.x schemas.

    Raises SpecValidationError if validation fails, or returns ValidationResult.
    """
    if not isinstance(spec_data, dict):
        raise SpecValidationError("Specification must be a JSON/YAML object.")

    version = spec_data.get("openapi")
    if not version or not isinstance(version, str):
        raise SpecValidationError(
            "Missing or invalid 'openapi' version field in specification root."
        )

    version_str = str(version).strip()
    if not (version_str.startswith("3.0") or version_str.startswith("3.1")):
        raise SpecValidationError(
            f"Unsupported OpenAPI version '{version_str}'. Supported versions: 3.0.x, 3.1.x."
        )

    try:
        validate(spec_data)
        return ValidationResult(is_valid=True, openapi_version=version_str)
    except OpenAPIValidationError as exc:
        err_msg = str(exc.message) if hasattr(exc, "message") else str(exc)
        path_str = (
            "/".join(str(p) for p in exc.absolute_path)
            if hasattr(exc, "absolute_path") and exc.absolute_path
            else "root"
        )
        detail = f"Validation error at '#/{path_str}': {err_msg}"
        raise SpecValidationError(
            f"OpenAPI {version_str} validation failed: {detail}",
            details=[detail],
        ) from exc
    except Exception as exc:
        raise SpecValidationError(f"Unexpected specification validation error: {exc}") from exc
