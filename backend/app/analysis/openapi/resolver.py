from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class RefStatus(StrEnum):
    RESOLVED_INTERNAL = "resolved_internal"
    UNRESOLVED_INTERNAL = "unresolved_internal"
    UNSUPPORTED_EXTERNAL = "unsupported_external"
    CIRCULAR = "circular"


@dataclass(frozen=True)
class RefResolutionResult:
    """Outcome of resolving an OpenAPI $ref pointer."""

    status: RefStatus
    ref: str
    resolved_data: dict[str, Any] | None = None
    error: str | None = None


def _unescape_json_pointer_token(token: str) -> str:
    """Decode an RFC 6901 JSON pointer token."""
    return token.replace("~1", "/").replace("~0", "~")


def resolve_internal_ref(
    spec: dict[str, Any],
    ref: str,
    visited: frozenset[str] | None = None,
) -> RefResolutionResult:
    """Resolve an internal JSON pointer $ref within the specification root.

    Explicitly distinguishes:
      - successfully resolved internal reference
      - unresolved internal reference
      - unsupported external reference
      - circular/self reference
    """
    if not isinstance(ref, str) or not ref.strip():
        return RefResolutionResult(
            status=RefStatus.UNRESOLVED_INTERNAL,
            ref=str(ref),
            error="Empty or non-string $ref provided.",
        )

    clean_ref = ref.strip()

    # External reference check
    if not clean_ref.startswith("#"):
        return RefResolutionResult(
            status=RefStatus.UNSUPPORTED_EXTERNAL,
            ref=clean_ref,
            error=f"External $ref '{clean_ref}' is unsupported in Phase 2 specification analysis.",
        )

    # Circular reference check
    current_visited = visited or frozenset()
    if clean_ref in current_visited:
        return RefResolutionResult(
            status=RefStatus.CIRCULAR,
            ref=clean_ref,
            error=f"Circular reference detected: pointer '{clean_ref}' already in resolution path.",
        )

    # Empty root pointer
    if clean_ref in ("#", "#/"):
        return RefResolutionResult(
            status=RefStatus.RESOLVED_INTERNAL,
            ref=clean_ref,
            resolved_data=spec,
        )

    # Parse pointer tokens
    pointer_path = clean_ref[2:] if clean_ref.startswith("#/") else clean_ref[1:]
    raw_tokens = pointer_path.split("/")
    tokens = [_unescape_json_pointer_token(t) for t in raw_tokens]

    curr: Any = spec
    for token in tokens:
        if isinstance(curr, dict):
            if token in curr:
                curr = curr[token]
            else:
                return RefResolutionResult(
                    status=RefStatus.UNRESOLVED_INTERNAL,
                    ref=clean_ref,
                    error=f"Cannot resolve token '{token}' in path '{clean_ref}'.",
                )
        elif isinstance(curr, list):
            try:
                idx = int(token)
                if 0 <= idx < len(curr):
                    curr = curr[idx]
                else:
                    return RefResolutionResult(
                        status=RefStatus.UNRESOLVED_INTERNAL,
                        ref=clean_ref,
                        error=f"Index {idx} out of range in path '{clean_ref}'.",
                    )
            except ValueError:
                return RefResolutionResult(
                    status=RefStatus.UNRESOLVED_INTERNAL,
                    ref=clean_ref,
                    error=f"Invalid list index '{token}' in path '{clean_ref}'.",
                )
        else:
            return RefResolutionResult(
                status=RefStatus.UNRESOLVED_INTERNAL,
                ref=clean_ref,
                error=(
                    f"Encountered non-container while resolving token '{token}' in '{clean_ref}'."
                ),
            )

    if not isinstance(curr, dict):
        # Resolved to a scalar or list
        return RefResolutionResult(
            status=RefStatus.RESOLVED_INTERNAL,
            ref=clean_ref,
            resolved_data={"_value": curr} if not isinstance(curr, dict) else curr,
        )

    # Chained reference handling (e.g. schema referencing another schema)
    if "$ref" in curr and isinstance(curr["$ref"], str):
        next_ref = curr["$ref"]
        return resolve_internal_ref(spec, next_ref, current_visited | {clean_ref})

    return RefResolutionResult(
        status=RefStatus.RESOLVED_INTERNAL,
        ref=clean_ref,
        resolved_data=curr,
    )
