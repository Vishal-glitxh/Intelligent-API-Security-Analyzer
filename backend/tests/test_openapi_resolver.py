from typing import Any

from app.analysis.openapi.resolver import (
    RefResolutionResult,
    RefStatus,
    _unescape_json_pointer_token,
    resolve_internal_ref,
)


def test_unescape_json_pointer_token() -> None:
    assert _unescape_json_pointer_token("foo~1bar~0baz") == "foo/bar~baz"
    assert _unescape_json_pointer_token("plain") == "plain"


def test_resolve_empty_or_non_string() -> None:
    res: RefResolutionResult = resolve_internal_ref({}, "")
    assert res.status == RefStatus.UNRESOLVED_INTERNAL
    assert "Empty or non-string" in (res.error or "")


def test_resolve_external_ref() -> None:
    res = resolve_internal_ref({}, "https://example.com/schema.json#/Item")
    assert res.status == RefStatus.UNSUPPORTED_EXTERNAL
    assert "External $ref" in (res.error or "")


def test_resolve_circular_ref() -> None:
    visited = frozenset(["#/components/schemas/A"])
    res = resolve_internal_ref({}, "#/components/schemas/A", visited=visited)
    assert res.status == RefStatus.CIRCULAR
    assert "Circular reference" in (res.error or "")


def test_resolve_root_pointer() -> None:
    spec = {"openapi": "3.0.3"}
    res = resolve_internal_ref(spec, "#/")
    assert res.status == RefStatus.RESOLVED_INTERNAL
    assert res.resolved_data == spec


def test_resolve_array_indices() -> None:
    spec: dict[str, Any] = {
        "items": [
            {"id": "first"},
            {"id": "second"},
        ]
    }
    res = resolve_internal_ref(spec, "#/items/1/id")
    assert res.status == RefStatus.RESOLVED_INTERNAL
    assert res.resolved_data == {"_value": "second"}

    # Out of range
    res_oor = resolve_internal_ref(spec, "#/items/5")
    assert res_oor.status == RefStatus.UNRESOLVED_INTERNAL
    assert "out of range" in (res_oor.error or "")

    # Invalid int
    res_inv = resolve_internal_ref(spec, "#/items/notanumber")
    assert res_inv.status == RefStatus.UNRESOLVED_INTERNAL
    assert "Invalid list index" in (res_inv.error or "")

    # Non-container
    res_nc = resolve_internal_ref(spec, "#/items/0/id/extra")
    assert res_nc.status == RefStatus.UNRESOLVED_INTERNAL
    assert "Encountered non-container" in (res_nc.error or "")


def test_resolve_chained_ref() -> None:
    spec: dict[str, Any] = {
        "components": {
            "schemas": {
                "A": {"type": "string"},
                "B": {"$ref": "#/components/schemas/A"},
            }
        }
    }
    res = resolve_internal_ref(spec, "#/components/schemas/B")
    assert res.status == RefStatus.RESOLVED_INTERNAL
    assert res.resolved_data == {"type": "string"}
