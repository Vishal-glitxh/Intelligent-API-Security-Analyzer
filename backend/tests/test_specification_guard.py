import json
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from app.schemas.worker import AnalysisWorkerInput
from app.services.analysis_worker import execute_analysis_worker
from app.services.specification_guard import (
    _MAX_DOCUMENT_BYTES,
    _MAX_YAML_ALIASES,
    _MAX_YAML_DEPTH,
    _MAX_YAML_NODES,
    SpecificationGuardError,
    guard_specification_references,
)

FIXTURES = Path(__file__).parent / "fixtures" / "openapi"
REFERENCE_ERROR = "OPENAPI_PARSING_ERROR: Only valid in-document references are supported."


def _spec_with_reference(reference: object, keyword: str = "$ref") -> str:
    return json.dumps(
        {
            "openapi": "3.0.3",
            "info": {"title": "Reference guard test", "version": "1.0"},
            "paths": {"/items": {"get": {"responses": {"200": {keyword: reference}}}}},
            "components": {"responses": {"OK": {"description": "Success"}}},
        }
    )


@pytest.mark.parametrize(
    "reference",
    [
        "http://127.0.0.1/private?token=review-secret",
        "https://example.invalid/schema.json#/Response",
        "file:///private/review-secret.yaml",
        "../review-secret.yaml#/Response",
        "schema.json#/Response",
        "/private/review-secret.yaml",
        "//example.invalid/schema.json",
        "https://example.invalid#",
        "?token=review-secret#/Response",
        r"C:\private\review-secret.yaml",
        "data:application/json,{}",
        "%23/components/responses/OK",
        " #/components/responses/OK",
        "\n#/components/responses/OK",
        "#/components/responses/OK\t",
        "",
        None,
        123,
        {"$ref": "#/components/responses/OK"},
        ["#/components/responses/OK"],
        "#/bad~escape",
        "#/bad%escape",
        "#/%FF",
        "#not/an/anchor",
    ],
)
def test_rejected_reference_never_reaches_retrieval(reference: object, tmp_path: Path) -> None:
    worker_input = AnalysisWorkerInput("guard-test", _spec_with_reference(reference), str(tmp_path))
    with (
        patch("app.services.analysis_worker.load_openapi_spec") as loader,
        patch("app.services.analysis_worker.validate_openapi_spec") as validator,
        patch("requests.sessions.Session.request") as request,
        patch("urllib.request.OpenerDirector.open") as url_open,
        patch("builtins.open") as file_open,
    ):
        result = execute_analysis_worker(worker_input)

    assert result.result is None
    assert result.error_message == REFERENCE_ERROR
    loader.assert_not_called()
    validator.assert_not_called()
    request.assert_not_called()
    url_open.assert_not_called()
    file_open.assert_not_called()


@pytest.mark.parametrize("keyword", ["$ref", "$dynamicRef", "$recursiveRef"])
@pytest.mark.parametrize("as_yaml", [False, True])
def test_nested_reference_keywords_in_arrays_are_checked(keyword: str, as_yaml: bool) -> None:
    document = {"components": {"schemas": {"Item": {"allOf": [{keyword: "other.json"}]}}}}
    content = yaml.safe_dump(document) if as_yaml else json.dumps(document)
    with pytest.raises(SpecificationGuardError, match="Only valid in-document"):
        guard_specification_references(content)


@pytest.mark.parametrize(
    "content",
    [
        "reference: &ref https://example.invalid/private\nnested: {$ref: *ref}",
        "template: &ref {$ref: 'other.yaml'}\nnested: [*ref, *ref]",
        "template: &ref {$ref: 'other.yaml'}\nnested: {<<: *ref}",
        "key: &key '$ref'\nnested: {*key: 'file:///private/secret'}",
    ],
)
def test_aliases_and_merge_keys_cannot_hide_external_references(content: str) -> None:
    expected = "YAML merge keys are unsupported" if "<<:" in content else "Only valid in-document"
    with pytest.raises(SpecificationGuardError, match=expected):
        guard_specification_references(content)


@pytest.mark.parametrize("content", ["node: &node {child: *node}", "node: &node [*node]"])
def test_cyclic_aliases_are_rejected_before_frozen_location_walker(content: str) -> None:
    with patch("app.services.analysis_worker.load_openapi_spec") as loader:
        result = execute_analysis_worker(AnalysisWorkerInput("cycle-test", content, "."))
    assert result.error_message == "OPENAPI_PARSING_ERROR: Cyclic YAML aliases are unsupported."
    loader.assert_not_called()


def test_shared_noncyclic_aliases_are_allowed() -> None:
    guard_specification_references(
        "template: &ref {$ref: '#/components/schemas/Item'}\nnested: [*ref, *ref]"
    )


def test_alias_references_within_budget_remain_supported() -> None:
    aliases = "\n".join("  - *shared" for _ in range(_MAX_YAML_ALIASES))
    document = f"template: &shared {{value: safe}}\nreferences:\n{aliases}\n"
    guard_specification_references(document)


def test_node_limit_is_enforced_during_composition() -> None:
    values = ",".join("x" for _ in range(_MAX_YAML_NODES))
    document = f"openapi: '3.0.3'\nvalues: [{values}]"
    with patch(
        "app.services.specification_guard._BoundedSafeLoader.construct_document"
    ) as construct:
        with pytest.raises(SpecificationGuardError) as error:
            guard_specification_references(document)
    assert str(error.value) == "OPENAPI_PARSING_ERROR: YAML exceeds supported complexity limits."
    construct.assert_not_called()


def test_nesting_depth_limit_is_enforced_during_composition() -> None:
    document = (
        "\n".join(f"{'  ' * depth}child:" for depth in range(_MAX_YAML_DEPTH))
        + f"\n{'  ' * _MAX_YAML_DEPTH}leaf: value"
    )
    with patch(
        "app.services.specification_guard._BoundedSafeLoader.construct_document"
    ) as construct:
        with pytest.raises(SpecificationGuardError) as error:
            guard_specification_references(document)
    assert str(error.value) == "OPENAPI_PARSING_ERROR: YAML exceeds supported complexity limits."
    construct.assert_not_called()


def test_alias_limit_is_enforced_during_composition() -> None:
    aliases = ",".join("*shared" for _ in range(_MAX_YAML_ALIASES + 1))
    document = f"template: &shared {{value: safe}}\nreferences: [{aliases}]"
    with patch(
        "app.services.specification_guard._BoundedSafeLoader.construct_document"
    ) as construct:
        with pytest.raises(SpecificationGuardError) as error:
            guard_specification_references(document)
    assert str(error.value) == "OPENAPI_PARSING_ERROR: YAML exceeds supported complexity limits."
    construct.assert_not_called()


def test_merge_expansion_pattern_is_rejected_before_flattening() -> None:
    lines = ["base: &base {value: safe}"]
    previous = "base"
    for index in range(32):
        current = f"merge_{index}"
        lines.append(f"{current}: &{current} {{<<: [*{previous}, *{previous}]}}")
        previous = current

    from yaml.constructor import SafeConstructor

    original_flatten = SafeConstructor.flatten_mapping
    merged_nodes: list[yaml.nodes.MappingNode] = []

    def track_merge_expansion(loader: SafeConstructor, node: yaml.nodes.MappingNode) -> None:
        if any(key.tag == "tag:yaml.org,2002:merge" for key, _ in node.value):
            merged_nodes.append(node)
        original_flatten(loader, node)

    with patch.object(SafeConstructor, "flatten_mapping", track_merge_expansion):
        with pytest.raises(SpecificationGuardError) as error:
            guard_specification_references("\n".join(lines))

    assert str(error.value) == "OPENAPI_PARSING_ERROR: YAML merge keys are unsupported."
    # The override rejects the key before SafeConstructor can expand it.
    assert merged_nodes == []


@pytest.mark.parametrize(
    "reference",
    ["#", "#/", "#/components/responses/OK", "#/a~1b/~0key", "#/%24defs/Item", "#Item"],
)
def test_internal_pointers_and_schema_anchors_are_allowed(reference: str) -> None:
    guard_specification_references(_spec_with_reference(reference))


@pytest.mark.parametrize(
    "content",
    [
        "secret: [https://example.invalid/private?token=review-secret",
        "!!python/object/apply:os.system ['echo review-secret']",
        "- review-secret",
        "",
        "\ud800",
    ],
)
def test_malformed_input_errors_do_not_echo_document(content: str) -> None:
    result = execute_analysis_worker(AnalysisWorkerInput("malformed-test", content, "."))
    assert result.error_message in {
        "OPENAPI_PARSING_ERROR: Invalid specification document.",
        "OPENAPI_PARSING_ERROR: Specification must be an object.",
    }


def test_size_limit_precedes_yaml_parsing() -> None:
    with patch("app.services.specification_guard.yaml.load") as loader:
        with pytest.raises(SpecificationGuardError, match="Specification is too large"):
            guard_specification_references("x" * (_MAX_DOCUMENT_BYTES + 1))
    loader.assert_not_called()


def test_malformed_input_near_size_limit_has_stable_sanitized_error(tmp_path: Path) -> None:
    prefix = "openapi: '3.0.3'\n#"
    malformed_tail = "\n[unterminated"
    padding_bytes = _MAX_DOCUMENT_BYTES - len(prefix.encode()) - len(malformed_tail.encode())
    content = prefix + ("x" * padding_bytes) + malformed_tail
    assert len(content.encode("utf-8")) == _MAX_DOCUMENT_BYTES

    outputs = [
        execute_analysis_worker(AnalysisWorkerInput("near-limit", content, str(tmp_path)))
        for _ in range(2)
    ]
    assert [output.error_message for output in outputs] == [
        "OPENAPI_PARSING_ERROR: Invalid specification document.",
        "OPENAPI_PARSING_ERROR: Invalid specification document.",
    ]
    assert "x" * 32 not in (outputs[0].error_message or "")


@pytest.mark.parametrize(
    "filename", ["valid_v30.yaml", "valid_v31.json", "secure_spec.yaml", "vulnerable_spec.yaml"]
)
def test_existing_fixture_worker_results_are_preserved(filename: str, tmp_path: Path) -> None:
    worker_input = AnalysisWorkerInput(
        "fixture-test", (FIXTURES / filename).read_text(), str(tmp_path)
    )
    with patch("app.services.analysis_worker.guard_specification_references"):
        original = execute_analysis_worker(worker_input)
    with patch("requests.sessions.Session.request") as request:
        guarded = execute_analysis_worker(worker_input)
    # secure_spec.yaml is a rule fixture with an undeclared path parameter; retain its
    # existing validator rejection rather than changing a frozen fixture for this guard.
    if filename != "secure_spec.yaml":
        assert original.error_message is None
    assert guarded.error_message == original.error_message
    assert guarded.result == original.result
    request.assert_not_called()


def test_internal_reference_is_validated_and_analyzed_without_retrieval(tmp_path: Path) -> None:
    with (
        patch("requests.sessions.Session.request") as request,
        patch("urllib.request.OpenerDirector.open") as url_open,
    ):
        result = execute_analysis_worker(
            AnalysisWorkerInput(
                "internal-test", _spec_with_reference("#/components/responses/OK"), str(tmp_path)
            )
        )
    assert result.error_message is None
    assert result.result is not None
    request.assert_not_called()
    url_open.assert_not_called()
