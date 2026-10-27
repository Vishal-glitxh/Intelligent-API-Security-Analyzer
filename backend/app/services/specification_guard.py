"""Admission checks for untrusted specifications before the frozen analyzer runs."""

import re
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml
from app.core.exceptions import InvalidInputError
from yaml.events import AliasEvent

_MAX_DOCUMENT_BYTES = 10 * 1024 * 1024  # Match the frozen specification loader's ceiling.
_MAX_YAML_NODES = 50_000
_MAX_YAML_DEPTH = 128
_MAX_YAML_ALIASES = 1_024
_REFERENCE_KEYS = frozenset({"$ref", "$dynamicRef", "$recursiveRef"})
_YAML_MERGE_TAG = "tag:yaml.org,2002:merge"
_REFERENCE_ERROR = "OPENAPI_PARSING_ERROR: Only valid in-document references are supported."
_YAML_COMPLEXITY_ERROR = "OPENAPI_PARSING_ERROR: YAML exceeds supported complexity limits."
_YAML_MERGE_ERROR = "OPENAPI_PARSING_ERROR: YAML merge keys are unsupported."


class SpecificationGuardError(InvalidInputError):
    """A specification cannot safely enter the analysis pipeline."""


class _BoundedSafeLoader(yaml.SafeLoader):
    """SafeLoader that bounds structural work while composing, before construction."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._composition_depth = 0
        self._composed_nodes = 0
        self._alias_references = 0

    def compose_node(self, parent: Any, index: Any) -> yaml.nodes.Node | None:
        self._composition_depth += 1
        try:
            if self._composition_depth > _MAX_YAML_DEPTH:
                raise SpecificationGuardError(_YAML_COMPLEXITY_ERROR)

            if self.check_event(AliasEvent):
                self._alias_references += 1
                if self._alias_references > _MAX_YAML_ALIASES:
                    raise SpecificationGuardError(_YAML_COMPLEXITY_ERROR)
            else:
                self._composed_nodes += 1
                if self._composed_nodes > _MAX_YAML_NODES:
                    raise SpecificationGuardError(_YAML_COMPLEXITY_ERROR)

            return super().compose_node(parent, index)
        finally:
            self._composition_depth -= 1

    def flatten_mapping(self, node: yaml.nodes.MappingNode) -> None:
        # SafeConstructor expands merge keys by recursively copying mapping entries.
        # Reject them before calling its implementation to avoid exponential expansion.
        if any(key.tag == _YAML_MERGE_TAG for key, _ in node.value):
            raise SpecificationGuardError(_YAML_MERGE_ERROR)
        super().flatten_mapping(node)


def _validate_reference(value: object) -> None:
    # urlsplit alone normalizes some whitespace/control characters. Reject them first.
    if (
        not isinstance(value, str)
        or not value.startswith("#")
        or any(character.isspace() or ord(character) < 32 for character in value)
        or "\\" in value
        or re.search(r"%(?![0-9A-Fa-f]{2})", value)
    ):
        raise SpecificationGuardError(_REFERENCE_ERROR)

    try:
        uri = urlsplit(value)
        fragment = unquote(uri.fragment, errors="strict")
    except ValueError, UnicodeError:
        raise SpecificationGuardError(_REFERENCE_ERROR) from None

    if uri.scheme or uri.netloc or uri.path or uri.query:
        raise SpecificationGuardError(_REFERENCE_ERROR)

    if not fragment:
        return  # The document root.
    if fragment.startswith("/"):
        if re.search(r"~(?![01])", fragment):
            raise SpecificationGuardError(_REFERENCE_ERROR)
        return  # RFC 6901 JSON Pointer, including escaped and percent-encoded tokens.
    if re.fullmatch(r"[A-Za-z_][-A-Za-z0-9._]*", fragment):
        return  # JSON Schema anchors in OpenAPI 3.1 are also local fragments.
    raise SpecificationGuardError(_REFERENCE_ERROR)


def guard_specification_references(content: str) -> None:
    """Reject external references and cyclic YAML before parsing/validation by the analyzer.

    The bounded SafeLoader caps nodes, nesting, and aliases during composition, before YAML
    construction. YAML merge keys are rejected before PyYAML can expand them. Shared ordinary
    aliases are visited once; cycles are rejected before reaching the frozen location walker.
    Errors contain no input values, parser excerpts, URLs, or filesystem locations.
    """
    try:
        if len(content.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
            raise SpecificationGuardError("OPENAPI_PARSING_ERROR: Specification is too large.")
        loader = _BoundedSafeLoader(content)
        try:
            document = loader.get_single_data()
        finally:
            loader.dispose()
    except RecursionError:
        raise SpecificationGuardError(_YAML_COMPLEXITY_ERROR) from None
    except yaml.YAMLError, UnicodeError, ValueError:
        raise SpecificationGuardError(
            "OPENAPI_PARSING_ERROR: Invalid specification document."
        ) from None

    if not isinstance(document, dict):
        raise SpecificationGuardError("OPENAPI_PARSING_ERROR: Specification must be an object.")

    visited: set[int] = set()
    active: set[int] = set()
    pending: list[tuple[object, bool]] = [(document, False)]
    while pending:
        node, exiting = pending.pop()
        if not isinstance(node, (dict, list)):
            continue
        identity = id(node)
        if exiting:
            active.remove(identity)
            visited.add(identity)
            continue
        if identity in active:
            raise SpecificationGuardError(
                "OPENAPI_PARSING_ERROR: Cyclic YAML aliases are unsupported."
            )
        if identity in visited:
            continue
        active.add(identity)
        pending.append((node, True))
        if isinstance(node, dict):
            for key, value in node.items():
                if key in _REFERENCE_KEYS:
                    _validate_reference(value)
                pending.append((value, False))
        else:
            pending.extend((value, False) for value in node)
