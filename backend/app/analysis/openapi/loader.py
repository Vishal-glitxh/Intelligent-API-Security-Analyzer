import hashlib
import json
from dataclasses import dataclass
from typing import Any, cast

import yaml

from app.analysis.context import SourceLocation
from app.core.exceptions import InvalidInputError


class SpecParsingError(InvalidInputError):
    """Raised when an OpenAPI specification cannot be parsed due to syntax or size limits."""


@dataclass(frozen=True)
class LoadedSpec:
    """Encapsulates raw parsed specification data, text hash, and location mapping."""

    raw_data: dict[str, Any]
    raw_text: str
    spec_hash: str
    location_map: dict[str, SourceLocation]
    file_path: str = "openapi.yaml"


def _encode_json_pointer_token(token: str) -> str:
    """Encode a token for RFC 6901 JSON pointer."""
    return token.replace("~", "~0").replace("/", "~1")


class _LineTrackingSafeLoader(yaml.SafeLoader):
    """Custom YAML loader recording source line/column coordinates."""


def load_openapi_spec(
    content: str,
    file_path: str = "openapi.yaml",
    max_size_bytes: int = 10 * 1024 * 1024,
) -> LoadedSpec:
    """Safely load and parse an OpenAPI specification from a YAML or JSON string.

    Enforces input size limits, tracks source line/column coordinates,
    computes deterministic SHA-256 digest, and returns a LoadedSpec.
    """
    if not isinstance(content, str):
        raise SpecParsingError("Specification content must be a string.")

    content_bytes = content.encode("utf-8")
    if len(content_bytes) > max_size_bytes:
        raise SpecParsingError(
            f"Specification size ({len(content_bytes)} bytes) exceeds the maximum limit "
            f"of {max_size_bytes} bytes."
        )

    if not content.strip():
        raise SpecParsingError("Specification content is empty.")

    spec_hash = hashlib.sha256(content_bytes).hexdigest()
    location_map: dict[str, SourceLocation] = {}

    # Custom YAML composer to extract line and column numbers per node
    class LocalLoader(_LineTrackingSafeLoader):
        pass

    def compose_mapping(loader: Any, node: yaml.nodes.MappingNode) -> dict[Any, Any]:
        mapping = cast(dict[Any, Any], loader.construct_mapping(node, deep=False))
        return mapping

    try:
        # Build YAML AST with composer to build full location map
        loader = LocalLoader(content)
        root_node = loader.get_single_node()
        if root_node is None:
            raise SpecParsingError("Specification document contains no root content.")

        def walk_node(node: yaml.nodes.Node, pointer: str) -> None:
            line = node.start_mark.line + 1
            col = node.start_mark.column + 1
            end_line = node.end_mark.line + 1
            end_col = node.end_mark.column + 1
            location_map[pointer] = SourceLocation(
                file=file_path,
                line=line,
                column=col,
                end_line=end_line,
                end_column=end_col,
                json_pointer=pointer,
            )

            if isinstance(node, yaml.nodes.MappingNode):
                for key_node, value_node in node.value:
                    if isinstance(key_node, yaml.nodes.ScalarNode):
                        key_str = str(key_node.value)
                        sub_pointer = f"{pointer}/{_encode_json_pointer_token(key_str)}"
                        walk_node(value_node, sub_pointer)
            elif isinstance(node, yaml.nodes.SequenceNode):
                for idx, item_node in enumerate(node.value):
                    sub_pointer = f"{pointer}/{idx}"
                    walk_node(item_node, sub_pointer)

        walk_node(root_node, "")

        # Now construct python dictionary safely
        raw_data = yaml.safe_load(content)

    except yaml.YAMLError as exc:
        # Fallback check for JSON
        try:
            raw_data = json.loads(content)
            # Basic fallback location for JSON if yaml failed
            location_map[""] = SourceLocation(file=file_path, line=1, column=1, json_pointer="")
        except json.JSONDecodeError:
            raise SpecParsingError(f"Failed to parse OpenAPI document: {exc}") from exc

    if not isinstance(raw_data, dict):
        raise SpecParsingError(
            f"OpenAPI root must be an object/mapping, got {type(raw_data).__name__}."
        )

    return LoadedSpec(
        raw_data=raw_data,
        raw_text=content,
        spec_hash=spec_hash,
        location_map=location_map,
        file_path=file_path,
    )
