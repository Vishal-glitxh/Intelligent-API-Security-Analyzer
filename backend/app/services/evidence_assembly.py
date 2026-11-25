"""Build bounded, trusted-only context for optional local model generation."""

from __future__ import annotations

import re
from typing import Any

from app.services.local_ai import redact_for_model
from app.services.rag_index import trusted_knowledge_excerpts

_RULE_IDENTIFIER = re.compile(r"\bAPI-(?:[A-Z0-9]+-)*[A-Z0-9]+-\d+\b")
_SOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}(?:#chunk-[0-9]{4})?$")
_MODEL_GUIDANCE_TYPES = frozenset(
    {"security_knowledge", "public_security_documentation", "internal_iasa_knowledge"}
)


def assemble_model_evidence(
    sources: list[dict[str, Any]], *, max_sources: int = 8, max_chars: int = 6000
) -> list[dict[str, str]]:
    """Select exact application-approved guidance; scan evidence never enters model context."""
    if max_sources < 1 or max_chars < 1:
        return []
    allowlisted = trusted_knowledge_excerpts()
    assembled: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    used_chars = 0
    for source in sources:
        if source.get("source_type") not in _MODEL_GUIDANCE_TYPES:
            continue
        source_id = source.get("id")
        if (
            not isinstance(source_id, str)
            or not source_id
            or source_id != source_id.strip()
            or not _SOURCE_ID.fullmatch(source_id)
            or source_id in seen_ids
        ):
            continue
        # Indexed titles are editable metadata and may contain prompt injection. The
        # approved excerpt is the only model-visible source content; keep the label
        # neutral and stable instead of forwarding the index title.
        title = "Approved security guidance"
        canonical_excerpt = redact_for_model(str(source.get("excerpt", "")))
        if allowlisted.get(source_id) != canonical_excerpt:
            continue
        excerpt = _RULE_IDENTIFIER.sub("[rule id]", canonical_excerpt)
        addition_size = len(title) + len(excerpt)
        if used_chars + addition_size > max_chars:
            continue
        seen_ids.add(source_id)
        assembled.append({"id": source_id, "title": title, "excerpt": excerpt})
        used_chars += addition_size
        if len(assembled) >= max_sources:
            break
    return assembled
