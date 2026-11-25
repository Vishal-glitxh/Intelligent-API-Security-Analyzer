"""Bounded, versioned local RAG index with atomic replacement and lexical fallback."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from app.core.config import settings

INDEX_SCHEMA_VERSION = 1
PROVENANCE_INDEX_SCHEMA_VERSION = 2
CHUNKING_VERSION = "paragraph-window-v1"
PROVENANCE_CHUNKING_VERSION = "structure-aware-provenance-v2"
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_INDEX_BYTES = 64 * 1024 * 1024
MAX_EMBEDDING_BYTES = 32 * 1024 * 1024
MAX_CHUNKS = 4096
_DOCUMENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class RagIndexError(ValueError):
    """A sanitized, expected local index error."""


def _configured_index_path() -> Path:
    configured = Path(settings.rag_index_path)
    if configured.is_absolute():
        return configured
    # Resolve configured relative paths from the project root rather than the process CWD;
    # the API and documented CLI run from different working directories.
    return Path(__file__).resolve().parents[3] / configured


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _bundled_documents() -> list[dict[str, str]]:
    # Lazy import avoids a module cycle: the assistant consumes this index module.
    from app.services.rag_assistant import _SECURITY_KNOWLEDGE

    documents: list[dict[str, str]] = []
    for document in _SECURITY_KNOWLEDGE:
        content = document.content
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        documents.append(
            {
                "document_id": document.document_id,
                "title": document.title,
                "source_type": document.source_type,
                "content": document.content,
                "source_location": document.source_url or document.citation,
                "source_url": document.source_url or "",
                "license": document.license or "",
                "source_category": "internal_iasa_knowledge",
                "original_filename": f"{document.document_id}.bundled",
                "source_identity": f"bundled:{document.document_id}",
                "source_sha256": digest,
                "document_sha256": digest,
                "segments": json.dumps([{"text": content, "page": None, "section": None}]),
            }
        )
    return documents


def _load_manifest(path: Path) -> list[dict[str, Any]]:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES:
            raise RagIndexError("RAG source manifest exceeds the configured size limit.")
        value = json.loads(raw)
    except RagIndexError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RagIndexError("RAG source manifest is unavailable or malformed.") from exc

    if not isinstance(value, dict) or not isinstance(value.get("documents"), list):
        raise RagIndexError("RAG source manifest must contain a documents array.")
    documents: list[dict[str, Any]] = []
    for item in value["documents"]:
        if not isinstance(item, dict):
            raise RagIndexError("RAG source manifest contains an invalid document.")
        string_fields = ("document_id", "title", "source_type", "content")
        if any(not isinstance(item.get(field), str) for field in string_fields):
            raise RagIndexError("RAG source manifest contains an incomplete document.")
        document = {field: str(item[field]) for field in string_fields}
        for field in ("source_location", "source_url", "license"):
            optional = item.get(field, "")
            if not isinstance(optional, str):
                raise RagIndexError("RAG source manifest contains invalid provenance metadata.")
            document[field] = optional
        for field in (
            "source_category",
            "original_filename",
            "source_identity",
            "source_sha256",
            "document_sha256",
            "segments",
        ):
            if field in item:
                document[field] = item[field]
        documents.append(document)
    return documents


def _normalize_documents(
    extra_documents: list[dict[str, Any]], include_bundled: bool
) -> list[dict[str, Any]]:
    from app.services.local_ai import redact_for_model

    candidates = (_bundled_documents() if include_bundled else []) + extra_documents
    normalized: dict[str, dict[str, Any]] = {}
    total_chars = 0
    for item in candidates:
        document_id = item.get("document_id", "").strip()
        title = redact_for_model(item.get("title", "").strip())
        source_type = item.get("source_type", "").strip()
        content = redact_for_model(item.get("content", "").strip())
        if not _DOCUMENT_ID.fullmatch(document_id) or not title or not source_type or not content:
            raise RagIndexError(
                "RAG source contains an invalid identifier or empty required field."
            )
        if len(title) > 300 or len(source_type) > 80 or len(content) > 50_000:
            raise RagIndexError("RAG source exceeds a per-field size limit.")
        source_url = redact_for_model(item.get("source_url", "").strip())
        parsed_url = urlsplit(source_url)
        if source_url and (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname
            or parsed_url.username
            or parsed_url.password
        ):
            raise RagIndexError("RAG source URL must be an HTTP(S) URL without credentials.")
        source_location = redact_for_model(item.get("source_location", "").strip())
        license_name = item.get("license", "").strip()
        if len(source_url) > 2048 or len(source_location) > 1024 or len(license_name) > 200:
            raise RagIndexError("RAG source provenance exceeds a size limit.")
        identity = {
            "document_id": document_id,
            "title": title,
            "source_type": source_type,
            "content": content,
            "source_location": source_location,
            "source_url": source_url,
            "license": license_name,
        }
        provenance_fields = (
            "source_category",
            "original_filename",
            "source_identity",
            "source_sha256",
            "document_sha256",
        )
        for field in provenance_fields:
            value = item.get(field)
            if value is not None:
                if not isinstance(value, str) or len(value) > 2048:
                    raise RagIndexError("RAG source provenance metadata is invalid.")
                identity[field] = value
        segments = item.get("segments")
        if isinstance(segments, str):
            try:
                segments = json.loads(segments)
            except json.JSONDecodeError as exc:
                raise RagIndexError("RAG source segments are invalid.") from exc
        if segments is not None:
            if not isinstance(segments, list) or not segments:
                raise RagIndexError("RAG source segments are invalid.")
            normalized_segments: list[dict[str, Any]] = []
            for segment in segments:
                if not isinstance(segment, dict) or not isinstance(segment.get("text"), str):
                    raise RagIndexError("RAG source segments are invalid.")
                segment_text = redact_for_model(segment["text"].strip())
                if not segment_text or len(segment_text) > len(content) + 1:
                    raise RagIndexError("RAG source segments are invalid.")
                page = segment.get("page")
                section = segment.get("section")
                if page is not None and (not isinstance(page, int) or page < 1):
                    raise RagIndexError("RAG source page provenance is invalid.")
                if section is not None and (not isinstance(section, str) or len(section) > 300):
                    raise RagIndexError("RAG source section provenance is invalid.")
                normalized_segments.append({"text": segment_text, "page": page, "section": section})
            segment_content = "\n\n".join(segment["text"] for segment in normalized_segments)
            if segment_content != content:
                # Secret redaction is applied to the whole document and segment text alike;
                # require exact reconstruction so offsets cannot point at unrelated text.
                raise RagIndexError("RAG source segments do not reconstruct document content.")
            identity["segments"] = normalized_segments
            identity["document_sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if "source_sha256" in identity:
            digest = identity["source_sha256"]
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise RagIndexError("RAG source document hash is invalid.")
        if "document_sha256" in identity:
            digest = identity["document_sha256"]
            if (
                len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
                or digest != hashlib.sha256(content.encode("utf-8")).hexdigest()
            ):
                raise RagIndexError("RAG normalized document hash is invalid.")
        if "source_identity" in identity:
            source_identity = Path(identity["source_identity"])
            if source_identity.is_absolute() or ".." in source_identity.parts:
                raise RagIndexError("RAG source identity must be relative to its ingestion root.")
        previous = normalized.get(document_id)
        if previous is not None:
            if previous != identity:
                raise RagIndexError("RAG source manifest contains conflicting duplicate IDs.")
            continue
        normalized[document_id] = identity
        total_chars += len(content)
        if total_chars > settings.rag_index_max_chars:
            raise RagIndexError("RAG source corpus exceeds the configured character limit.")
        if len(normalized) > settings.rag_index_max_documents:
            raise RagIndexError("RAG source corpus exceeds the configured document limit.")
    if not normalized:
        raise RagIndexError("RAG source corpus is empty.")
    return [normalized[key] for key in sorted(normalized)]


def _split_content(content: str) -> list[str]:
    maximum = settings.rag_chunk_chars
    overlap = settings.rag_chunk_overlap_chars
    chunks: list[str] = []
    start = 0
    while start < len(content):
        end = min(len(content), start + maximum)
        if end < len(content):
            boundary = content.rfind(" ", start + maximum // 2, end)
            if boundary > start:
                end = boundary
        chunk = content[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(content):
            break
        start = max(start + 1, end - overlap)
    return chunks


def _split_with_offsets(content: str, maximum: int, overlap: int) -> list[tuple[str, int, int]]:
    chunks: list[tuple[str, int, int]] = []
    start = 0
    while start < len(content):
        end = min(len(content), start + maximum)
        if end < len(content):
            candidates = [
                content.rfind("\n\n", start + maximum // 2, end),
                content.rfind("\n", start + maximum // 2, end),
                content.rfind(". ", start + maximum // 2, end),
                content.rfind(" ", start + maximum // 2, end),
            ]
            boundary = max(candidates)
            if boundary > start:
                end = boundary + (2 if content[boundary : boundary + 2] in {"\n\n", ". "} else 1)
        left = start
        right = end
        while left < right and content[left].isspace():
            left += 1
        while right > left and content[right - 1].isspace():
            right -= 1
        if right > left:
            chunks.append((content[left:right], left, right))
        if end >= len(content):
            break
        start = max(start + 1, end - overlap)
    return chunks


def _make_chunks(
    documents: list[dict[str, Any]], *, with_provenance: bool = False
) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    for document in documents:
        content = document["content"]
        segments = document.get("segments") if with_provenance else None
        ranges: list[tuple[str, int, int, int | None, str | None]] = []
        if isinstance(segments, list):
            search_from = 0
            for segment in segments:
                segment_text = str(segment["text"])
                segment_start = content.find(segment_text, search_from)
                if segment_start < 0:
                    raise RagIndexError("RAG source segment offsets could not be established.")
                segment_end = segment_start + len(segment_text)
                ranges.extend(
                    (
                        text,
                        segment_start + start,
                        segment_start + end,
                        segment.get("page"),
                        segment.get("section"),
                    )
                    for text, start, end in _split_with_offsets(
                        segment_text, settings.rag_chunk_chars, settings.rag_chunk_overlap_chars
                    )
                )
                search_from = segment_end
        else:
            cursor = 0
            for text in _split_content(content):
                start = content.find(text, cursor)
                if start < 0:
                    raise RagIndexError("RAG chunk offsets could not be established.")
                end = start + len(text)
                ranges.append((text, start, end, None, None))
                cursor = max(start + 1, end - settings.rag_chunk_overlap_chars)
        for index, (text, char_start, char_end, page, section) in enumerate(ranges):
            parts_count = len(ranges)
            chunk_id = (
                document["document_id"]
                if parts_count == 1
                else f"{document['document_id']}#chunk-{index + 1:04d}"
            )
            base = {
                key: value for key, value in document.items() if key not in {"content", "segments"}
            }
            chunks.append(
                {
                    **base,
                    "chunk_id": chunk_id,
                    "chunk_index": index,
                    "text": text,
                    "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    "embedding": None,
                    "char_start": char_start,
                    "char_end": char_end,
                    "page": page,
                    "section": section,
                }
            )
            if len(chunks) > MAX_CHUNKS:
                raise RagIndexError("RAG source corpus exceeds the configured chunk limit.")
    return chunks


def trusted_knowledge_excerpts() -> dict[str, str]:
    """Return the application-controlled model-eligible knowledge corpus.

    The bundled source code is the trust anchor; editable index metadata and its
    self-checksum cannot add model-eligible documents.
    """
    documents = _normalize_documents([], include_bundled=True)
    trusted = {chunk["chunk_id"]: chunk["text"] for chunk in _make_chunks(documents)}
    # The frozen v1 index uses document IDs where the provenance-aware v2 index
    # uses chunk IDs. Keep exact bundled excerpts trusted under both stable IDs.
    trusted.update({document["document_id"]: document["content"] for document in documents})
    approved = {
        value.strip().lower()
        for value in settings.rag_approved_document_hashes.split(",")
        if value.strip()
    }
    if approved:
        index = _read_index(_configured_index_path())
        if index and index.get("index_schema_version") == PROVENANCE_INDEX_SCHEMA_VERSION:
            trusted.update(
                {
                    str(chunk["chunk_id"]): str(chunk["text"])
                    for chunk in index["chunks"]
                    if chunk.get("document_sha256") in approved
                    and chunk.get("source_category")
                    in {"public_security_documentation", "internal_iasa_knowledge"}
                }
            )
    return trusted


def _add_embeddings(
    chunks: list[dict[str, Any]],
    status_data: dict[str, Any],
) -> tuple[str, str | None, int]:
    from app.services.local_ai import embed_local_texts

    model = status_data.get("embedding_model")
    if not status_data.get("embedding_available") or not isinstance(model, str) or not model:
        raise RagIndexError("The configured local embedding model is unavailable.")
    dimensions: int | None = None
    embedding_bytes = 0
    for start in range(0, len(chunks), 64):
        batch = chunks[start : start + 64]
        vectors = embed_local_texts([item["text"] for item in batch], status_data=status_data)
        if vectors is None or len(vectors) != len(batch):
            raise RagIndexError(
                "Local embedding generation failed; the current index was preserved."
            )
        for chunk, vector in zip(batch, vectors, strict=True):
            if not vector or any(not math.isfinite(value) for value in vector):
                raise RagIndexError("Local embedding generation returned an invalid vector.")
            if dimensions is None:
                dimensions = len(vector)
            if len(vector) != dimensions:
                raise RagIndexError("Local embeddings have inconsistent dimensions.")
            norm = math.sqrt(sum(value * value for value in vector))
            if not norm:
                raise RagIndexError("Local embedding generation returned a zero vector.")
            normalized = [value / norm for value in vector]
            embedding_bytes += len(json.dumps(normalized, separators=(",", ":")).encode("ascii"))
            if embedding_bytes > MAX_EMBEDDING_BYTES:
                raise RagIndexError("Local embeddings exceed the configured index size budget.")
            chunk["embedding"] = normalized
    if dimensions is None:
        raise RagIndexError("No chunks were available for embedding.")
    model_digest = status_data.get("embedding_model_digest")
    if model_digest is not None and (not isinstance(model_digest, str) or not model_digest):
        raise RagIndexError("Local embedding model identity is invalid.")
    expected_dimensions = status_data.get("embedding_dimensions")
    if expected_dimensions is not None and expected_dimensions != dimensions:
        raise RagIndexError("Generated vector dimensions do not match configured model metadata.")
    return model, model_digest, dimensions


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded) > MAX_INDEX_BYTES:
        raise RagIndexError("Generated RAG index exceeds the configured storage limit.")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as out:
            temp_name = out.name
            os.chmod(temp_name, 0o600)
            out.write(encoded)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp_name, path)
        temp_name = None
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as exc:
        raise RagIndexError(
            "RAG index could not be written; the existing index was preserved."
        ) from exc
    finally:
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def rebuild_index(
    *,
    output_path: Path | None = None,
    manifest_path: Path | None = None,
    include_bundled: bool = True,
    lexical_only: bool = False,
    status_data: dict[str, Any] | None = None,
    extra_documents: list[dict[str, Any]] | None = None,
    schema_version: int = INDEX_SCHEMA_VERSION,
) -> dict[str, Any]:
    """Build a complete index off to the side, then atomically replace the old index."""
    path = output_path or _configured_index_path()
    previous = _read_index(path) if path.exists() else None
    extras = extra_documents if extra_documents is not None else []
    if manifest_path is not None:
        extras = _load_manifest(manifest_path)
    documents = _normalize_documents(extras, include_bundled)
    if schema_version not in {INDEX_SCHEMA_VERSION, PROVENANCE_INDEX_SCHEMA_VERSION}:
        raise RagIndexError("Requested RAG index schema is unsupported.")
    chunking_version = (
        PROVENANCE_CHUNKING_VERSION
        if schema_version == PROVENANCE_INDEX_SCHEMA_VERSION
        else CHUNKING_VERSION
    )
    if schema_version == PROVENANCE_INDEX_SCHEMA_VERSION and any(
        not all(
            isinstance(document.get(field), str)
            for field in ("source_sha256", "document_sha256", "source_identity", "source_category")
        )
        or not isinstance(document.get("segments"), list)
        for document in documents
    ):
        raise RagIndexError("Provenance index sources require complete ingestion metadata.")
    chunks = _make_chunks(
        documents, with_provenance=schema_version == PROVENANCE_INDEX_SCHEMA_VERSION
    )
    embedding_model: str | None = None
    embedding_model_digest: str | None = None
    embedding_dimensions: int | None = None
    if not lexical_only:
        if status_data is None:
            from app.services.local_ai import get_local_ai_status

            status_data = get_local_ai_status()
        embedding_model, embedding_model_digest, embedding_dimensions = _add_embeddings(
            chunks, status_data
        )

    manifest = {
        "index_schema_version": schema_version,
        "chunking_version": chunking_version,
        "chunking": {
            "maximum_characters": settings.rag_chunk_chars,
            "overlap_characters": settings.rag_chunk_overlap_chars,
        },
        "embedding_model": embedding_model,
        "embedding_model_digest": embedding_model_digest,
        "embedding_dimensions": embedding_dimensions,
        "document_count": len(documents),
        "chunk_count": len(chunks),
        "manifest_sha256": hashlib.sha256(
            _canonical_json(
                {
                    "documents": documents,
                    "chunking_version": chunking_version,
                    "chunking": {
                        "maximum_characters": settings.rag_chunk_chars,
                        "overlap_characters": settings.rag_chunk_overlap_chars,
                    },
                    "embedding_model": embedding_model,
                    "embedding_model_digest": embedding_model_digest,
                    "embedding_dimensions": embedding_dimensions,
                }
            )
        ).hexdigest(),
        "created_at": previous.get("created_at", _now()) if previous else _now(),
        "updated_at": _now(),
        "chunks": chunks,
    }
    if schema_version == PROVENANCE_INDEX_SCHEMA_VERSION:
        manifest["documents"] = documents
    manifest["integrity_sha256"] = hashlib.sha256(_canonical_json(manifest)).hexdigest()
    _atomic_write(path, manifest)
    return inspect_index(path)


def build_ingested_index(
    directory: Path,
    *,
    output_path: Path,
    lexical_only: bool = False,
    status_data: dict[str, Any] | None = None,
    source_category: str = "public_security_documentation",
) -> dict[str, Any]:
    """Build a new provenance index without replacing the configured or existing index."""
    from app.services.rag_ingestion import ingest_directory

    configured = _configured_index_path().resolve()
    destination = output_path.expanduser().resolve()
    if destination == configured or destination.exists():
        raise RagIndexError("Ingestion output must be a new path separate from the active index.")
    ingested = ingest_directory(directory, source_category=source_category)
    result = rebuild_index(
        output_path=destination,
        include_bundled=True,
        lexical_only=lexical_only,
        status_data=status_data,
        extra_documents=ingested.documents,
        schema_version=PROVENANCE_INDEX_SCHEMA_VERSION,
    )
    result.update(
        {
            "ingested_document_count": len(ingested.documents),
            "excluded_duplicate_count": ingested.duplicate_count,
            "excluded_sensitive_count": ingested.excluded_sensitive_count,
            "ignored_unsupported_count": ingested.ignored_unsupported_count,
            "ingested_source_bytes": ingested.total_source_bytes,
            "review_required_document_hashes": sorted(
                str(document["document_sha256"])
                for document in (_read_index(destination) or {}).get("documents", [])
                if document.get("source_category") == source_category
            ),
        }
    )
    return result


def _read_index(path: Path) -> dict[str, Any] | None:
    try:
        if path.stat().st_mode & 0o077:
            return None
        with path.open("rb") as source:
            raw = source.read(MAX_INDEX_BYTES + 1)
        if len(raw) > MAX_INDEX_BYTES:
            return None
        value = json.loads(raw)
    except OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError:
        return None
    if not isinstance(value, dict) or value.get("index_schema_version") not in {
        INDEX_SCHEMA_VERSION,
        PROVENANCE_INDEX_SCHEMA_VERSION,
    }:
        return None
    integrity = value.get("integrity_sha256")
    unsigned = {key: item for key, item in value.items() if key != "integrity_sha256"}
    if (
        not isinstance(integrity, str)
        or hashlib.sha256(_canonical_json(unsigned)).hexdigest() != integrity
    ):
        return None
    chunks = value.get("chunks")
    integer_fields = ("document_count", "chunk_count")
    if (
        not isinstance(chunks, list)
        or len(chunks) > MAX_CHUNKS
        or any(not isinstance(value.get(field), int) for field in integer_fields)
        or value.get("chunk_count") != len(chunks)
        or not isinstance(value.get("manifest_sha256"), str)
        or not isinstance(value.get("created_at"), str)
        or not isinstance(value.get("updated_at"), str)
        or not isinstance(value.get("chunking_version"), str)
        or not isinstance(value.get("chunking"), dict)
        or value.get("embedding_model") is not None
        and not isinstance(value.get("embedding_model"), str)
        or value.get("embedding_model_digest") is not None
        and not isinstance(value.get("embedding_model_digest"), str)
    ):
        return None
    dimensions = value.get("embedding_dimensions")
    if dimensions is not None and (not isinstance(dimensions, int) or dimensions < 1):
        return None
    model = value.get("embedding_model")
    if (model is None) != (dimensions is None):
        return None
    if value.get("embedding_model_digest") is not None and model is None:
        return None
    schema_version = value["index_schema_version"]
    documents_by_id: dict[str, dict[str, Any]] = {}
    if schema_version == PROVENANCE_INDEX_SCHEMA_VERSION:
        documents = value.get("documents")
        if not isinstance(documents, list) or len(documents) != value["document_count"]:
            return None
        for document in documents:
            if not isinstance(document, dict) or any(
                not isinstance(document.get(field), str)
                for field in (
                    "document_id",
                    "content",
                    "source_sha256",
                    "document_sha256",
                    "source_identity",
                )
            ):
                return None
            if not _DOCUMENT_ID.fullmatch(document["document_id"]):
                return None
            if (
                hashlib.sha256(document["content"].encode("utf-8")).hexdigest()
                != document["document_sha256"]
                or document["document_id"] in documents_by_id
                or not isinstance(document.get("segments"), list)
                or not isinstance(document.get("source_category"), str)
                or not isinstance(document.get("source_identity"), str)
                or Path(document["source_identity"]).is_absolute()
                or ".." in Path(document["source_identity"]).parts
                or len(document["content"]) > 50_000
            ):
                return None
            source_hash = document["source_sha256"]
            content_hash = document["document_sha256"]
            if (
                len(source_hash) != 64
                or any(char not in "0123456789abcdef" for char in source_hash)
                or len(content_hash) != 64
                or document["source_category"]
                not in {"internal_iasa_knowledge", "public_security_documentation"}
            ):
                return None
            reconstructed_segments: list[str] = []
            for segment in document["segments"]:
                if (
                    not isinstance(segment, dict)
                    or not isinstance(segment.get("text"), str)
                    or segment.get("page") is not None
                    and (not isinstance(segment.get("page"), int) or segment["page"] < 1)
                    or segment.get("section") is not None
                    and (
                        not isinstance(segment.get("section"), str) or len(segment["section"]) > 300
                    )
                ):
                    return None
                reconstructed_segments.append(segment["text"])
            if "\n\n".join(reconstructed_segments) != document["content"]:
                return None
            if (
                document["source_category"] == "public_security_documentation"
                and document["document_id"] != f"doc-{source_hash}"
            ):
                return None
            documents_by_id[document["document_id"]] = document
        expected_manifest_hash = hashlib.sha256(
            _canonical_json(
                {
                    "documents": documents,
                    "chunking_version": value.get("chunking_version"),
                    "chunking": value.get("chunking"),
                    "embedding_model": value.get("embedding_model"),
                    "embedding_model_digest": value.get("embedding_model_digest"),
                    "embedding_dimensions": value.get("embedding_dimensions"),
                }
            )
        ).hexdigest()
        if expected_manifest_hash != value.get("manifest_sha256"):
            return None
    chunk_ids: set[str] = set()
    document_ids: set[str] = set()
    for chunk in chunks:
        required_strings = (
            "document_id",
            "chunk_id",
            "title",
            "source_type",
            "source_location",
            "source_url",
            "license",
            "text",
            "content_sha256",
        )
        if not isinstance(chunk, dict) or any(
            not isinstance(chunk.get(field), str) for field in required_strings
        ):
            return None
        if len(chunk["text"]) > 1200 or chunk["chunk_id"] in chunk_ids:
            return None
        if hashlib.sha256(chunk["text"].encode("utf-8")).hexdigest() != chunk["content_sha256"]:
            return None
        if schema_version == PROVENANCE_INDEX_SCHEMA_VERSION:
            document = documents_by_id.get(chunk["document_id"])
            start, end = chunk.get("char_start"), chunk.get("char_end")
            if (
                document is None
                or (
                    chunk["chunk_id"] != chunk["document_id"]
                    and re.fullmatch(
                        rf"{re.escape(chunk['document_id'])}#chunk-[0-9]{{4}}",
                        chunk["chunk_id"],
                    )
                    is None
                )
                or not isinstance(start, int)
                or not isinstance(end, int)
                or start < 0
                or end <= start
                or document["content"][start:end] != chunk["text"]
                or chunk.get("document_sha256") != document["document_sha256"]
                or chunk.get("source_sha256") != document["source_sha256"]
            ):
                return None
        chunk_ids.add(chunk["chunk_id"])
        document_ids.add(chunk["document_id"])
        vector = chunk.get("embedding")
        if vector is not None:
            if (
                model is None
                or not isinstance(vector, list)
                or len(vector) != dimensions
                or not vector
                or any(
                    not isinstance(item, (int, float)) or not math.isfinite(item) for item in vector
                )
            ):
                return None
    if len(document_ids) != value["document_count"]:
        return None
    return value


def load_index(
    path: Path | None = None,
    *,
    expected_model_id: str | None = None,
    expected_model_digest: str | None = None,
    expected_embedding_dimensions: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load verified chunks and report incompatibility without attempting a rebuild."""
    target = path or _configured_index_path()
    index = _read_index(target)
    if index is None:
        exists = target.exists()
        return [], {"status": "invalid" if exists else "missing", "index_version": None}
    model = index.get("embedding_model")
    chunking = index.get("chunking", {})
    expected_chunking = (
        PROVENANCE_CHUNKING_VERSION
        if index.get("index_schema_version") == PROVENANCE_INDEX_SCHEMA_VERSION
        else CHUNKING_VERSION
    )
    if (
        index.get("chunking_version") != expected_chunking
        or chunking.get("maximum_characters") != settings.rag_chunk_chars
        or chunking.get("overlap_characters") != settings.rag_chunk_overlap_chars
    ):
        status = "stale_chunking"
    elif model is None:
        status = "lexical_only"
    elif expected_model_id and model != expected_model_id:
        status = "stale_model"
    elif expected_model_digest and index.get("embedding_model_digest") != expected_model_digest:
        status = "stale_model_version"
    elif (
        expected_embedding_dimensions is not None
        and index.get("embedding_dimensions") != expected_embedding_dimensions
    ):
        status = "stale_dimensions"
    else:
        status = "ready"
    metadata = {
        "status": status,
        "index_version": index["manifest_sha256"],
        "embedding_model": model,
        "embedding_model_digest": index.get("embedding_model_digest"),
        "embedding_dimensions": index.get("embedding_dimensions"),
        "document_count": index["document_count"],
        "chunk_count": index["chunk_count"],
        "created_at": index["created_at"],
        "updated_at": index["updated_at"],
        "chunking_version": index["chunking_version"],
        "index_schema_version": index["index_schema_version"],
    }
    return cast(list[dict[str, Any]], index["chunks"]), metadata


def inspect_index(
    path: Path | None = None,
    *,
    expected_model_digest: str | None = None,
    expected_embedding_dimensions: int | None = None,
) -> dict[str, Any]:
    """Return safe index metadata without exposing local filesystem paths."""
    expected = settings.ollama_embedding_model.strip() or None
    _, metadata = load_index(
        path,
        expected_model_id=expected,
        expected_model_digest=expected_model_digest,
        expected_embedding_dimensions=expected_embedding_dimensions,
    )
    return metadata
