import json
from pathlib import Path

import pytest
from app.core.config import settings
from app.services import local_ai, rag_assistant, rag_index
from app.services.rag_assistant import answer_scan_question
from app.services.rag_index import (
    RagIndexError,
    _configured_index_path,
    load_index,
    rebuild_index,
)


def _document(document_id: str = "local-guide") -> dict[str, str]:
    return {
        "document_id": document_id,
        "title": "Local authorization guide",
        "source_type": "approved_guidance",
        "content": "Check ownership before returning an object to the authenticated caller.",
        "source_location": "internal://guidance/authorization",
        "source_url": "",
        "license": "Internal project guidance",
    }


def test_configured_relative_index_path_is_independent_of_process_cwd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "rag_index_path", "scratch/rag-index-v1.json")
    assert _configured_index_path() == (
        Path(__file__).resolve().parents[2] / "scratch/rag-index-v1.json"
    )


def test_lexical_index_is_atomic_versioned_and_preserves_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "index.json"
    monkeypatch.setattr(settings, "rag_chunk_chars", 32)
    monkeypatch.setattr(settings, "rag_chunk_overlap_chars", 4)
    monkeypatch.setattr(settings, "ollama_embedding_model", "")

    metadata = rebuild_index(
        output_path=path,
        lexical_only=True,
        extra_documents=[_document()],
    )
    chunks, loaded_metadata = load_index(path)

    local_chunks = [chunk for chunk in chunks if chunk["document_id"] == "local-guide"]
    assert metadata["status"] == "lexical_only"
    assert metadata["index_version"] == loaded_metadata["index_version"]
    assert metadata["document_count"] == 8
    assert len(local_chunks) > 1
    assert all(len(chunk["text"]) <= 32 for chunk in local_chunks)
    assert local_chunks[0]["chunk_id"] == "local-guide#chunk-0001"
    assert local_chunks[0]["source_location"] == "internal://guidance/authorization"
    assert local_chunks[0]["embedding"] is None
    assert path.stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".index.json.*"))


def test_duplicate_documents_are_deduplicated_and_conflicts_preserve_old_index(
    tmp_path: Path,
) -> None:
    path = tmp_path / "index.json"
    doc = _document()
    first = rebuild_index(
        output_path=path,
        lexical_only=True,
        extra_documents=[doc, dict(doc)],
    )
    original = path.read_bytes()
    assert first["document_count"] == 8

    conflict = {**doc, "content": "Different content for a duplicate stable ID."}
    with pytest.raises(RagIndexError, match="conflicting duplicate IDs"):
        rebuild_index(output_path=path, lexical_only=True, extra_documents=[doc, conflict])

    assert path.read_bytes() == original


def test_embedding_failure_does_not_replace_the_existing_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "index.json"
    monkeypatch.setattr(settings, "ollama_embedding_model", "test-embedding-v1")
    monkeypatch.setattr(
        local_ai,
        "embed_local_texts",
        lambda texts, status_data=None: [[1.0, 0.0] for _ in texts],
    )
    status = {
        "embedding_available": True,
        "embedding_model": "test-embedding-v1",
        "embedding_model_digest": "sha256:test-digest-1",
        "embedding_dimensions": 2,
    }
    rebuild_index(output_path=path, status_data=status)
    original = path.read_bytes()
    monkeypatch.setattr(
        local_ai,
        "embed_local_texts",
        lambda texts, status_data=None: None,
    )

    with pytest.raises(RagIndexError, match="Local embedding generation failed"):
        rebuild_index(output_path=path, status_data=status)

    assert path.read_bytes() == original
    chunks, metadata = load_index(
        path,
        expected_model_id="test-embedding-v1",
        expected_model_digest="sha256:test-digest-1",
        expected_embedding_dimensions=2,
    )
    assert metadata["status"] == "ready"
    assert all(chunk["embedding"] == [1.0, 0.0] for chunk in chunks)


def test_embedding_byte_budget_rejects_large_vectors_and_preserves_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "index.json"
    rebuild_index(output_path=path, lexical_only=True)
    original = path.read_bytes()
    monkeypatch.setattr(rag_index, "MAX_EMBEDDING_BYTES", 10)
    monkeypatch.setattr(
        local_ai,
        "embed_local_texts",
        lambda texts, status_data=None: [[0.1, 0.2, 0.3] for _ in texts],
    )

    with pytest.raises(RagIndexError, match="index size budget"):
        rebuild_index(
            output_path=path,
            status_data={"embedding_available": True, "embedding_model": "local-test"},
        )
    assert path.read_bytes() == original


def test_embedding_index_records_model_and_detects_model_or_chunking_staleness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "index.json"
    monkeypatch.setattr(settings, "ollama_embedding_model", "test-embedding-v1")
    monkeypatch.setattr(
        local_ai,
        "embed_local_texts",
        lambda texts, status_data=None: [[3.0, 4.0] for _ in texts],
    )
    metadata = rebuild_index(
        output_path=path,
        status_data={
            "embedding_available": True,
            "embedding_model": "test-embedding-v1",
            "embedding_model_digest": "sha256:test-digest-1",
            "embedding_dimensions": 2,
        },
    )
    chunks, ready = load_index(
        path,
        expected_model_id="test-embedding-v1",
        expected_model_digest="sha256:test-digest-1",
    )
    assert metadata["status"] == "ready"
    assert ready["embedding_dimensions"] == 2
    assert chunks[0]["embedding"] == [0.6, 0.8]
    assert load_index(path, expected_model_id="different-model")[1]["status"] == "stale_model"
    assert (
        load_index(
            path,
            expected_model_id="test-embedding-v1",
            expected_model_digest="sha256:changed-digest",
        )[1]["status"]
        == "stale_model_version"
    )
    assert (
        load_index(
            path,
            expected_model_id="test-embedding-v1",
            expected_model_digest="sha256:test-digest-1",
            expected_embedding_dimensions=3,
        )[1]["status"]
        == "stale_dimensions"
    )

    monkeypatch.setattr(settings, "rag_chunk_chars", settings.rag_chunk_chars + 1)
    assert load_index(path, expected_model_id="test-embedding-v1")[1]["status"] == "stale_chunking"


def test_retrieval_uses_persisted_semantic_vectors_and_reports_ranking_method(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "index.json"
    monkeypatch.setattr(settings, "rag_index_path", str(path))
    monkeypatch.setattr(settings, "ollama_embedding_model", "test-embedding-v1")
    monkeypatch.setattr(
        local_ai,
        "embed_local_texts",
        lambda texts, status_data=None: [[1.0, 0.0] for _ in texts],
    )
    monkeypatch.setattr(
        rag_assistant,
        "embed_local_texts",
        lambda texts, status_data=None: [[1.0, 0.0] for _ in texts],
    )
    rebuild_index(
        output_path=path,
        status_data={
            "embedding_available": True,
            "embedding_model": "test-embedding-v1",
            "embedding_model_digest": "sha256:test-digest-1",
            "embedding_dimensions": 2,
        },
        extra_documents=[_document()],
    )
    result = answer_scan_question(
        "How do I verify object ownership?",
        spec_findings=[],
        source_findings=[],
        correlated_findings=[],
        matched_endpoints=[],
        local_ai_status={
            "embedding_available": True,
            "embedding_model": "test-embedding-v1",
            "embedding_model_digest": "sha256:test-digest-1",
            "embedding_dimensions": 2,
        },
    )

    assert result["index_status"] == "ready"
    assert result["index_version"]
    assert result["retrieval"] == "local_hybrid_bm25_ollama_embeddings"
    assert result["ranking_method"] == "reciprocal_rank_fusion_k60_semantic_min_0.50"
    source = next(item for item in result["sources"] if item["id"] == "local-guide")
    assert source["document_id"] == "local-guide"
    assert source["chunk_id"] == "local-guide"
    assert source["retrieval_method"] == "bm25+ollama_embedding"


def test_corrupt_index_is_rejected_and_lexical_fallback_remains_available(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "index.json"
    path.write_text("{ malformed", encoding="utf-8")
    monkeypatch.setattr(settings, "rag_index_path", str(path))
    chunks, metadata = load_index(path)
    assert chunks == []
    assert metadata["status"] == "invalid"
    result = answer_scan_question(
        "How should ownership checks work?",
        spec_findings=[],
        source_findings=[],
        correlated_findings=[],
        matched_endpoints=[],
    )
    assert result["index_status"] == "invalid"
    assert any(source["id"] == "owasp-api1" for source in result["sources"])
    assert result["external_network_used"] is False


def test_manifest_ingestion_rejects_malformed_and_oversized_inputs(
    tmp_path: Path,
) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("not-json", encoding="utf-8")
    with pytest.raises(RagIndexError, match="unavailable or malformed"):
        rebuild_index(output_path=tmp_path / "index.json", manifest_path=malformed)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (8 * 1024 * 1024 + 1))
    with pytest.raises(RagIndexError, match="size limit"):
        rebuild_index(output_path=tmp_path / "index.json", manifest_path=oversized)


def test_manifest_ingestion_accepts_reviewed_local_documents(tmp_path: Path) -> None:
    manifest = tmp_path / "sources.json"
    manifest.write_text(json.dumps({"documents": [_document("approved-doc")]}), encoding="utf-8")
    chunks, metadata = load_index(tmp_path / "index.json")
    assert chunks == []
    assert metadata["status"] == "missing"
    result = rebuild_index(
        output_path=tmp_path / "index.json",
        manifest_path=manifest,
        include_bundled=False,
        lexical_only=True,
    )
    indexed, _ = load_index(tmp_path / "index.json")
    assert result["document_count"] == 1
    assert indexed[0]["document_id"] == "approved-doc"


def test_secret_redaction_covers_indexed_provenance(tmp_path: Path) -> None:
    document = {
        **_document("provenance-doc"),
        "source_location": "https://internal.example/doc?token=provenance-secret",
        "source_url": "https://internal.example/doc?api_key=source-secret",
    }
    rebuild_index(
        output_path=tmp_path / "index.json",
        lexical_only=True,
        include_bundled=False,
        extra_documents=[document],
    )
    indexed, _ = load_index(tmp_path / "index.json")
    assert "provenance-secret" not in indexed[0]["source_location"]
    assert "source-secret" not in indexed[0]["source_url"]


def test_unavailable_ollama_does_not_auto_create_or_rebuild_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "index.json"
    monkeypatch.setattr(settings, "rag_index_path", str(path))
    result = answer_scan_question(
        "Which guidance covers authorization?",
        spec_findings=[],
        source_findings=[],
        correlated_findings=[],
        matched_endpoints=[],
        local_ai_status={"status": "Unavailable", "embedding_available": False},
    )
    assert result["index_status"] == "missing"
    assert not path.exists()
    assert result["external_network_used"] is False
