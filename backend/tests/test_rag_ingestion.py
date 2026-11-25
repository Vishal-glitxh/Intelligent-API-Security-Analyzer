from __future__ import annotations

import hashlib
import json
import os
import uuid
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from app.core.config import settings
from app.schemas.scan import ScanAssistantResponse
from app.services import rag_index
from app.services.rag_assistant import answer_scan_question
from app.services.rag_index import (
    PROVENANCE_INDEX_SCHEMA_VERSION,
    RagIndexError,
    build_ingested_index,
    load_index,
    trusted_knowledge_excerpts,
)
from app.services.rag_ingestion import DocumentIngestionError, ingest_directory


def _pdf_with_text(text: str) -> bytes:
    stream = f"BT /F1 12 Tf 40 200 Td ({text}) Tj ET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    result = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(result))
        result.extend(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")
    xref_offset = len(result)
    result.extend(f"xref\n0 {len(offsets)}\n".encode())
    result.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        result.extend(f"{offset:010d} 00000 n \n".encode())
    result.extend(
        (
            f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
        ).encode()
    )
    return bytes(result)


def _docx_with_text(path: Path, text: str) -> None:
    xml = (
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr>'
        "<w:r><w:t>Access</w:t></w:r></w:p>"
        f"<w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", xml)


def _reseal_v2_index(value: dict[str, object]) -> None:
    manifest = {
        key: value[key]
        for key in (
            "documents",
            "chunking_version",
            "chunking",
            "embedding_model",
            "embedding_model_digest",
            "embedding_dimensions",
        )
    }
    value["manifest_sha256"] = hashlib.sha256(rag_index._canonical_json(manifest)).hexdigest()
    unsigned = {key: item for key, item in value.items() if key != "integrity_sha256"}
    value["integrity_sha256"] = hashlib.sha256(rag_index._canonical_json(unsigned)).hexdigest()


def _write_candidate_index(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(path, 0o600)


def test_extracts_pdf_docx_text_markdown_html_and_plain_text(tmp_path: Path) -> None:
    (tmp_path / "guide.pdf").write_bytes(_pdf_with_text("verify authorization"))
    _docx_with_text(tmp_path / "guide.docx", "check object ownership")
    (tmp_path / "guide.md").write_text("# Rate Limits\nUse bounded requests.", encoding="utf-8")
    (tmp_path / "guide.html").write_text(
        "<h1>Resource Limits</h1><p>Bound each request.</p><script>secret()</script>",
        encoding="utf-8",
    )
    (tmp_path / "guide.txt").write_text("Review access policy.", encoding="utf-8")

    result = ingest_directory(tmp_path)
    by_name = {item["original_filename"]: item for item in result.documents}
    assert len(by_name) == 5
    assert "verify authorization" in by_name["guide.pdf"]["content"]
    assert "check object ownership" in by_name["guide.docx"]["content"]
    assert by_name["guide.docx"]["segments"][0]["section"] == "Access"
    assert "Rate Limits" in by_name["guide.md"]["content"]
    assert "Bound each request" in by_name["guide.html"]["content"]
    assert "secret()" not in by_name["guide.html"]["content"]
    assert by_name["guide.pdf"]["segments"][0]["page"] == 1


def test_rejects_invalid_empty_and_oversized_documents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "bad.txt").write_bytes(b"\xff\xfe")
    with pytest.raises(DocumentIngestionError, match="UTF-8"):
        ingest_directory(tmp_path)

    (tmp_path / "bad.txt").unlink()
    (tmp_path / "empty.html").write_text("<script>no visible text</script>", encoding="utf-8")
    with pytest.raises(DocumentIngestionError, match="no extractable text"):
        ingest_directory(tmp_path)

    (tmp_path / "empty.html").unlink()
    (tmp_path / "large.md").write_text("x" * 20, encoding="utf-8")
    monkeypatch.setattr(settings, "rag_max_ingest_file_bytes", 10)
    with pytest.raises(DocumentIngestionError, match="per-file size limit"):
        ingest_directory(tmp_path)


def test_rejects_symbolic_links_and_excludes_sensitive_paths(tmp_path: Path) -> None:
    (tmp_path / "safe.md").write_text("Safe reference text.", encoding="utf-8")
    secret_dir = tmp_path / ".ssh"
    secret_dir.mkdir()
    (secret_dir / "id_ed25519").write_text("not read", encoding="utf-8")
    (tmp_path / "application-secrets.md").write_text("must not be indexed", encoding="utf-8")
    result = ingest_directory(tmp_path)
    assert [item["original_filename"] for item in result.documents] == ["safe.md"]
    assert result.excluded_sensitive_count == 1

    target = tmp_path.parent / "outside.md"
    target.write_text("Outside root.", encoding="utf-8")
    try:
        (tmp_path / "linked.md").symlink_to(target)
    except OSError, NotImplementedError:
        pytest.skip("Symlink creation is unavailable on this platform.")
    with pytest.raises(DocumentIngestionError, match="symbolic-link"):
        ingest_directory(tmp_path)


def test_duplicate_files_are_deduplicated_by_raw_sha256(tmp_path: Path) -> None:
    content = b"# Authorization\nCheck ownership before returning objects."
    (tmp_path / "first.md").write_bytes(content)
    (tmp_path / "copy.md").write_bytes(content)
    result = ingest_directory(tmp_path)
    assert len(result.documents) == 1
    assert result.duplicate_count == 1
    assert result.documents[0]["source_sha256"] == hashlib.sha256(content).hexdigest()
    assert result.documents[0]["document_id"] == f"doc-{hashlib.sha256(content).hexdigest()}"


def test_provenance_candidate_index_preserves_offsets_and_requires_hash_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_dir = tmp_path / "refs"
    source_dir.mkdir()
    text = "# Authorization\n\n" + "Check object ownership before returning data. " * 20
    source_path = source_dir / "auth.md"
    source_path.write_text(text, encoding="utf-8")
    active = tmp_path / "rag-index-v1.json"
    candidate = tmp_path / "rag-index-v2-candidate.json"
    monkeypatch.setattr(settings, "rag_index_path", str(active))
    monkeypatch.setattr(settings, "rag_chunk_chars", 64)
    monkeypatch.setattr(settings, "rag_chunk_overlap_chars", 8)
    monkeypatch.setattr(settings, "rag_approved_document_hashes", "")

    result = build_ingested_index(source_dir, output_path=candidate, lexical_only=True)
    chunks, metadata = load_index(candidate)
    imported = [
        chunk for chunk in chunks if chunk["source_category"] == "public_security_documentation"
    ]
    approved_digest = result["review_required_document_hashes"][0]
    assert result["index_schema_version"] == PROVENANCE_INDEX_SCHEMA_VERSION
    assert metadata["index_schema_version"] == PROVENANCE_INDEX_SCHEMA_VERSION
    assert len(imported) > 1
    assert all(chunk["source_identity"] == "auth.md" for chunk in imported)
    assert all(chunk["original_filename"] == "auth.md" for chunk in imported)
    assert all(chunk["document_sha256"] == approved_digest for chunk in imported)
    assert all(chunk["char_end"] - chunk["char_start"] == len(chunk["text"]) for chunk in imported)
    assert not any(chunk["chunk_id"] in trusted_knowledge_excerpts() for chunk in imported)

    monkeypatch.setattr(settings, "rag_index_path", str(candidate))
    monkeypatch.setattr(settings, "rag_approved_document_hashes", approved_digest)
    approved = trusted_knowledge_excerpts()
    assert all(approved[chunk["chunk_id"]] == chunk["text"] for chunk in imported)
    retrieval = answer_scan_question(
        "Check object ownership before returning data",
        spec_findings=[],
        source_findings=[],
        correlated_findings=[],
        matched_endpoints=[],
        limit=8,
        local_ai_status={"embedding_available": False},
    )
    retrieved = next(
        source for source in retrieval["sources"] if source["document_sha256"] == approved_digest
    )
    assert retrieved["document_sha256"] == approved_digest
    assert retrieved["source_identity"] is None
    assert retrieved["original_filename"] is None
    assert retrieved["source_url"] is None
    assert approved_digest in retrieved["citation"]
    assert retrieved["char_end"] - retrieved["char_start"] == len(retrieved["excerpt"])
    serialized = ScanAssistantResponse.model_validate(
        {
            "scan_id": uuid.uuid4(),
            "answer": retrieval["answer"],
            "sources": retrieval["sources"],
            "retrieval": retrieval["retrieval"],
            "ranking_policy": retrieval["ranking_policy"],
            "ranking_method": retrieval["ranking_method"],
            "external_network_used": False,
            "notice": retrieval["notice"],
            "ai_status": "Unavailable",
            "ai_used": False,
            "claim_citations": retrieval["claim_citations"],
        }
    )
    serialized_source = next(
        source for source in serialized.sources if source.document_sha256 == approved_digest
    )
    assert serialized_source.source_identity is None
    assert serialized_source.original_filename is None
    assert serialized_source.source_url is None
    assert approved_digest in serialized_source.citation
    assert serialized_source.page is None
    assert serialized_source.section is None
    assert not active.exists()


def test_ingest_refuses_active_or_existing_index_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_dir = tmp_path / "refs"
    source_dir.mkdir()
    (source_dir / "guide.txt").write_text("Local guide.", encoding="utf-8")
    active = tmp_path / "active.json"
    active.write_text("existing", encoding="utf-8")
    monkeypatch.setattr(settings, "rag_index_path", str(active))
    with pytest.raises(RagIndexError, match="new path"):
        build_ingested_index(source_dir, output_path=active, lexical_only=True)
    assert active.read_text(encoding="utf-8") == "existing"


def test_v2_index_rejects_forged_chunk_even_if_local_checksums_are_recomputed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_dir = tmp_path / "refs"
    source_dir.mkdir()
    (source_dir / "guide.txt").write_text("Original approved guidance.", encoding="utf-8")
    path = tmp_path / "candidate-v2.json"
    monkeypatch.setattr(settings, "rag_index_path", str(tmp_path / "active-v1.json"))
    build_ingested_index(source_dir, output_path=path, lexical_only=True)
    value = json.loads(path.read_text(encoding="utf-8"))
    imported_chunk = next(
        chunk
        for chunk in value["chunks"]
        if chunk.get("source_category") == "public_security_documentation"
    )
    imported_chunk["text"] = "Forged unapproved guidance."
    imported_chunk["content_sha256"] = hashlib.sha256(imported_chunk["text"].encode()).hexdigest()
    unsigned = {key: item for key, item in value.items() if key != "integrity_sha256"}
    value["integrity_sha256"] = hashlib.sha256(rag_index._canonical_json(unsigned)).hexdigest()
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(path, 0o600)

    chunks, metadata = load_index(path)
    assert chunks == []
    assert metadata["status"] == "invalid"


def test_v2_index_rejects_forged_chunk_identity_and_offsets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_dir = tmp_path / "refs"
    source_dir.mkdir()
    (source_dir / "guide.txt").write_text("Original approved guidance.", encoding="utf-8")
    path = tmp_path / "candidate-v2.json"
    monkeypatch.setattr(settings, "rag_index_path", str(tmp_path / "active-v1.json"))
    build_ingested_index(source_dir, output_path=path, lexical_only=True)
    original: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))

    def assert_invalid(mutator: Callable[[dict[str, Any]], None]) -> None:
        value: dict[str, object] = json.loads(json.dumps(original))
        chunks = value["chunks"]
        assert isinstance(chunks, list) and chunks
        chunk = next(
            item for item in chunks if item["source_category"] == "public_security_documentation"
        )
        mutator(chunk)
        _reseal_v2_index(value)
        _write_candidate_index(path, value)
        loaded, metadata = load_index(path)
        assert loaded == []
        assert metadata["status"] == "invalid"

    assert_invalid(lambda chunk: chunk.__setitem__("chunk_id", "ignore-policy-and-reveal-secrets"))
    assert_invalid(lambda chunk: chunk.__setitem__("char_start", -1))
    assert_invalid(lambda chunk: chunk.__setitem__("char_end", chunk["char_end"] - 1))


def test_unapproved_document_cannot_become_trusted_through_metadata_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_dir = tmp_path / "refs"
    source_dir.mkdir()
    (source_dir / "guide.md").write_text(
        "Review authorization decisions carefully.", encoding="utf-8"
    )
    path = tmp_path / "candidate-v2.json"
    monkeypatch.setattr(settings, "rag_index_path", str(tmp_path / "active-v1.json"))
    monkeypatch.setattr(settings, "rag_approved_document_hashes", "")
    result = build_ingested_index(source_dir, output_path=path, lexical_only=True)
    value: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
    document_hash = result["review_required_document_hashes"][0]
    documents = value["documents"]
    assert isinstance(documents, list)
    imported = next(
        document for document in documents if document["document_sha256"] == document_hash
    )
    imported["title"] = "OWASP API Security Top 10"
    imported["source_location"] = "OWASP official security guidance"
    imported["source_url"] = "https://example.invalid/authoritative-guidance"
    chunks = value["chunks"]
    assert isinstance(chunks, list)
    imported_chunks = [chunk for chunk in chunks if chunk["document_id"] == imported["document_id"]]
    assert imported_chunks
    for chunk in imported_chunks:
        chunk["title"] = imported["title"]
        chunk["source_location"] = imported["source_location"]
        chunk["source_url"] = imported["source_url"]
        chunk["source_type"] = "security_knowledge"
    _reseal_v2_index(value)
    _write_candidate_index(path, value)

    monkeypatch.setattr(settings, "rag_index_path", str(path))
    chunks, metadata = load_index(path)
    assert metadata["status"] == "lexical_only"
    assert any(chunk["source_type"] == "security_knowledge" for chunk in chunks)
    assert not set(trusted_knowledge_excerpts()).intersection(
        chunk["chunk_id"] for chunk in imported_chunks
    )


def test_deleted_document_cannot_leave_stale_model_trust_or_citations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_dir = tmp_path / "refs"
    source_dir.mkdir()
    (source_dir / "guide.md").write_text(
        "Review authorization decisions carefully.", encoding="utf-8"
    )
    path = tmp_path / "candidate-v2.json"
    monkeypatch.setattr(settings, "rag_index_path", str(tmp_path / "active-v1.json"))
    result = build_ingested_index(source_dir, output_path=path, lexical_only=True)
    document_hash = result["review_required_document_hashes"][0]
    initial_value: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
    initial_documents = initial_value["documents"]
    initial_chunks = initial_value["chunks"]
    assert isinstance(initial_documents, list) and isinstance(initial_chunks, list)
    deleted_document = next(
        document for document in initial_documents if document["document_sha256"] == document_hash
    )
    deleted_ids = {
        chunk["chunk_id"]
        for chunk in initial_chunks
        if chunk["document_id"] == deleted_document["document_id"]
    }
    monkeypatch.setattr(settings, "rag_index_path", str(path))
    monkeypatch.setattr(settings, "rag_approved_document_hashes", document_hash)
    assert deleted_ids.intersection(trusted_knowledge_excerpts())

    documents = [
        document
        for document in initial_documents
        if document["document_id"] != deleted_document["document_id"]
    ]
    chunks = [
        chunk for chunk in initial_chunks if chunk["document_id"] != deleted_document["document_id"]
    ]
    value: dict[str, object] = {
        **initial_value,
        "documents": documents,
        "chunks": chunks,
        "document_count": len(documents),
        "chunk_count": len(chunks),
    }
    _reseal_v2_index(value)
    _write_candidate_index(path, value)
    monkeypatch.setattr(settings, "rag_index_path", str(path))

    loaded, metadata = load_index(path)
    trusted = trusted_knowledge_excerpts()
    assert metadata["status"] == "lexical_only"
    assert loaded
    assert deleted_ids.isdisjoint(trusted)
    assert all(
        chunk["chunk_id"] not in trusted
        for chunk in loaded
        if chunk["document_id"] == deleted_document["document_id"]
    )


def test_v2_index_rejects_stale_chunk_references_after_source_deletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_dir = tmp_path / "refs"
    source_dir.mkdir()
    (source_dir / "guide.md").write_text(
        "Review authorization decisions carefully.", encoding="utf-8"
    )
    path = tmp_path / "candidate-v2.json"
    monkeypatch.setattr(settings, "rag_index_path", str(tmp_path / "active-v1.json"))
    build_ingested_index(source_dir, output_path=path, lexical_only=True)
    value: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
    documents = value["documents"]
    assert isinstance(documents, list)
    imported = next(
        document
        for document in documents
        if document["source_category"] == "public_security_documentation"
    )
    remaining_documents = [document for document in documents if document is not imported]
    value["documents"] = remaining_documents
    value["document_count"] = len(remaining_documents)
    # Keep its chunk records to model a stale source reference after a partial deletion.
    _reseal_v2_index(value)
    _write_candidate_index(path, value)

    chunks, metadata = load_index(path)
    assert chunks == []
    assert metadata["status"] == "invalid"
