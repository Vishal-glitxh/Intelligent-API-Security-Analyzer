"""Safe, local-only ingestion of bounded security reference documents."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import resource
import stat
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from app.core.config import settings

SUPPORTED_EXTENSIONS = frozenset({".pdf", ".docx", ".txt", ".md", ".markdown", ".html", ".htm"})
SUPPORTED_CATEGORIES = frozenset({"public_security_documentation", "internal_iasa_knowledge"})
MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_PDF_PAGES = 500
MAX_PDF_STREAM_BYTES = 8 * 1024 * 1024
MAX_PDF_DECODE_WORK_BYTES = 32 * 1024 * 1024
MAX_DOCX_ENTRIES = 4096
MAX_DOCX_EXPANDED_BYTES = 50 * 1024 * 1024
MAX_EXTRACTED_DOCUMENT_CHARS = 50_000
PDF_WORKER_TIMEOUT_SECONDS = 8
_SENSITIVE_COMPONENTS = frozenset(
    {".git", ".ssh", ".aws", ".azure", ".kube", ".config", "secrets", "credentials"}
)
_SENSITIVE_NAMES = re.compile(
    r"^(?:\.env(?:\..*)?|id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:pem|key|p12|pfx))$|"
    r"(?:^|[._-])(?:secrets?|credentials?|tokens?|api[-_]?keys?|private[-_]?keys?)"
    r"(?:[._-]|$)",
    re.IGNORECASE,
)
_HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
_PDF_HEADER = b"%PDF-"


class DocumentIngestionError(ValueError):
    """An expected, sanitized input or extraction failure."""


@dataclass(frozen=True)
class IngestionResult:
    documents: list[dict[str, Any]]
    excluded_files: tuple[str, ...]
    excluded_sensitive_count: int
    ignored_unsupported_count: int
    duplicate_count: int
    total_source_bytes: int


class _TextHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.section: str | None = None
        self.heading_depth = 0
        self.heading_parts: list[str] = []
        self.ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        lowered = tag.lower()
        if lowered in {"script", "style", "noscript", "svg"}:
            self.ignored_depth += 1
            self.parts.append("\n\n")
            return
        if self.ignored_depth:
            return
        if re.fullmatch(r"h[1-6]", lowered):
            self.heading_depth += 1
            self.heading_parts = []
        elif lowered in {"p", "div", "li", "section", "article", "br", "tr"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in {"script", "style", "noscript", "svg"} and self.ignored_depth:
            self.ignored_depth -= 1
            return
        if self.ignored_depth:
            return
        if re.fullmatch(r"h[1-6]", lowered) and self.heading_depth:
            heading = " ".join("".join(self.heading_parts).split())
            if heading:
                self.section = heading[:300]
                self.parts.append("\n")
                self.parts.append(heading)
                self.parts.append("\n")
            self.heading_depth = 0
            self.heading_parts = []
        elif lowered in {"p", "div", "li", "section", "article", "br", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self.ignored_depth:
            return
        if self.heading_depth:
            self.heading_parts.append(data)
        else:
            self.parts.append(data)


def _normalize_text(value: str) -> str:
    value = value.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    value = value.replace("\u00a0", " ")
    lines = [line.rstrip() for line in value.splitlines()]
    normalized = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()
    if not normalized:
        raise DocumentIngestionError("A supported document contains no extractable text.")
    return normalized


def _text_segments(text: str) -> list[dict[str, Any]]:
    segments: list[dict[str, Any]] = []
    current_section: str | None = None
    current: list[str] = []

    def flush() -> None:
        block = _normalize_text("\n".join(current)) if "\n".join(current).strip() else ""
        if block:
            segments.append({"text": block, "section": current_section, "page": None})
        current.clear()

    for line in text.splitlines():
        heading = _HEADING.match(line)
        if heading:
            flush()
            current_section = heading.group(2).strip()[:300]
            current.append(current_section)
        elif not line.strip() and current:
            flush()
        else:
            current.append(line)
    flush()
    if not segments:
        segments.append({"text": _normalize_text(text), "section": None, "page": None})
    return segments


def _extract_pdf_segments(raw: bytes) -> list[dict[str, Any]]:
    if not raw.startswith(_PDF_HEADER):
        raise DocumentIngestionError("PDF signature is invalid.")
    try:
        from pypdf import PdfReader, apply_configuration

        with apply_configuration(
            maximum_declared_stream_length=MAX_PDF_STREAM_BYTES,
            array_based_stream_maximum_output_length=MAX_PDF_STREAM_BYTES,
            jbig2_maximum_output_length=MAX_PDF_STREAM_BYTES,
            lzw_maximum_output_length=MAX_PDF_STREAM_BYTES,
            run_length_maximum_output_length=MAX_PDF_STREAM_BYTES,
            zlib_maximum_output_length=MAX_PDF_STREAM_BYTES,
            brotli_maximum_output_length=MAX_PDF_STREAM_BYTES,
            image_maximum_buffer_size=MAX_PDF_STREAM_BYTES,
            stream_decoding_work_maximum_length=MAX_PDF_DECODE_WORK_BYTES,
        ):
            reader = PdfReader(io.BytesIO(raw), strict=True)
            if reader.is_encrypted:
                raise DocumentIngestionError("Encrypted PDF documents are not supported.")
            if len(reader.pages) > MAX_PDF_PAGES:
                raise DocumentIngestionError("PDF exceeds the page limit.")
            segments: list[dict[str, Any]] = []
            for page_number, page in enumerate(reader.pages, start=1):
                text = page.extract_text(extraction_mode="plain") or ""
                if text.strip():
                    if (
                        sum(len(segment["text"]) for segment in segments) + len(text)
                        > MAX_EXTRACTED_DOCUMENT_CHARS
                    ):
                        raise DocumentIngestionError(
                            "PDF extracted text exceeds the document limit."
                        )
                    segments.append(
                        {"text": _normalize_text(text), "section": None, "page": page_number}
                    )
    except DocumentIngestionError:
        raise
    except Exception as exc:
        raise DocumentIngestionError("PDF could not be parsed safely.") from exc
    if not segments:
        raise DocumentIngestionError("PDF contains no extractable text.")
    return segments


def _apply_pdf_worker_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))


def _read_pdf(raw: bytes) -> list[dict[str, Any]]:
    if not raw.startswith(_PDF_HEADER):
        raise DocumentIngestionError("PDF signature is invalid.")
    try:
        response = subprocess.run(
            [sys.executable, "-m", "app.services.rag_ingestion", "--pdf-worker"],
            input=raw,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=PDF_WORKER_TIMEOUT_SECONDS,
            check=False,
            preexec_fn=_apply_pdf_worker_limits,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired, ValueError) as exc:
        raise DocumentIngestionError("PDF parsing exceeded local safety limits.") from exc
    if response.returncode != 0 or len(response.stdout) > 2 * MAX_EXTRACTED_DOCUMENT_CHARS:
        raise DocumentIngestionError("PDF could not be parsed within local safety limits.")
    try:
        value = json.loads(response.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DocumentIngestionError("PDF extraction returned invalid text data.") from exc
    if not isinstance(value, list) or not all(
        isinstance(segment, dict)
        and isinstance(segment.get("text"), str)
        and (segment.get("page") is None or isinstance(segment.get("page"), int))
        for segment in value
    ):
        raise DocumentIngestionError("PDF extraction returned invalid text data.")
    return value


def _safe_docx_segments(raw: bytes) -> list[dict[str, Any]]:
    try:
        with zipfile.ZipFile(__import__("io").BytesIO(raw)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_DOCX_ENTRIES:
                raise DocumentIngestionError("DOCX archive exceeds the entry limit.")
            total_expanded = 0
            names: set[str] = set()
            for info in infos:
                name = info.filename.replace("\\", "/")
                path = Path(name)
                mode = info.external_attr >> 16
                if (
                    name in names
                    or path.is_absolute()
                    or name.startswith("/")
                    or re.match(r"^[A-Za-z]:", name)
                    or ".." in path.parts
                    or stat.S_ISLNK(mode)
                    or info.flag_bits & 0x1
                ):
                    raise DocumentIngestionError("DOCX contains an unsafe archive entry.")
                names.add(name)
                total_expanded += info.file_size
                if total_expanded > MAX_DOCX_EXPANDED_BYTES:
                    raise DocumentIngestionError("DOCX expanded content exceeds the size limit.")
            info = archive.getinfo("word/document.xml")
            if info.file_size > MAX_DOCX_EXPANDED_BYTES:
                raise DocumentIngestionError("DOCX document content exceeds the size limit.")
            xml = archive.read(info)
        if b"<!DOCTYPE" in xml.upper() or b"<!ENTITY" in xml.upper():
            raise DocumentIngestionError("DOCX XML declarations are not supported.")
        root = ElementTree.fromstring(xml)
        namespace = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
        segments: list[dict[str, Any]] = []
        section: str | None = None
        for paragraph in root.iter(f"{namespace}p"):
            text = "".join(node.text or "" for node in paragraph.iter(f"{namespace}t"))
            style = paragraph.find(f"{namespace}pPr/{namespace}pStyle")
            if style is not None and str(
                style.attrib.get(f"{namespace}val", "")
            ).lower().startswith("heading"):
                if text.strip():
                    section = _normalize_text(text)[:300]
            if text.strip():
                segments.append({"text": _normalize_text(text), "section": section, "page": None})
    except DocumentIngestionError:
        raise
    except (OSError, KeyError, zipfile.BadZipFile, ElementTree.ParseError, RuntimeError) as exc:
        raise DocumentIngestionError("DOCX could not be parsed safely.") from exc
    if not segments:
        raise DocumentIngestionError("DOCX contains no extractable text.")
    return segments


def _extract(raw: bytes, extension: str) -> list[dict[str, Any]]:
    if extension == ".pdf":
        return _read_pdf(raw)
    if extension == ".docx":
        return _safe_docx_segments(raw)
    try:
        decoded = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise DocumentIngestionError("Text document must use UTF-8 encoding.") from exc
    if extension in {".html", ".htm"}:
        parser = _TextHTMLParser()
        parser.feed(decoded)
        parser.close()
        return _text_segments("".join(parser.parts))
    if extension in {".md", ".markdown"}:
        return _text_segments(decoded)
    return [{"text": _normalize_text(decoded), "section": None, "page": None}]


def _pdf_worker_main() -> int:
    raw = sys.stdin.buffer.read(settings.rag_max_ingest_file_bytes + 1)
    if len(raw) > settings.rag_max_ingest_file_bytes:
        return 2
    try:
        segments = _extract_pdf_segments(raw)
    except DocumentIngestionError:
        return 2
    sys.stdout.write(json.dumps(segments, ensure_ascii=True, separators=(",", ":")))
    return 0


def _is_sensitive(relative_path: Path) -> bool:
    return any(
        component.lower() in _SENSITIVE_COMPONENTS or _SENSITIVE_NAMES.search(component)
        for component in relative_path.parts
    )


def ingest_directory(
    directory: Path, *, source_category: str = "public_security_documentation"
) -> IngestionResult:
    """Extract supported documents without following links or reading outside `directory`."""
    if source_category not in SUPPORTED_CATEGORIES:
        raise DocumentIngestionError("Document category is unsupported.")
    if directory.is_symlink():
        raise DocumentIngestionError("Document root must not be a symbolic link.")
    try:
        root = directory.resolve(strict=True)
    except OSError as exc:
        raise DocumentIngestionError("Document root is unavailable.") from exc
    if not root.is_dir():
        raise DocumentIngestionError("Document root must be a directory.")

    paths: list[Path] = []
    excluded_sensitive_count = 0
    ignored_unsupported_count = 0
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        retained_dirs: list[str] = []
        for name in sorted(dirs):
            candidate = base / name
            relative = candidate.relative_to(root)
            if candidate.is_symlink():
                if _is_sensitive(relative):
                    continue
                raise DocumentIngestionError("Document tree contains a symbolic-link directory.")
            if not _is_sensitive(relative):
                retained_dirs.append(name)
        dirs[:] = retained_dirs
        for name in sorted(files):
            candidate = base / name
            relative = candidate.relative_to(root)
            if _is_sensitive(relative):
                excluded_sensitive_count += 1
                continue
            if candidate.suffix.lower() not in SUPPORTED_EXTENSIONS:
                ignored_unsupported_count += 1
                continue
            if candidate.is_symlink():
                raise DocumentIngestionError("Document tree contains a symbolic-link file.")
            paths.append(candidate)
    if len(paths) > settings.rag_max_ingest_files:
        raise DocumentIngestionError("Document tree exceeds the configured file-count limit.")

    documents: list[dict[str, Any]] = []
    excluded: list[str] = []
    seen_hashes: set[str] = set()
    total_bytes = 0
    for path in paths:
        relative = path.relative_to(root)
        try:
            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise DocumentIngestionError("Document tree contains a non-regular file.")
            if metadata.st_size > settings.rag_max_ingest_file_bytes:
                raise DocumentIngestionError("Document exceeds the per-file size limit.")
            total_bytes += metadata.st_size
            if total_bytes > MAX_TOTAL_BYTES:
                raise DocumentIngestionError("Document tree exceeds the total source size limit.")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or opened.st_size != metadata.st_size:
                    raise DocumentIngestionError("A document changed while it was being read.")
                with os.fdopen(descriptor, "rb", closefd=False) as source:
                    raw = source.read(settings.rag_max_ingest_file_bytes + 1)
            finally:
                os.close(descriptor)
        except DocumentIngestionError:
            raise
        except OSError as exc:
            raise DocumentIngestionError("A supported document could not be read.") from exc
        if len(raw) != metadata.st_size:
            raise DocumentIngestionError("A document changed while it was being read.")
        source_sha256 = hashlib.sha256(raw).hexdigest()
        if source_sha256 in seen_hashes:
            excluded.append(relative.as_posix())
            continue
        seen_hashes.add(source_sha256)
        segments = _extract(raw, path.suffix.lower())
        content = "\n\n".join(segment["text"] for segment in segments)
        if len(content) > settings.rag_index_max_chars:
            raise DocumentIngestionError("Extracted document text exceeds the configured limit.")
        document_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        documents.append(
            {
                "document_id": f"doc-{source_sha256}",
                "title": path.stem[:300],
                "source_type": source_category,
                "content": content,
                "source_location": relative.as_posix(),
                "source_url": "",
                "license": "Unspecified; verify license before redistribution.",
                "source_category": source_category,
                "original_filename": path.name,
                "source_identity": relative.as_posix(),
                "source_sha256": source_sha256,
                "document_sha256": document_sha256,
                "segments": segments,
            }
        )
    if not documents:
        raise DocumentIngestionError("No supported, readable documents were found.")
    return IngestionResult(
        documents,
        tuple(excluded),
        excluded_sensitive_count,
        ignored_unsupported_count,
        len(excluded),
        total_bytes,
    )


if __name__ == "__main__" and sys.argv[1:] == ["--pdf-worker"]:
    raise SystemExit(_pdf_worker_main())
