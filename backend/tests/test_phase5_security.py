import io
import zipfile
from pathlib import Path

import pytest
from app.main import app
from app.services.analysis_worker import sanitize_error_message
from app.services.archive import extract_source_archive, validate_spec_upload
from fastapi.testclient import TestClient

client = TestClient(app)


def test_zip_slip_rejection(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../../evil.py", "print('hacked')")
    zip_bytes = buf.getvalue()

    with pytest.raises(ValueError, match="UNTRUSTED_ARCHIVE_REJECTED: Zip Slip attempt detected"):
        extract_source_archive(zip_bytes, tmp_path)


def test_oversized_archive_rejection(tmp_path: Path) -> None:
    large_bytes = b"0" * (25 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="UNTRUSTED_ARCHIVE_REJECTED: Source archive size"):
        extract_source_archive(large_bytes, tmp_path)


def test_file_count_exceeded_rejection(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(2001):
            zf.writestr(f"file_{i}.py", "x=1")
    zip_bytes = buf.getvalue()

    with pytest.raises(ValueError, match="UNTRUSTED_ARCHIVE_REJECTED: Archive file count"):
        extract_source_archive(zip_bytes, tmp_path)


def test_individual_file_size_exceeded_rejection(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("large.py", "x" * (1 * 1024 * 1024 + 1))
    zip_bytes = buf.getvalue()

    with pytest.raises(ValueError, match="UNTRUSTED_ARCHIVE_REJECTED: Individual file"):
        extract_source_archive(zip_bytes, tmp_path)


def test_spec_file_size_exceeded_rejection() -> None:
    large_spec = b"openapi: 3.0.0\n" + b" " * (5 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="UNTRUSTED_ARCHIVE_REJECTED: OpenAPI spec size"):
        validate_spec_upload("openapi.yaml", large_spec)


def test_invalid_spec_extension_rejection() -> None:
    with pytest.raises(ValueError, match="UNTRUSTED_ARCHIVE_REJECTED: Invalid spec extension"):
        validate_spec_upload("openapi.exe", b"data")


def test_symlink_rejection(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("symlink_entry")
        # 0o120000 is file mode for symlink
        info.external_attr = 0o120755 << 16
        zf.writestr(info, "target_file")
    zip_bytes = buf.getvalue()

    with pytest.raises(ValueError, match="UNTRUSTED_ARCHIVE_REJECTED: Symlink detected"):
        extract_source_archive(zip_bytes, tmp_path)


def test_uncompressed_size_exceeded_rejection(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # 51 MB of uncompressed zeros compresses down very small
        one_mb_zeros = b"0" * (1024 * 1024)
        for i in range(51):
            zf.writestr(f"file_{i}.txt", one_mb_zeros)
    zip_bytes = buf.getvalue()

    match_str = "UNTRUSTED_ARCHIVE_REJECTED: Cumulative uncompressed archive size"
    with pytest.raises(ValueError, match=match_str):
        extract_source_archive(zip_bytes, tmp_path)


def test_error_message_sanitization() -> None:
    raw_path_err = Exception("Failed at /Users/vishalsuhas/Documents/secret/code.py line 45")
    sanitized = sanitize_error_message(raw_path_err, "SOURCE_ANALYSIS_ERROR")

    assert "/Users/vishalsuhas" not in sanitized
    assert "<sanitized_path>" in sanitized
    assert sanitized.startswith("SOURCE_ANALYSIS_ERROR:")
