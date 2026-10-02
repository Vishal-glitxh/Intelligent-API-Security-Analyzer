import os
import zipfile
from pathlib import Path

from app.core.config import settings

ALLOWED_SPEC_EXTENSIONS = {".yaml", ".yml", ".json"}
ALLOWED_ARCHIVE_EXTENSIONS = {".zip"}

_DECOMPRESSION_CHUNK_BYTES = 64 * 1024


def validate_spec_upload(
    filename: str,
    content_bytes: bytes,
    max_size_bytes: int | None = None,
) -> None:
    """Validate spec file size and extension against authoritative configuration."""
    limit = max_size_bytes if max_size_bytes is not None else settings.max_spec_bytes
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_SPEC_EXTENSIONS:
        raise ValueError(
            f"UNTRUSTED_ARCHIVE_REJECTED: Invalid spec extension '{ext}'. "
            f"Must be one of {ALLOWED_SPEC_EXTENSIONS}"
        )
    if len(content_bytes) > limit:
        raise ValueError(
            f"UNTRUSTED_ARCHIVE_REJECTED: OpenAPI spec size ({len(content_bytes)} B) "
            f"exceeds maximum limit of {limit} B."
        )


def validate_source_archive_filename(filename: str) -> None:
    """Reject source uploads whose declared format is not explicitly supported."""
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_ARCHIVE_EXTENSIONS:
        raise ValueError(
            f"UNTRUSTED_ARCHIVE_REJECTED: Invalid source archive extension '{ext}'. "
            f"Must be one of {ALLOWED_ARCHIVE_EXTENSIONS}"
        )


def extract_source_archive(
    archive_bytes: bytes,
    dest_dir: Path,
    max_archive_size_bytes: int | None = None,
    max_uncompressed_total_bytes: int | None = None,
    max_file_count: int | None = None,
    max_individual_file_bytes: int | None = None,
) -> int:
    """Safely extract ZIP archive enforcing Zip Slip prevention, size, and file count limits."""
    max_archive = (
        max_archive_size_bytes if max_archive_size_bytes is not None else settings.max_archive_bytes
    )
    max_uncompressed = (
        max_uncompressed_total_bytes
        if max_uncompressed_total_bytes is not None
        else settings.max_uncompressed_bytes
    )
    max_files = max_file_count if max_file_count is not None else settings.max_files_per_scan
    max_single_file = (
        max_individual_file_bytes
        if max_individual_file_bytes is not None
        else settings.max_individual_file_bytes
    )

    if len(archive_bytes) > max_archive:
        raise ValueError(
            f"UNTRUSTED_ARCHIVE_REJECTED: Source archive size ({len(archive_bytes)} B) "
            f"exceeds maximum allowed size of {max_archive} B."
        )

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_dir_resolved = dest_dir.resolve()
    temp_zip_path = dest_dir / "_source.zip"

    with open(temp_zip_path, "wb") as f:
        f.write(archive_bytes)

    try:
        if not zipfile.is_zipfile(temp_zip_path):
            raise ValueError(
                "UNTRUSTED_ARCHIVE_REJECTED: Provided file is not a valid ZIP archive."
            )

        with zipfile.ZipFile(temp_zip_path, "r") as zf:
            infolist = zf.infolist()

            if len(infolist) > max_files:
                raise ValueError(
                    f"UNTRUSTED_ARCHIVE_REJECTED: Archive file count ({len(infolist)}) "
                    f"exceeds maximum limit of {max_files} files."
                )

            total_uncompressed_bytes = 0
            actual_total_uncompressed = 0

            for member in infolist:
                mode = member.external_attr >> 16
                if mode & 0o120000 == 0o120000:
                    raise ValueError(
                        f"UNTRUSTED_ARCHIVE_REJECTED: Symlink detected in '{member.filename}'."
                    )

                # Header-level preliminary check
                if member.file_size > max_single_file:
                    raise ValueError(
                        f"UNTRUSTED_ARCHIVE_REJECTED: Individual file '{member.filename}' "
                        f"exceeds limit of {max_single_file} B."
                    )

                total_uncompressed_bytes += member.file_size
                if total_uncompressed_bytes > max_uncompressed:
                    raise ValueError(
                        f"UNTRUSTED_ARCHIVE_REJECTED: Cumulative uncompressed archive size "
                        f"exceeds maximum limit of {max_uncompressed} B."
                    )

                # Zip Slip Prevention Check
                target_path = (dest_dir / member.filename).resolve()
                try:
                    target_path.relative_to(dest_dir_resolved)
                except ValueError as exc:
                    raise ValueError(
                        f"UNTRUSTED_ARCHIVE_REJECTED: Zip Slip attempt detected in member "
                        f"'{member.filename}'."
                    ) from exc

                # Safe extraction with chunked decompression guarding against decompression bombs
                if member.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                else:
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    member_extracted_bytes = 0
                    with zf.open(member) as source, open(target_path, "wb") as target:
                        while chunk := source.read(_DECOMPRESSION_CHUNK_BYTES):
                            member_extracted_bytes += len(chunk)
                            actual_total_uncompressed += len(chunk)
                            if member_extracted_bytes > max_single_file:
                                msg = (
                                    "UNTRUSTED_ARCHIVE_REJECTED: Individual file "
                                    f"'{member.filename}' exceeds limit of {max_single_file} B."
                                )
                                raise ValueError(msg)
                            if actual_total_uncompressed > max_uncompressed:
                                raise ValueError(
                                    "UNTRUSTED_ARCHIVE_REJECTED: Cumulative uncompressed archive "
                                    f"size exceeds maximum limit of {max_uncompressed} B."
                                )
                            target.write(chunk)

            return len(infolist)
    finally:
        if temp_zip_path.exists():
            try:
                os.remove(temp_zip_path)
            except OSError:
                pass
