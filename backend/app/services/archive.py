import os
import zipfile
from pathlib import Path

MAX_SPEC_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_ARCHIVE_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB
MAX_UNCOMPRESSED_TOTAL_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_FILE_COUNT = 2000
MAX_INDIVIDUAL_FILE_BYTES = 1 * 1024 * 1024  # 1 MB

ALLOWED_SPEC_EXTENSIONS = {".yaml", ".yml", ".json"}
ALLOWED_ARCHIVE_EXTENSIONS = {".zip"}


def validate_spec_upload(filename: str, content_bytes: bytes) -> None:
    """Validate spec file size and extension."""
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_SPEC_EXTENSIONS:
        raise ValueError(
            f"UNTRUSTED_ARCHIVE_REJECTED: Invalid spec extension '{ext}'. "
            f"Must be one of {ALLOWED_SPEC_EXTENSIONS}"
        )
    if len(content_bytes) > MAX_SPEC_SIZE_BYTES:
        raise ValueError(
            f"UNTRUSTED_ARCHIVE_REJECTED: OpenAPI spec size ({len(content_bytes)} B) "
            f"exceeds maximum limit of {MAX_SPEC_SIZE_BYTES} B (5 MB)."
        )


def extract_source_archive(archive_bytes: bytes, dest_dir: Path) -> int:
    """Safely extract ZIP archive enforcing Zip Slip prevention, size, and file count limits."""
    if len(archive_bytes) > MAX_ARCHIVE_SIZE_BYTES:
        raise ValueError(
            f"UNTRUSTED_ARCHIVE_REJECTED: Source archive size ({len(archive_bytes)} B) "
            f"exceeds maximum allowed size of {MAX_ARCHIVE_SIZE_BYTES} B (25 MB)."
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

            if len(infolist) > MAX_FILE_COUNT:
                raise ValueError(
                    f"UNTRUSTED_ARCHIVE_REJECTED: Archive file count ({len(infolist)}) "
                    f"exceeds maximum limit of {MAX_FILE_COUNT} files."
                )

            total_uncompressed_bytes = 0

            for member in infolist:
                mode = member.external_attr >> 16
                if mode & 0o120000 == 0o120000:
                    raise ValueError(
                        f"UNTRUSTED_ARCHIVE_REJECTED: Symlink detected in "
                        f"entry '{member.filename}'."
                    )

                if member.file_size > MAX_INDIVIDUAL_FILE_BYTES:
                    raise ValueError(
                        f"UNTRUSTED_ARCHIVE_REJECTED: Individual file '{member.filename}' "
                        f"exceeds limit of {MAX_INDIVIDUAL_FILE_BYTES} B (1 MB)."
                    )

                total_uncompressed_bytes += member.file_size
                if total_uncompressed_bytes > MAX_UNCOMPRESSED_TOTAL_BYTES:
                    raise ValueError(
                        f"UNTRUSTED_ARCHIVE_REJECTED: Cumulative uncompressed archive size "
                        f"exceeds maximum limit of {MAX_UNCOMPRESSED_TOTAL_BYTES} B (50 MB)."
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

                # Safe extraction
                if member.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                else:
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as source, open(target_path, "wb") as target:
                        target.write(source.read())

            return len(infolist)
    finally:
        if temp_zip_path.exists():
            try:
                os.remove(temp_zip_path)
            except OSError:
                pass
