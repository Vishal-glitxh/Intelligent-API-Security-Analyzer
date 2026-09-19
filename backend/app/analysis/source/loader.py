import hashlib
from dataclasses import dataclass
from pathlib import Path

from app.analysis.context import SourceDiagnostic
from app.core.exceptions import InvalidInputError

# Defensive resource ceilings
DEFAULT_MAX_FILE_SIZE = 1_048_576  # 1 MB
DEFAULT_MAX_FILE_COUNT = 500
DEFAULT_MAX_TOTAL_SIZE = 10_485_760  # 10 MB

_EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
}


class SourceLoadingError(InvalidInputError):
    """Raised when source loading exceeds safety boundaries or cannot read critical inputs."""


@dataclass(frozen=True)
class LoadedSourceFile:
    """Raw loaded source file with relative path, text content, and SHA-256 hash."""

    relative_path: str
    content: str
    content_hash: str
    size_bytes: int


@dataclass(frozen=True)
class LoadedSourceTree:
    """Collection of loaded source files with deterministic tree hash and diagnostics."""

    files: tuple[LoadedSourceFile, ...]
    tree_hash: str
    diagnostics: tuple[SourceDiagnostic, ...]
    root_path: str


def compute_sha256(data: bytes | str) -> str:
    """Compute standard SHA-256 hex digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_tree_hash(loaded_files: tuple[LoadedSourceFile, ...]) -> str:
    """Compute aggregate tree hash from sorted file paths and individual content hashes."""
    hasher = hashlib.sha256()
    for f in loaded_files:
        entry = f"{f.relative_path}:{f.content_hash}\n"
        hasher.update(entry.encode("utf-8"))
    return hasher.hexdigest()


def load_source_from_memory(
    files: dict[str, str],
    root_path: str = "in-memory",
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_file_count: int = DEFAULT_MAX_FILE_COUNT,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
) -> LoadedSourceTree:
    """Safely loads Python source files provided in-memory with defensive limits."""
    if len(files) > max_file_count:
        raise SourceLoadingError(
            f"File count ({len(files)}) exceeds maximum allowed ({max_file_count})."
        )

    loaded_files: list[LoadedSourceFile] = []
    diagnostics: list[SourceDiagnostic] = []
    total_size = 0

    # Deterministic sorting by relative path
    for rel_path in sorted(files.keys()):
        if not rel_path.endswith(".py"):
            continue

        raw_content = files[rel_path]
        size_bytes = len(raw_content.encode("utf-8"))
        total_size += size_bytes

        if size_bytes > max_file_size:
            diagnostics.append(
                SourceDiagnostic(
                    file_path=rel_path,
                    message=(
                        f"File size ({size_bytes} B) exceeds maximum limit "
                        f"({max_file_size} B). Skipping."
                    ),
                    severity="warning",
                )
            )
            continue

        if total_size > max_total_size:
            raise SourceLoadingError(
                f"Total source size ({total_size} B) exceeds limit ({max_total_size} B)."
            )

        f_hash = compute_sha256(raw_content)
        loaded_files.append(
            LoadedSourceFile(
                relative_path=rel_path,
                content=raw_content,
                content_hash=f_hash,
                size_bytes=size_bytes,
            )
        )

    files_tuple = tuple(loaded_files)
    tree_hash = compute_tree_hash(files_tuple)
    return LoadedSourceTree(
        files=files_tuple,
        tree_hash=tree_hash,
        diagnostics=tuple(diagnostics),
        root_path=root_path,
    )


def load_source_from_disk(
    directory_path: str | Path,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_file_count: int = DEFAULT_MAX_FILE_COUNT,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
) -> LoadedSourceTree:
    """Safely scans a directory on disk, reading only .py files without execution."""
    root = Path(directory_path).resolve()
    if not root.exists() or not root.is_dir():
        raise SourceLoadingError(f"Target directory does not exist or is not a directory: {root}")

    py_paths: list[Path] = []
    for path in root.rglob("*.py"):
        if any(part in _EXCLUDED_DIRS for part in path.parts):
            continue
        py_paths.append(path)

    if len(py_paths) > max_file_count:
        raise SourceLoadingError(
            f"Directory contains {len(py_paths)} Python files, exceeding limit ({max_file_count})."
        )

    # Sort paths deterministically
    py_paths.sort(key=lambda p: str(p.relative_to(root)))

    loaded_files: list[LoadedSourceFile] = []
    diagnostics: list[SourceDiagnostic] = []
    total_size = 0

    for path in py_paths:
        rel_path = str(path.relative_to(root))
        try:
            stat = path.stat()
            file_size = stat.st_size
            total_size += file_size

            if file_size > max_file_size:
                diagnostics.append(
                    SourceDiagnostic(
                        file_path=rel_path,
                        message=(
                            f"File size ({file_size} B) exceeds maximum limit "
                            f"({max_file_size} B). Skipping."
                        ),
                        severity="warning",
                    )
                )
                continue

            if total_size > max_total_size:
                raise SourceLoadingError(
                    f"Aggregate source size ({total_size} B) exceeds limit ({max_total_size} B)."
                )

            raw_bytes = path.read_bytes()
            try:
                content = raw_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                diagnostics.append(
                    SourceDiagnostic(
                        file_path=rel_path,
                        message=f"UTF-8 decoding failed: {exc}. File skipped.",
                        severity="warning",
                    )
                )
                continue

            content_hash = compute_sha256(raw_bytes)
            loaded_files.append(
                LoadedSourceFile(
                    relative_path=rel_path,
                    content=content,
                    content_hash=content_hash,
                    size_bytes=file_size,
                )
            )
        except OSError as exc:
            diagnostics.append(
                SourceDiagnostic(
                    file_path=rel_path,
                    message=f"I/O error reading file: {exc}. File skipped.",
                    severity="error",
                )
            )

    files_tuple = tuple(loaded_files)
    tree_hash = compute_tree_hash(files_tuple)
    return LoadedSourceTree(
        files=files_tuple,
        tree_hash=tree_hash,
        diagnostics=tuple(diagnostics),
        root_path=str(root),
    )
