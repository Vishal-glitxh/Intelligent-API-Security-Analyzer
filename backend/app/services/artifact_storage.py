"""Shared durable storage for scan upload artifacts."""

from __future__ import annotations

import importlib
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Protocol, cast

from app.core.config import settings

_ARTIFACT_KEY = re.compile(r"^scans/[0-9a-f-]{36}/(?:spec|source)$")


class ArtifactStorage(Protocol):
    def put(self, key: str, content: bytes, content_type: str) -> None: ...

    def get(self, key: str, *, max_bytes: int) -> bytes: ...

    def delete(self, key: str) -> None: ...


def validate_artifact_key(key: str) -> None:
    if not _ARTIFACT_KEY.fullmatch(key):
        raise ValueError("Invalid scan artifact key.")


class LocalArtifactStorage:
    """Private local storage for development and single-instance operation."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)

    def _path(self, key: str) -> Path:
        validate_artifact_key(key)
        path = self.root.joinpath(*key.split("/"))
        if path.parent.resolve() != path.parent or self.root not in path.parents:
            raise ValueError("Invalid scan artifact path.")
        return path

    def put(self, key: str, content: bytes, content_type: str) -> None:
        del content_type
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".upload-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as target:
                os.fchmod(target.fileno(), 0o600)
                target.write(content)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary_name, path)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise

    def get(self, key: str, *, max_bytes: int) -> bytes:
        path = self._path(key)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
                raise ValueError("Stored scan artifact is invalid or exceeds the size limit.")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                content = source.read(max_bytes + 1)
        finally:
            os.close(descriptor)
        if len(content) > max_bytes:
            raise ValueError("Stored scan artifact exceeds the size limit.")
        return content

    def delete(self, key: str) -> None:
        try:
            self._path(key).unlink(missing_ok=True)
        except OSError:
            # A missing local artifact is already clean; other storage errors surface.
            if self._path(key).exists():
                raise


class S3ArtifactStorage:
    """S3-compatible object storage using the runtime's standard credential chain."""

    def __init__(
        self,
        *,
        bucket: str,
        prefix: str = "",
        endpoint_url: str | None = None,
        region_name: str | None = None,
        client: Any | None = None,
    ) -> None:
        if not bucket:
            raise ValueError("Artifact storage bucket must be configured.")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        if client is None:
            boto3 = importlib.import_module("boto3")
            client = boto3.client(
                "s3",
                endpoint_url=endpoint_url,
                region_name=region_name or None,
            )
        self.client = client

    def _key(self, key: str) -> str:
        validate_artifact_key(key)
        return f"{self.prefix}/{key}" if self.prefix else key

    def put(self, key: str, content: bytes, content_type: str) -> None:
        self.client.put_object(
            Bucket=self.bucket,
            Key=self._key(key),
            Body=content,
            ContentType=content_type,
            ServerSideEncryption="AES256",
        )

    def get(self, key: str, *, max_bytes: int) -> bytes:
        response = self.client.get_object(Bucket=self.bucket, Key=self._key(key))
        body = response["Body"]
        try:
            if int(response.get("ContentLength", 0)) > max_bytes:
                raise ValueError("Stored scan artifact exceeds the size limit.")
            content = cast(bytes, body.read(max_bytes + 1))
        finally:
            body.close()
        if len(content) > max_bytes:
            raise ValueError("Stored scan artifact exceeds the size limit.")
        return content

    def delete(self, key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=self._key(key))


def get_artifact_storage() -> ArtifactStorage:
    backend = settings.artifact_storage_backend
    if backend == "local":
        return LocalArtifactStorage(Path(settings.artifact_storage_local_path))
    if backend == "s3":
        return S3ArtifactStorage(
            bucket=settings.artifact_storage_bucket,
            prefix=settings.artifact_storage_prefix,
            endpoint_url=settings.artifact_storage_endpoint_url or None,
            region_name=settings.artifact_storage_region or None,
        )
    raise ValueError("Unsupported artifact storage backend.")
