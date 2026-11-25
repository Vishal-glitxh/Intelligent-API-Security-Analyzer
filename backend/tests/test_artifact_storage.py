from pathlib import Path
from unittest.mock import Mock

import pytest
from app.services.artifact_storage import LocalArtifactStorage, S3ArtifactStorage


def test_local_artifact_storage_round_trip_and_private_modes(tmp_path: Path) -> None:
    storage = LocalArtifactStorage(tmp_path / "private")
    key = "scans/123e4567-e89b-12d3-a456-426614174000/spec"
    storage.put(key, b"openapi: 3.0.3", "application/yaml")
    assert storage.get(key, max_bytes=64) == b"openapi: 3.0.3"
    storage.delete(key)
    with pytest.raises(FileNotFoundError):
        storage.get(key, max_bytes=64)
    assert (tmp_path / "private").stat().st_mode & 0o777 == 0o700


def test_artifact_storage_rejects_untrusted_keys_and_oversized_objects(tmp_path: Path) -> None:
    storage = LocalArtifactStorage(tmp_path / "private")
    with pytest.raises(ValueError, match="Invalid scan artifact key"):
        storage.put("scans/../../outside/spec", b"x", "text/plain")
    key = "scans/123e4567-e89b-12d3-a456-426614174000/spec"
    storage.put(key, b"too big", "text/plain")
    with pytest.raises(ValueError, match="exceeds the size limit"):
        storage.get(key, max_bytes=2)


def test_s3_adapter_uses_generated_key_prefix_and_bounded_reads() -> None:
    client = Mock()
    storage = S3ArtifactStorage(bucket="private-bucket", prefix="prod/iasa", client=client)
    key = "scans/123e4567-e89b-12d3-a456-426614174000/spec"
    storage.put(key, b"spec", "application/yaml")
    client.put_object.assert_called_once_with(
        Bucket="private-bucket",
        Key=f"prod/iasa/{key}",
        Body=b"spec",
        ContentType="application/yaml",
        ServerSideEncryption="AES256",
    )
    client.get_object.return_value = {
        "ContentLength": 4,
        "Body": Mock(read=Mock(return_value=b"spec")),
    }
    assert storage.get(key, max_bytes=4) == b"spec"
    storage.delete(key)
    client.delete_object.assert_called_once_with(Bucket="private-bucket", Key=f"prod/iasa/{key}")
