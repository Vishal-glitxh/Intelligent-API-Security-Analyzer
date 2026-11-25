import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from app.core.config import settings
from app.db.models import Scan
from app.db.session import SessionLocal
from app.repositories.scan import ScanCapacityError, ScanRepository
from app.services.upload_admission import UploadAdmission


def _enqueue(repository: ScanRepository, scan_id: uuid.UUID, *, max_active: int = 100) -> Scan:
    return repository.enqueue_scan(
        scan_id=scan_id,
        project_name="coordination test",
        spec_filename="openapi.yaml",
        source_filename="Not provided",
        spec_hash="a" * 64,
        source_hash=None,
        client_id=f"tenant-{scan_id}",
        spec_artifact_key=f"scans/{scan_id}/spec",
        source_artifact_key=None,
        spec_content_type="application/yaml",
        source_content_type=None,
        max_active=max_active,
        max_per_client=100,
    )


def test_concurrent_replicas_share_scan_capacity() -> None:
    scan_ids = [uuid4(), uuid4()]
    with SessionLocal() as db:
        max_active = ScanRepository(db).count_active_scans() + 1

    def enqueue(scan_id: uuid.UUID) -> str:
        with SessionLocal() as db:
            try:
                _enqueue(ScanRepository(db), scan_id, max_active=max_active)
                return "queued"
            except ScanCapacityError:
                return "full"

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(enqueue, scan_ids))
        assert sorted(results) == ["full", "queued"]
    finally:
        with SessionLocal() as db:
            db.query(Scan).filter(Scan.id.in_(scan_ids)).delete(synchronize_session=False)
            db.commit()


def test_expired_job_lease_is_reclaimed_and_stale_worker_is_fenced() -> None:
    scan_id = uuid4()
    first_token = None
    second_token = None
    try:
        with SessionLocal() as db:
            _enqueue(ScanRepository(db), scan_id)
        with SessionLocal() as db:
            first = ScanRepository(db).claim_next_scan(
                worker_id="replica-a", lease_seconds=30, max_attempts=2
            )
        assert first is not None and first.scan_id == scan_id
        first_token = first.lease_token
        assert first_token is not None

        with SessionLocal() as db:
            assert (
                ScanRepository(db).claim_next_scan(
                    worker_id="replica-b", lease_seconds=30, max_attempts=2
                )
                is None
            )
            scan = db.get(Scan, scan_id)
            assert scan is not None
            scan.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
            db.commit()

        with SessionLocal() as db:
            second = ScanRepository(db).claim_next_scan(
                worker_id="replica-b", lease_seconds=30, max_attempts=2
            )
        assert second is not None
        second_token = second.lease_token
        assert second_token is not None
        assert second_token != first_token

        with SessionLocal() as db:
            assert (
                ScanRepository(db).fail_claimed_scan(
                    scan_id, first_token, "stale attempt must not persist"
                )
                is False
            )
        with SessionLocal() as db:
            assert (
                ScanRepository(db).fail_claimed_scan(scan_id, second_token, "test terminal failure")
                is True
            )
            scan = db.get(Scan, scan_id)
            assert scan is not None and scan.status == "FAILED"
            assert scan.lease_token is None
    finally:
        with SessionLocal() as db:
            db.query(Scan).filter(Scan.id == scan_id).delete(synchronize_session=False)
            db.commit()


def test_upload_admission_is_shared_between_instances(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "max_concurrent_uploads", 2)
    monkeypatch.setattr(settings, "max_concurrent_uploads_per_client", 1)
    one = UploadAdmission()
    two = UploadAdmission()
    first = one.try_reserve("coordination-test-client")
    assert first is not None
    try:
        assert two.try_reserve("coordination-test-client") is None
        other = two.try_reserve("other-coordination-client")
        assert other is not None
        try:
            assert one.active_counts() == (
                2,
                {
                    "coordination-test-client": 1,
                    "other-coordination-client": 1,
                },
            )
        finally:
            other.release()
    finally:
        first.release()
    assert one.active_counts() == (0, {})
