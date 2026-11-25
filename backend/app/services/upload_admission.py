"""PostgreSQL-backed upload reservations shared across API replicas."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.core.config import settings
from app.db.models import CoordinationLock
from app.db.models import UploadReservation as UploadReservationRecord
from app.db.session import SessionLocal
from sqlalchemy import delete, func, select
from sqlalchemy.exc import SQLAlchemyError


class AdmissionUnavailable(RuntimeError):
    """Shared admission storage could not safely make a reservation decision."""


@dataclass
class UploadReservation:
    _admission: UploadAdmission
    _reservation_id: uuid.UUID
    _released: bool = False

    def release(self) -> None:
        self._admission.release(self)


class UploadAdmission:
    """Atomic, expiring global and per-client admission for multipart uploads."""

    def __init__(
        self,
        max_global: int | None = None,
        max_per_client: int | None = None,
    ) -> None:
        self.max_global = settings.max_concurrent_uploads if max_global is None else max_global
        self.max_per_client = (
            settings.max_concurrent_uploads_per_client if max_per_client is None else max_per_client
        )

    def try_reserve(self, client_id: str) -> UploadReservation | None:
        reservation_id = uuid.uuid4()
        try:
            with SessionLocal() as db:
                lock = db.scalar(
                    select(CoordinationLock)
                    .where(CoordinationLock.lock_name == "scan-admission")
                    .with_for_update()
                )
                if lock is None:
                    raise AdmissionUnavailable("Shared admission migration is not installed.")
                db.execute(
                    delete(UploadReservationRecord).where(
                        UploadReservationRecord.expires_at <= func.now()
                    )
                )
                active_total = int(
                    db.scalar(select(func.count()).select_from(UploadReservationRecord)) or 0
                )
                active_client = int(
                    db.scalar(
                        select(func.count())
                        .select_from(UploadReservationRecord)
                        .where(UploadReservationRecord.client_id == client_id)
                    )
                    or 0
                )
                if active_total >= self.max_global or active_client >= self.max_per_client:
                    db.rollback()
                    return None
                db.add(
                    UploadReservationRecord(
                        id=reservation_id,
                        client_id=client_id,
                        expires_at=func.now()
                        + func.make_interval(
                            0, 0, 0, 0, 0, 0, settings.upload_reservation_ttl_seconds
                        ),
                    )
                )
                db.commit()
        except AdmissionUnavailable:
            raise
        except SQLAlchemyError as exc:
            raise AdmissionUnavailable("Shared upload admission is unavailable.") from exc
        return UploadReservation(self, reservation_id)

    def release(self, reservation: UploadReservation) -> None:
        if reservation._released:
            return
        reservation._released = True
        try:
            with SessionLocal() as db:
                db.execute(
                    delete(UploadReservationRecord).where(
                        UploadReservationRecord.id == reservation._reservation_id
                    )
                )
                db.commit()
        except SQLAlchemyError as exc:
            raise AdmissionUnavailable("Shared upload reservation could not be released.") from exc

    def active_counts(self) -> tuple[int, dict[str, int]]:
        """Expose current shared reservation counts for operational checks and tests."""
        try:
            with SessionLocal() as db:
                db.execute(
                    delete(UploadReservationRecord).where(
                        UploadReservationRecord.expires_at <= func.now()
                    )
                )
                rows = db.execute(
                    select(UploadReservationRecord.client_id, func.count()).group_by(
                        UploadReservationRecord.client_id
                    )
                ).all()
                db.commit()
            by_client = {str(client_id): int(count) for client_id, count in rows}
            return sum(by_client.values()), by_client
        except SQLAlchemyError as exc:
            raise AdmissionUnavailable("Shared upload admission is unavailable.") from exc


upload_admission = UploadAdmission()
