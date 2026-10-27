"""Process-local, bounded admission for authenticated in-flight scan uploads."""

from __future__ import annotations

from threading import Lock

from app.core.config import settings


class UploadReservation:
    def __init__(self, admission: UploadAdmission, client_id: str) -> None:
        self._admission = admission
        self._client_id = client_id
        self._released = False

    def release(self) -> None:
        self._admission.release(self)


class UploadAdmission:
    """Non-blocking global and per-client upload slots, counting active clients only."""

    def __init__(
        self,
        max_global: int | None = None,
        max_per_client: int | None = None,
    ) -> None:
        self.max_global = settings.max_concurrent_uploads if max_global is None else max_global
        self.max_per_client = (
            settings.max_concurrent_uploads_per_client if max_per_client is None else max_per_client
        )
        self._lock = Lock()
        self._global_count = 0
        self._client_counts: dict[str, int] = {}

    def try_reserve(self, client_id: str) -> UploadReservation | None:
        with self._lock:
            if self._global_count >= self.max_global:
                return None
            if self._client_counts.get(client_id, 0) >= self.max_per_client:
                return None
            self._global_count += 1
            self._client_counts[client_id] = self._client_counts.get(client_id, 0) + 1
        return UploadReservation(self, client_id)

    def release(self, reservation: UploadReservation) -> None:
        with self._lock:
            if reservation._released:
                return
            reservation._released = True
            self._global_count -= 1
            remaining = self._client_counts[reservation._client_id] - 1
            if remaining:
                self._client_counts[reservation._client_id] = remaining
            else:
                del self._client_counts[reservation._client_id]

    def active_counts(self) -> tuple[int, dict[str, int]]:
        with self._lock:
            return self._global_count, dict(self._client_counts)


upload_admission = UploadAdmission()
