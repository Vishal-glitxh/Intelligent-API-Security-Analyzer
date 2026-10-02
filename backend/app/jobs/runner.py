from abc import ABC, abstractmethod
from collections.abc import Callable
from concurrent.futures import Future, ProcessPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, TypeVar

T = TypeVar("T")
R = TypeVar("R")


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class JobResult[R]:
    """Represents the outcome of a job execution."""

    job_id: str
    status: JobStatus
    result: R | None = None
    error: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


def _apply_memory_limit(max_memory_bytes: int | None) -> None:
    """Apply a best-effort address-space ceiling in the isolated child process.

    ``resource`` is only available on POSIX systems.  The application timeout remains the
    cross-platform CPU bound; production container limits should be configured as a second
    enforcement layer.
    """
    if max_memory_bytes is None:
        return
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        target_hard = hard if hard != resource.RLIM_INFINITY else max_memory_bytes
        target_soft = min(max_memory_bytes, target_hard)
        resource.setrlimit(resource.RLIMIT_AS, (target_soft, target_hard))
    except ImportError, OSError, ValueError:
        # Unsupported platforms and hosts with restrictive ulimit policies still retain the
        # parent-side timeout and deployment-level container limits.
        return


def _process_worker_entrypoint(
    job_id: str,
    func: Callable[[Any], Any],
    input_data: Any,
    max_memory_bytes: int | None,
) -> JobResult[Any]:
    """Top-level picklable entrypoint executed inside the worker process."""
    started_at = datetime.now(UTC)
    try:
        _apply_memory_limit(max_memory_bytes)
        output = func(input_data)
        completed_at = datetime.now(UTC)
        return JobResult(
            job_id=job_id,
            status=JobStatus.COMPLETED,
            result=output,
            started_at=started_at,
            completed_at=completed_at,
        )
    except Exception as exc:
        completed_at = datetime.now(UTC)
        return JobResult(
            job_id=job_id,
            status=JobStatus.FAILED,
            error=str(exc),
            started_at=started_at,
            completed_at=completed_at,
        )


class JobRunner(ABC):
    """Abstract boundary for executing CPU-bound or background analysis jobs."""

    @abstractmethod
    def submit(
        self,
        job_id: str,
        func: Callable[[Any], Any],
        input_data: Any,
    ) -> Future[JobResult[Any]]:
        """Submit a job for execution."""
        raise NotImplementedError

    @abstractmethod
    def run(
        self,
        job_id: str,
        func: Callable[[Any], Any],
        input_data: Any,
        timeout: float | None = None,
    ) -> JobResult[Any]:
        """Synchronously execute and wait for job completion."""
        raise NotImplementedError


class LocalProcessJobRunner(JobRunner):
    """Executes CPU-bound analysis jobs in isolated OS processes using a process pool."""

    def __init__(self, max_workers: int = 2, max_memory_bytes: int | None = None) -> None:
        self._executor = ProcessPoolExecutor(max_workers=max_workers)
        self._max_memory_bytes = max_memory_bytes

    def submit(
        self,
        job_id: str,
        func: Callable[[Any], Any],
        input_data: Any,
    ) -> Future[JobResult[Any]]:
        return self._executor.submit(
            _process_worker_entrypoint,
            job_id,
            func,
            input_data,
            self._max_memory_bytes,
        )

    def run(
        self,
        job_id: str,
        func: Callable[[Any], Any],
        input_data: Any,
        timeout: float | None = None,
    ) -> JobResult[Any]:
        future = self.submit(job_id, func, input_data)
        try:
            return future.result(timeout=timeout)
        except Exception as exc:
            return JobResult(
                job_id=job_id,
                status=JobStatus.FAILED,
                error=str(exc),
                completed_at=datetime.now(UTC),
            )

    def shutdown(self, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait)


class QueueJobRunner(JobRunner):
    """Future distributed queue-based runner (e.g. Redis/Celery/RabbitMQ).

    Interface only in Phase 1.
    """

    def submit(
        self,
        job_id: str,
        func: Callable[[Any], Any],
        input_data: Any,
    ) -> Future[JobResult[Any]]:
        raise NotImplementedError("QueueJobRunner will be implemented in a future phase.")

    def run(
        self,
        job_id: str,
        func: Callable[[Any], Any],
        input_data: Any,
        timeout: float | None = None,
    ) -> JobResult[Any]:
        raise NotImplementedError("QueueJobRunner will be implemented in a future phase.")
