import pytest
from app.jobs.runner import (
    JobStatus,
    LocalProcessJobRunner,
    QueueJobRunner,
)


def _sample_cpu_task(data: dict[str, int]) -> int:
    """Picklable top-level worker function for testing process isolation."""
    return data["a"] + data["b"]


def _failing_task(data: dict[str, str]) -> str:
    """Picklable top-level worker function that intentionally fails."""
    raise RuntimeError("Intentional worker failure")


def test_local_process_job_runner_success() -> None:
    runner = LocalProcessJobRunner(max_workers=1)
    try:
        result = runner.run(
            job_id="job-test-01",
            func=_sample_cpu_task,
            input_data={"a": 15, "b": 27},
            timeout=5.0,
        )
        assert result.job_id == "job-test-01"
        assert result.status == JobStatus.COMPLETED
        assert result.result == 42
        assert result.error is None
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.completed_at >= result.started_at
    finally:
        runner.shutdown(wait=True)


def test_local_process_job_runner_failure() -> None:
    runner = LocalProcessJobRunner(max_workers=1)
    try:
        result = runner.run(
            job_id="job-fail-01",
            func=_failing_task,
            input_data={"test": "val"},
            timeout=5.0,
        )
        assert result.job_id == "job-fail-01"
        assert result.status == JobStatus.FAILED
        assert result.result is None
        assert result.error is not None
        assert "Intentional worker failure" in result.error
    finally:
        runner.shutdown(wait=True)


def test_local_process_job_runner_submit_async() -> None:
    runner = LocalProcessJobRunner(max_workers=1)
    try:
        future = runner.submit(
            job_id="job-async-01",
            func=_sample_cpu_task,
            input_data={"a": 100, "b": 200},
        )
        result = future.result(timeout=5.0)
        assert result.status == JobStatus.COMPLETED
        assert result.result == 300
    finally:
        runner.shutdown(wait=True)


def test_queue_job_runner_interface_raises_not_implemented() -> None:
    runner = QueueJobRunner()
    with pytest.raises(
        NotImplementedError, match="QueueJobRunner will be implemented in a future phase"
    ):
        runner.submit("job-q1", _sample_cpu_task, {})

    with pytest.raises(
        NotImplementedError, match="QueueJobRunner will be implemented in a future phase"
    ):
        runner.run("job-q1", _sample_cpu_task, {})
