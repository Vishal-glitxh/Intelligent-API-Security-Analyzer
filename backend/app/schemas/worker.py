from dataclasses import dataclass

from app.analysis.correlation import MultiLayerAnalysisResult


@dataclass(frozen=True)
class AnalysisWorkerInput:
    """Serializable input payload passed to child worker process."""

    scan_id: str
    spec_content: str  # Raw OpenAPI spec YAML/JSON text
    source_dir: str  # Path to sandboxed extracted source directory
    config_version: str = "1.0.0"


@dataclass(frozen=True)
class AnalysisWorkerOutput:
    """Serializable output payload returned from child worker process."""

    scan_id: str
    result: MultiLayerAnalysisResult | None
    error_message: str | None = None
    execution_time_seconds: float = 0.0
