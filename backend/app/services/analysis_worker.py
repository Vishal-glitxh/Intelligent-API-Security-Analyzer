import re
import time
from pathlib import Path

from app.analysis.context import AnalysisContext
from app.analysis.correlation.engine import CorrelationEngine
from app.analysis.engine import AnalysisEngine
from app.analysis.openapi.loader import load_openapi_spec
from app.analysis.openapi.normalizer import normalize_openapi_spec
from app.analysis.openapi.validator import validate_openapi_spec
from app.analysis.rules.builtin import register_builtin_rules
from app.analysis.rules.registry import RuleRegistry
from app.analysis.source import normalize_source_tree
from app.analysis.source.loader import load_source_from_disk
from app.schemas.worker import AnalysisWorkerInput, AnalysisWorkerOutput


def sanitize_error_message(err: Exception, default_prefix: str) -> str:
    """Sanitize exception output stripping stack traces, filesystem paths, and secrets."""
    msg = str(err)
    if not msg:
        msg = err.__class__.__name__

    # Remove absolute file paths (e.g., /Users/... or /tmp/... or C:\...)
    msg = re.sub(r"/(?:[\w.-]+/)+[\w.-]+", "<sanitized_path>", msg)
    msg = re.sub(r"[A-Za-z]:\\[^\n\r]+", "<sanitized_path>", msg)

    # Remove stack trace or traceback substrings if present
    msg = msg.split("\n")[0]

    # Ensure standardized prefix
    if not any(
        msg.startswith(prefix)
        for prefix in (
            "OPENAPI_PARSING_ERROR:",
            "SOURCE_ANALYSIS_ERROR:",
            "CORRELATION_ERROR:",
            "TIMEOUT_EXCEEDED:",
            "UNTRUSTED_ARCHIVE_REJECTED:",
            "SYSTEM_INTERRUPTED:",
            "PERSISTENCE_ERROR:",
            "PROCESS_EXECUTION_ERROR:",
        )
    ):
        msg = f"{default_prefix}: {msg}"

    return msg


def execute_analysis_worker(input_data: AnalysisWorkerInput) -> AnalysisWorkerOutput:
    """Picklable worker function executed inside process-isolated child process.

    Executes Phase 2 (OpenAPI) -> Phase 3 (Source AST) -> Phase 4 (Correlation Engine).
    Operates without database sessions, FastAPI request objects, or ORM state.
    """
    start_time = time.monotonic()
    scan_id = input_data.scan_id

    # 1. Phase 2 — OpenAPI Analysis
    try:
        loaded_spec = load_openapi_spec(input_data.spec_content)
        validate_openapi_spec(loaded_spec.raw_data)
        normalized_spec = normalize_openapi_spec(loaded_spec)

        spec_context = AnalysisContext(specification=normalized_spec)
        spec_registry = RuleRegistry()
        register_builtin_rules(spec_registry)
        spec_engine = AnalysisEngine(spec_registry)
        spec_analysis_result = spec_engine.analyze(spec_context)
        spec_findings = spec_analysis_result.findings
    except Exception as e:
        sanitized = sanitize_error_message(e, "OPENAPI_PARSING_ERROR")
        return AnalysisWorkerOutput(
            scan_id=scan_id,
            result=None,
            error_message=sanitized,
            execution_time_seconds=time.monotonic() - start_time,
        )

    # 2. Phase 3 — Source Code Analysis
    try:
        source_dir = Path(input_data.source_dir)
        loaded_source = load_source_from_disk(source_dir)
        source_tree = normalize_source_tree(loaded_source)

        source_context = AnalysisContext(source=source_tree)
        source_registry = RuleRegistry()
        register_builtin_rules(source_registry)
        source_engine = AnalysisEngine(source_registry)
        source_analysis_result = source_engine.analyze(source_context)
        source_findings = source_analysis_result.findings
    except Exception as e:
        sanitized = sanitize_error_message(e, "SOURCE_ANALYSIS_ERROR")
        return AnalysisWorkerOutput(
            scan_id=scan_id,
            result=None,
            error_message=sanitized,
            execution_time_seconds=time.monotonic() - start_time,
        )

    # 3. Phase 4 — Evidence Correlation Engine
    try:
        combined_context = AnalysisContext(specification=normalized_spec, source=source_tree)
        correlation_engine = CorrelationEngine()
        multi_layer_result = correlation_engine.correlate(
            context=combined_context,
            spec_findings=spec_findings,
            source_findings=source_findings,
        )
    except Exception as e:
        sanitized = sanitize_error_message(e, "CORRELATION_ERROR")
        return AnalysisWorkerOutput(
            scan_id=scan_id,
            result=None,
            error_message=sanitized,
            execution_time_seconds=time.monotonic() - start_time,
        )

    execution_time = time.monotonic() - start_time
    return AnalysisWorkerOutput(
        scan_id=scan_id,
        result=multi_layer_result,
        error_message=None,
        execution_time_seconds=execution_time,
    )
