import hashlib
import json
import logging
import platform
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from app.analysis.context import AnalysisContext
from app.analysis.correlation.engine import CorrelationEngine
from app.analysis.correlation.models import MultiLayerAnalysisResult
from app.analysis.engine import AnalysisEngine
from app.analysis.openapi.loader import load_openapi_spec
from app.analysis.openapi.normalizer import normalize_openapi_spec
from app.analysis.rules.builtin import register_builtin_rules
from app.analysis.rules.registry import RuleRegistry
from app.analysis.source import normalize_source_tree
from app.analysis.source.loader import load_source_from_disk
from app.evaluation.classifier import (
    evaluate_correlation_state,
    evaluate_endpoint_pair,
    evaluate_security_proposition,
)
from app.evaluation.loader import (
    DEFAULT_DATASET_DIR,
    EXTERNAL_DATASET_DIR,
    get_case_files,
    load_dataset,
)
from app.evaluation.metrics import (
    compute_dimension_b_score,
    compute_dimension_c_score,
    compute_metric_population,
    evaluate_evidence_completeness,
    evaluate_explainability_rubric,
)
from app.evaluation.models import (
    CaseGroundTruth,
    DimensionAResult,
    DimensionBResult,
    DimensionCResult,
    EvaluationModeResult,
    EvaluationReportData,
    PropositionClassification,
)

logger = logging.getLogger(__name__)


def run_single_case_analysis(
    spec_path: Path, source_dir: Path
) -> tuple[str, MultiLayerAnalysisResult]:
    """Execute Phase 2-4 analysis engines returning raw MultiLayerAnalysisResult."""
    with open(spec_path, encoding="utf-8") as f:
        spec_content = f.read()

    loaded_spec = load_openapi_spec(spec_content)
    normalized_spec = normalize_openapi_spec(loaded_spec)

    loaded_source = load_source_from_disk(source_dir)
    # SOURCE_ONLY is the independent source-analysis condition. Connexion's routes are
    # declared by OpenAPI, so passing the contract here would leak SPEC_ONLY evidence
    # into the source-only benchmark. Production scans pass the spec to normalization.
    source_tree = normalize_source_tree(loaded_source)

    # 1. Phase 2: Spec Analysis
    spec_context = AnalysisContext(specification=normalized_spec)
    spec_registry = RuleRegistry()
    register_builtin_rules(spec_registry)
    spec_engine = AnalysisEngine(spec_registry)
    spec_result = spec_engine.analyze(spec_context)

    # 2. Phase 3: Source Analysis
    source_context = AnalysisContext(source=source_tree)
    source_registry = RuleRegistry()
    register_builtin_rules(source_registry)
    source_engine = AnalysisEngine(source_registry)
    source_result = source_engine.analyze(source_context)

    # 3. Phase 4: Evidence Correlation Engine
    combined_context = AnalysisContext(specification=normalized_spec, source=source_tree)
    correlation_engine = CorrelationEngine()
    multi_layer_result = correlation_engine.correlate(
        context=combined_context,
        spec_findings=spec_result.findings,
        source_findings=source_result.findings,
    )

    return spec_content, multi_layer_result


def evaluate_mode(
    mode: str,
    dataset: tuple[CaseGroundTruth, ...],
    analysis_results: dict[str, Any],
) -> EvaluationModeResult:
    """Evaluate a single analysis mode (SPEC_ONLY, SOURCE_ONLY, or CORRELATED)."""
    classifications: list[PropositionClassification] = []
    category_classifications: dict[str, list[PropositionClassification]] = {}
    dim_b_evals: list[dict[str, Any]] = []
    dim_c_evals: list[dict[str, Any]] = []
    raw_results_list = []

    for case in dataset:
        case_id = case.case_id
        _, multi_layer_res = analysis_results[case_id]
        raw_results_list.append(multi_layer_res)

        # Determine finding population for this mode
        if mode == "SPEC_ONLY":
            findings = multi_layer_res.spec_only_findings
        elif mode == "SOURCE_ONLY":
            findings = multi_layer_res.source_only_findings
        else:
            findings = multi_layer_res.correlated_findings

        # 1. Dimension A: Security Detection Evaluation (proposition-level)
        for prop in case.propositions:
            c = evaluate_security_proposition(prop, case_id, findings)
            classifications.append(c)

            cat = c.category
            if cat not in category_classifications:
                category_classifications[cat] = []
            category_classifications[cat].append(c)

        # 2. Dimension B: Correlation Evaluation (only for CORRELATED mode)
        if mode == "CORRELATED":
            for corr_gt in case.expected_correlations:
                dim_b_evals.append(evaluate_correlation_state(corr_gt, multi_layer_res))

        # 3. Dimension C: Endpoint Matching Evaluation (only for CORRELATED mode)
        if mode == "CORRELATED":
            for pair_gt in case.expected_endpoint_pairs:
                dim_c_evals.append(evaluate_endpoint_pair(pair_gt, multi_layer_res))

    # Compute Dimension A Metrics
    overall_metrics = compute_metric_population(classifications)

    category_metrics = {}
    for cat, c_list in category_classifications.items():
        category_metrics[cat] = compute_metric_population(c_list)

    dim_a_res = DimensionAResult(
        overall_metrics=overall_metrics,
        category_metrics=category_metrics,
        classifications=tuple(classifications),
    )

    # Compute Dimension B & C Results
    dim_b_res = DimensionBResult(
        score=compute_dimension_b_score(dim_b_evals),
        details=tuple(dim_b_evals),
    )
    dim_c_res = DimensionCResult(
        score=compute_dimension_c_score(dim_c_evals),
        details=tuple(dim_c_evals),
    )

    # Evidence Completeness & Explainability Rubrics
    ev_completeness = evaluate_evidence_completeness(mode, raw_results_list)
    explainability = evaluate_explainability_rubric(mode, raw_results_list)

    return EvaluationModeResult(
        mode=mode,
        dimension_a=dim_a_res,
        dimension_b=dim_b_res,
        dimension_c=dim_c_res,
        evidence_completeness=ev_completeness,
        explainability=explainability,
    )


def run_evaluation_experiment(
    dataset_dir: Path = DEFAULT_DATASET_DIR,
    runs_dir: Path = Path("evaluation/runs"),
    deterministic: bool = True,
    experiment_id: str | None = None,
    execution_timestamp: str | None = None,
    benchmark: str = "baseline",
) -> EvaluationReportData:
    """Execute complete research evaluation pipeline across benchmark cases in 3 modes."""
    if benchmark == "baseline":
        default_exp_id = "4eb72e4c-2ba5-47c8-ad1b-9d992b709f61"
        default_exec_ts = "2026-09-20T04:15:55Z"
        default_dataset_ver = "6.0.0"
        dataset_path = dataset_dir
    elif benchmark == "external":
        default_exp_id = "8c9d1e2f-3a4b-5c6d-7e8f-9a0b1c2d3e4f"
        default_exec_ts = "2026-10-12T12:00:00Z"
        default_dataset_ver = "7.3.0"
        dataset_path = EXTERNAL_DATASET_DIR if dataset_dir == DEFAULT_DATASET_DIR else dataset_dir
    elif benchmark == "combined":
        default_exp_id = "9d0e1f2a-4b5c-6d7e-8f9a-0b1c2d3e4f5a"
        default_exec_ts = "2026-10-12T12:00:00Z"
        default_dataset_ver = "6.0.0+7.3.0"
        dataset_path = dataset_dir
    else:
        default_exp_id = "4eb72e4c-2ba5-47c8-ad1b-9d992b709f61"
        default_exec_ts = "2026-09-20T04:15:55Z"
        default_dataset_ver = "6.0.0"
        dataset_path = dataset_dir

    if deterministic:
        exp_id = experiment_id or default_exp_id
        exec_ts = execution_timestamp or default_exec_ts
    else:
        exp_id = experiment_id or str(uuid.uuid4())
        exec_ts = execution_timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    dataset = load_dataset(dataset_path, benchmark=benchmark)
    runs_dir = runs_dir.resolve()

    analysis_results: dict[str, Any] = {}

    # Execute the current Phase 2-4 analyzer against all benchmark cases in this partition
    for case in dataset:
        spec_path, source_dir = get_case_files(case.case_id, dataset_path)
        spec_content, multi_layer_res = run_single_case_analysis(spec_path, source_dir)

        spec_hash = hashlib.sha256(spec_content.encode("utf-8")).hexdigest()
        analysis_results[case.case_id] = (spec_hash, multi_layer_res)

        # Save raw run artifact for each mode
        for mode in ("SPEC_ONLY", "SOURCE_ONLY", "CORRELATED"):
            mode_dir = runs_dir / mode
            mode_dir.mkdir(parents=True, exist_ok=True)
            raw_run_file = mode_dir / f"{case.case_id}.json"

            run_payload = {
                "experiment_id": exp_id,
                "case_id": case.case_id,
                "mode": mode,
                "spec_hash": spec_hash,
                "spec_only_findings_count": len(multi_layer_res.spec_only_findings),
                "source_only_findings_count": len(multi_layer_res.source_only_findings),
                "correlated_findings_count": len(multi_layer_res.correlated_findings),
                "matched_endpoints_count": len(multi_layer_res.matched_endpoints),
            }
            with open(raw_run_file, "w") as rf:
                json.dump(run_payload, rf, indent=2)

    # Evaluate across all 3 modes
    mode_results: dict[str, EvaluationModeResult] = {}
    for mode in ("SPEC_ONLY", "SOURCE_ONLY", "CORRELATED"):
        mode_results[mode] = evaluate_mode(mode, dataset, analysis_results)

    report_data = EvaluationReportData(
        experiment_id=exp_id,
        dataset_version=default_dataset_ver,
        analyzer_version="0.1.0",
        rule_set_version="0.1.0",
        config_version="1.0.0",
        python_version=sys.version.split()[0],
        platform_info=f"{platform.system()} {platform.release()} ({platform.machine()})",
        execution_timestamp=exec_ts,
        mode_results=mode_results,
    )

    return report_data
