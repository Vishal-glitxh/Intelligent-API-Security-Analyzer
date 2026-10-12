from pathlib import Path

import yaml
from app.analysis.openapi.loader import load_openapi_spec
from app.analysis.openapi.normalizer import normalize_openapi_spec
from app.evaluation.loader import (
    BASELINE_DATASET_DIR,
    EXTERNAL_DATASET_DIR,
    get_case_files,
    load_dataset,
)
from app.evaluation.models import (
    CaseGroundTruth,
    GroundTruthLabel,
)
from app.evaluation.runner import run_evaluation_experiment


def test_external_dataset_loading_and_schema_validation() -> None:
    """Verify that external dataset loads 12 valid cases with schema conformance."""
    external_cases = load_dataset(benchmark="external")
    assert len(external_cases) == 12

    seen_ids: set[str] = set()
    for case in external_cases:
        assert isinstance(case, CaseGroundTruth)
        assert case.case_id.startswith("VAMPI-")
        assert case.case_id not in seen_ids
        seen_ids.add(case.case_id)
        assert isinstance(case.ground_truth_label, GroundTruthLabel)
        assert case.dataset_version == "7.3.0"
        assert case.evaluation_role == "EXTERNAL"
        assert len(case.propositions) >= 1
        for prop in case.propositions:
            assert prop.category in {"authentication", "authorization", "sensitive_data"}
            assert prop.endpoint.startswith("/")
            assert prop.method in {"GET", "POST", "PUT", "DELETE", "PATCH"}
            assert isinstance(prop.expected, bool)


def test_external_dataset_provenance_and_ground_truth_completeness() -> None:
    """Verify provenance, licensing records, and ground truth completeness for VAmPI."""
    gt_file = EXTERNAL_DATASET_DIR / "ground_truth.yaml"
    assert gt_file.exists()

    with open(gt_file) as f:
        data = yaml.safe_load(f)

    assert data["dataset_version"] == "7.3.0"
    assert data["total_cases"] == 12

    prov = data.get("provenance", {})
    assert prov.get("repository") == "https://github.com/erev0s/VAmPI"
    assert prov.get("pinned_commit") == "f16052dce83f05847133ec98f01c5193a41de7d8"
    assert prov.get("author") == "Dimitrios Vlachos (Erev0s)"
    assert prov.get("license") == "MIT"

    # License file
    license_file = EXTERNAL_DATASET_DIR / "LICENSE"
    assert license_file.exists()
    license_content = license_file.read_text()
    assert "MIT License" in license_content
    assert "erev0s" in license_content

    # README documentation with exclusions
    readme_file = EXTERNAL_DATASET_DIR / "README.md"
    assert readme_file.exists()
    readme_content = readme_file.read_text()
    assert "f16052dce83f05847133ec98f01c5193a41de7d8" in readme_content
    assert "Excluded Cases" in readme_content


def test_external_case_files_and_endpoint_method_mapping() -> None:
    """Verify endpoint and HTTP method mapping for all external benchmark cases."""
    external_cases = load_dataset(benchmark="external")

    for case in external_cases:
        spec_path, source_dir = get_case_files(case.case_id, EXTERNAL_DATASET_DIR)
        assert spec_path.exists(), f"Spec missing for {case.case_id}"
        assert source_dir.exists(), f"Source directory missing for {case.case_id}"

        with open(spec_path, encoding="utf-8") as f:
            content = f.read()

        loaded_spec = load_openapi_spec(content)
        normalized_spec = normalize_openapi_spec(loaded_spec)

        # Confirm each proposition endpoint is present in the normalized specification
        spec_endpoints = {ep.path for ep in normalized_spec.endpoints}
        spec_methods = {
            (ep.path, op.method.upper()) for ep in normalized_spec.endpoints for op in ep.operations
        }

        for prop in case.propositions:
            assert prop.endpoint in spec_endpoints, (
                f"Proposition endpoint {prop.endpoint} not found in spec for {case.case_id}"
            )
            assert (prop.endpoint, prop.method) in spec_methods, (
                f"Proposition method {prop.method} on {prop.endpoint} not found for {case.case_id}"
            )


def test_benchmark_partition_isolation(tmp_path: Path) -> None:
    """Verify partition isolation across baseline, external, and combined datasets."""
    baseline_cases = load_dataset(benchmark="baseline")
    external_cases = load_dataset(benchmark="external")
    combined_cases = load_dataset(benchmark="combined")

    assert len(baseline_cases) == 24
    assert len(external_cases) == 12
    assert len(combined_cases) == 36

    baseline_ids = {c.case_id for c in baseline_cases}
    external_ids = {c.case_id for c in external_cases}

    # Strict partition disjointness
    assert len(baseline_ids.intersection(external_ids)) == 0

    # Test file retrieval partition isolation
    for b_case in baseline_cases:
        b_spec, b_src = get_case_files(b_case.case_id, BASELINE_DATASET_DIR)
        assert BASELINE_DATASET_DIR.name in str(b_spec)

    for e_case in external_cases:
        e_spec, e_src = get_case_files(e_case.case_id, EXTERNAL_DATASET_DIR)
        assert EXTERNAL_DATASET_DIR.name in str(e_spec)


def test_deterministic_external_evaluation(tmp_path: Path) -> None:
    """Verify deterministic execution and metrics on external benchmark partition."""
    runs_dir = tmp_path / "runs_external"
    report_data = run_evaluation_experiment(
        runs_dir=runs_dir,
        deterministic=True,
        benchmark="external",
    )

    assert report_data.experiment_id == "8c9d1e2f-3a4b-5c6d-7e8f-9a0b1c2d3e4f"
    assert report_data.dataset_version == "7.3.0"
    assert set(report_data.mode_results.keys()) == {"SPEC_ONLY", "SOURCE_ONLY", "CORRELATED"}

    spec_mode = report_data.mode_results["SPEC_ONLY"]
    assert spec_mode.dimension_a.overall_metrics.tp == 4
    assert spec_mode.dimension_a.overall_metrics.fp == 2
    assert spec_mode.dimension_a.overall_metrics.fn == 3
    assert spec_mode.dimension_a.overall_metrics.tn == 3

    # All 12 case run artifacts were persisted
    for mode in ("SPEC_ONLY", "SOURCE_ONLY", "CORRELATED"):
        mode_dir = runs_dir / mode
        assert mode_dir.exists()
        assert len(list(mode_dir.glob("VAMPI-*.json"))) == 12


def test_unchanged_baseline_metrics(tmp_path: Path) -> None:
    """Verify frozen baseline benchmark metrics are identical to published Phase 6 results."""
    runs_dir = tmp_path / "runs_baseline"
    report_data = run_evaluation_experiment(
        runs_dir=runs_dir,
        deterministic=True,
        benchmark="baseline",
    )

    assert report_data.experiment_id == "4eb72e4c-2ba5-47c8-ad1b-9d992b709f61"
    assert report_data.dataset_version == "6.0.0"

    modes = report_data.mode_results

    # SPEC_ONLY baseline metrics
    spec_a = modes["SPEC_ONLY"].dimension_a.overall_metrics
    assert spec_a.tp == 4
    assert spec_a.fp == 4
    assert spec_a.fn == 4
    assert spec_a.tn == 10
    assert spec_a.precision == 0.5000
    assert spec_a.recall == 0.5000
    assert spec_a.f1 == 0.5000

    # SOURCE_ONLY baseline metrics
    src_a = modes["SOURCE_ONLY"].dimension_a.overall_metrics
    assert src_a.tp == 5
    assert src_a.fp == 4
    assert src_a.fn == 3
    assert src_a.tn == 10

    # CORRELATED baseline metrics
    corr_a = modes["CORRELATED"].dimension_a.overall_metrics
    assert corr_a.tp == 5
    assert corr_a.fp == 1
    assert corr_a.fn == 3
    assert corr_a.tn == 13

    # Correlation and Endpoint Match Accuracy
    assert modes["CORRELATED"].dimension_b.score.accuracy == 1.0000
    assert modes["CORRELATED"].dimension_c.score.accuracy == 1.0000
