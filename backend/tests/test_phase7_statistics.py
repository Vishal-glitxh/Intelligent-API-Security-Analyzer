from pathlib import Path

from app.evaluation.models import ClassificationOutcome, PropositionClassification
from app.evaluation.runner import run_evaluation_experiment
from app.evaluation.statistics import (
    compute_bootstrap_f1_ci,
    compute_correlation_effect_transitions,
    compute_error_taxonomy_analysis,
    compute_mode_comparisons,
    compute_wilson_score_interval,
    run_phase7_statistical_analysis,
)


def test_wilson_score_confidence_interval_calculation() -> None:
    """Verify 95% Wilson Score confidence interval bounds for binomial proportions."""
    # 1. Zero sample size -> None bounds
    low_zero, up_zero = compute_wilson_score_interval(0, 0)
    assert low_zero is None
    assert up_zero is None

    # 2. Perfect proportion k=5, n=5
    low_perf, up_perf = compute_wilson_score_interval(5, 5)
    assert low_perf is not None and up_perf is not None
    assert low_perf > 0.5
    assert up_perf == 1.0

    # 3. CORRELATED precision k=5, n=6 (p = 0.8333)
    low_corr, up_corr = compute_wilson_score_interval(5, 6)
    assert low_corr is not None and up_corr is not None
    assert 0.40 <= low_corr <= 0.45
    assert 0.95 <= up_corr <= 1.00


def test_deterministic_bootstrap_f1_confidence_interval() -> None:
    """Verify reproducible F1 confidence interval via fixed-seed bootstrap."""
    classifications = [
        PropositionClassification(
            proposition_id=f"P{i}",
            case_id=f"C{i}",
            category="authentication",
            endpoint="/api",
            method="GET",
            condition="cond",
            expected=True if i <= 5 else False,
            outcome=ClassificationOutcome.TP
            if i <= 3
            else ClassificationOutcome.FN
            if i <= 5
            else ClassificationOutcome.TN,
        )
        for i in range(1, 11)
    ]

    ci1 = compute_bootstrap_f1_ci(classifications, mode="TEST", n_resamples=500, seed=42)
    ci2 = compute_bootstrap_f1_ci(classifications, mode="TEST", n_resamples=500, seed=42)

    assert ci1.metric == "f1"
    assert ci1.method == "bootstrap_percentile"
    assert ci1.seed == 42
    assert ci1.estimate == ci2.estimate
    assert ci1.lower == ci2.lower
    assert ci1.upper == ci2.upper
    assert ci1.lower is not None and ci1.upper is not None
    assert ci1.lower <= (ci1.estimate or 0.0) <= ci1.upper


def test_mode_comparisons_and_absolute_differences() -> None:
    """Verify absolute differences between CORRELATED and single-layer baselines."""
    report_data = run_evaluation_experiment(deterministic=True)
    mode_comps = compute_mode_comparisons(report_data.mode_results)

    assert len(mode_comps) == 10  # 5 metrics x 2 baselines

    spec_f1_comp = [
        c for c in mode_comps if c["baseline_mode"] == "SPEC_ONLY" and c["metric"] == "f1"
    ][0]
    assert spec_f1_comp["baseline_value"] == 0.5000
    assert spec_f1_comp["comparison_value"] == 0.7143
    assert spec_f1_comp["absolute_difference"] == 0.2143
    assert not spec_f1_comp["statistically_significant"]

    source_f1_comp = [
        c for c in mode_comps if c["baseline_mode"] == "SOURCE_ONLY" and c["metric"] == "f1"
    ][0]
    assert source_f1_comp["baseline_value"] == 0.5882
    assert source_f1_comp["comparison_value"] == 0.7143
    assert source_f1_comp["absolute_difference"] == 0.1261


def test_dynamic_proposition_discovery_and_transitions() -> None:
    """Verify dynamic discovery of all propositions and correlation effect transitions."""
    report_data = run_evaluation_experiment(deterministic=True)
    effects = compute_correlation_effect_transitions(report_data.mode_results)

    assert effects["proposition_count"] == 22
    assert len(effects["records"]) == 22

    # Verify SPEC -> CORRELATED and SOURCE -> CORRELATED transition summaries
    spec_summary = effects["spec_to_correlated_summary"]
    source_summary = effects["source_to_correlated_summary"]

    assert "FN_TO_TP" in spec_summary["transition_counts"]
    assert "PROP-AUTH-002" in spec_summary["propositions_by_transition"]["FN_TO_TP"]

    assert "TP_TO_FN" in source_summary["transition_counts"]
    assert "PROP-SECRET-001" in source_summary["propositions_by_transition"]["TP_TO_FN"]


def test_secret_001_handling_in_error_taxonomy() -> None:
    """Verify PROP-SECRET-001 is categorized as SOURCE_INTRINSIC_NON_ENDPOINT in CORRELATED mode."""
    report_data = run_evaluation_experiment(deterministic=True)
    err_analysis = compute_error_taxonomy_analysis(report_data.mode_results)

    sec_errors = [
        e
        for e in err_analysis["error_details"]
        if e["proposition_id"] == "PROP-SECRET-001" and e["mode"] == "CORRELATED"
    ]
    assert len(sec_errors) == 1
    sec_err = sec_errors[0]
    assert sec_err["outcome"] == "FN"
    assert sec_err["error_source_category"] == "SOURCE_INTRINSIC_NON_ENDPOINT"
    assert "Hardcoded source secret without OpenAPI counterpart" in sec_err["rationale"]


def test_empty_and_degenerate_classification_handling() -> None:
    """Verify zero/empty classification handling produces valid None structures without crashing."""
    empty_ci = compute_bootstrap_f1_ci([], mode="EMPTY")
    assert empty_ci.estimate is None
    assert empty_ci.lower is None
    assert empty_ci.upper is None

    empty_mode_comps = compute_mode_comparisons({})
    assert empty_mode_comps == []


def test_end_to_end_phase7_analysis_serialization(tmp_path: Path) -> None:
    """Verify complete end-to-end Phase 7 statistical analysis pipeline and artifact structure."""
    report_data = run_evaluation_experiment(deterministic=True)
    stats_res = run_phase7_statistical_analysis(report_data)

    assert stats_res.dataset_version == "6.0.0"
    assert stats_res.dimension_a_propositions_count == 22
    assert len(stats_res.confidence_intervals) > 0
    assert len(stats_res.mode_comparisons) == 10
    assert len(stats_res.limitations) >= 5

    # Verify limitations contain required small-sample statements
    lims_text = " ".join(stats_res.limitations)
    assert "24 total benchmark cases" in lims_text
    assert "22 Dimension-A" in lims_text
    assert "small-sample uncertainty bounds" in lims_text
