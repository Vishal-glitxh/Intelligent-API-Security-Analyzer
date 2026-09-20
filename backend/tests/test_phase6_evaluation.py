from pathlib import Path
from typing import Any

from app.analysis.correlation.models import (
    EndpointMatchState,
    MatchedEndpointPair,
    MultiLayerAnalysisResult,
)
from app.analysis.findings import Evidence, Finding, Severity
from app.evaluation.classifier import (
    evaluate_correlation_state,
    evaluate_endpoint_pair,
    evaluate_security_proposition,
)
from app.evaluation.loader import load_dataset
from app.evaluation.metrics import (
    compute_dimension_b_score,
    compute_dimension_c_score,
    compute_metric_population,
    evaluate_evidence_completeness,
    evaluate_explainability_rubric,
)
from app.evaluation.models import (
    CaseGroundTruth,
    ClassificationOutcome,
    ExpectedCorrelationState,
    ExpectedEndpointPair,
    ExplainabilityCriterionStatus,
    GroundTruthLabel,
    PropositionClassification,
    SecurityProposition,
)
from app.evaluation.reporter import generate_html_report, generate_json_artifacts
from app.evaluation.runner import run_evaluation_experiment


def test_dataset_loading_and_integrity() -> None:
    """Verify that dataset loads 24 cases with unique IDs and valid ground truth metadata."""
    dataset = load_dataset()
    assert len(dataset) == 24

    seen_ids = set()
    for case in dataset:
        assert isinstance(case, CaseGroundTruth)
        assert case.case_id not in seen_ids
        seen_ids.add(case.case_id)
        assert isinstance(case.ground_truth_label, GroundTruthLabel)
        assert case.dataset_version == "6.0.0"


def test_proposition_classification_tp_fp_fn_tn() -> None:
    """Verify proposition-level TP, FP, FN, TN classification logic."""
    ev = Evidence(kind="TEST_KIND", message="Found endpoint /api/v1/secure")
    test_finding = Finding(
        rule_id="MISSING_AUTH",
        rule_version="1.0.0",
        title="Missing Auth",
        severity=Severity.HIGH,
        confidence=0.9,
        rationale="OpenAPI missing security",
        remediation="Add auth",
        evidence=(ev,),
    )

    # 1. Expected True + Finding Present => TP
    prop_true = SecurityProposition(
        proposition_id="P1",
        category="authentication",
        endpoint="/api/v1/secure",
        method="GET",
        condition="missing_authentication",
        expected=True,
    )
    res_tp = evaluate_security_proposition(prop_true, "TEST-01", (test_finding,))
    assert res_tp.outcome == ClassificationOutcome.TP

    # 2. Expected True + Finding Absent => FN
    res_fn = evaluate_security_proposition(prop_true, "TEST-01", ())
    assert res_fn.outcome == ClassificationOutcome.FN

    # 3. Expected False + Finding Present => FP
    prop_false = SecurityProposition(
        proposition_id="P2",
        category="authentication",
        endpoint="/api/v1/secure",
        method="GET",
        condition="missing_authentication",
        expected=False,
    )
    res_fp = evaluate_security_proposition(prop_false, "TEST-01", (test_finding,))
    assert res_fp.outcome == ClassificationOutcome.FP

    # 4. Expected False + Finding Absent => TN
    res_tn = evaluate_security_proposition(prop_false, "TEST-01", ())
    assert res_tn.outcome == ClassificationOutcome.TN


def test_metrics_zero_denominator_handling() -> None:
    """Verify zero denominators produce None values with reason strings (never NaN)."""
    # Empty classifications -> zero TP, FP, FN, TN
    empty_pop = compute_metric_population([])
    assert empty_pop.precision is None
    assert empty_pop.recall is None
    assert empty_pop.f1 is None
    assert empty_pop.fpr is None
    assert empty_pop.fnr is None
    assert "precision" in empty_pop.undefined_reasons
    assert "recall" in empty_pop.undefined_reasons

    # Pure TN population -> TP+FP=0, TP+FN=0
    tn_only = [
        PropositionClassification(
            proposition_id="P1",
            case_id="C1",
            category="authentication",
            endpoint="/ep",
            method="GET",
            condition="cond",
            expected=False,
            outcome=ClassificationOutcome.TN,
        )
    ]
    tn_pop = compute_metric_population(tn_only)
    assert tn_pop.precision is None
    assert tn_pop.recall is None
    assert tn_pop.fpr == 0.0


def test_evidence_completeness_na_handling() -> None:
    """Verify evidence completeness evaluation does not penalize SPEC_ONLY for N/A fields."""
    ev = Evidence(kind="TEST_KIND", message="Spec check")
    spec_finding = Finding(
        rule_id="SPEC-001",
        rule_version="1.0.0",
        title="Unauth Spec",
        severity=Severity.HIGH,
        confidence=0.9,
        rationale="Spec missing auth",
        remediation="Fix spec",
        evidence=(ev,),
    )
    res = MultiLayerAnalysisResult(
        spec_only_findings=(spec_finding,),
        source_only_findings=(),
        correlated_findings=(),
        matched_endpoints=(),
        unmatched_spec_endpoints=(),
        unmatched_source_endpoints=(),
    )

    spec_score = evaluate_evidence_completeness("SPEC_ONLY", [res])
    assert spec_score.score == 1.0
    assert spec_score.not_applicable_count >= 1


def test_explainability_rubric_na_handling() -> None:
    """Verify explainability rubric supports NOT_APPLICABLE without score reduction."""
    ev = Evidence(kind="TEST_KIND", message="Endpoint /api/v1/data")
    finding = Finding(
        rule_id="SPEC-001",
        rule_version="1.0.0",
        title="Title",
        severity=Severity.MEDIUM,
        confidence=0.8,
        rationale="Rationale text",
        remediation="Remediation text",
        evidence=(ev,),
    )
    res = MultiLayerAnalysisResult(
        spec_only_findings=(finding,),
        source_only_findings=(),
        correlated_findings=(),
        matched_endpoints=(),
        unmatched_spec_endpoints=(),
        unmatched_source_endpoints=(),
    )

    exp = evaluate_explainability_rubric("SPEC_ONLY", [res])
    assert exp.score == 1.0
    na_status = ExplainabilityCriterionStatus.NOT_APPLICABLE
    assert exp.criteria_breakdown["provenance_file_line"] == na_status
    assert exp.criteria_breakdown["correlation_relationship"] == na_status


def test_dimension_b_correlation_evaluation() -> None:
    """Verify Dimension B correlation state evaluation logic."""
    expected = ExpectedCorrelationState(
        target_id="T1",
        category="authentication",
        endpoint="/api/v1/admin",
        method="GET",
        expected_state="CONTRADICTED",
    )
    res = MultiLayerAnalysisResult(
        spec_only_findings=(),
        source_only_findings=(),
        correlated_findings=(),
        matched_endpoints=(),
        unmatched_spec_endpoints=(),
        unmatched_source_endpoints=(),
    )
    eval_res = evaluate_correlation_state(expected, res)
    assert not eval_res["is_correct"]
    assert eval_res["actual_state"] == "INCONCLUSIVE"

    dim_b_score = compute_dimension_b_score([eval_res])
    assert dim_b_score.accuracy == 0.0


def test_dimension_c_endpoint_matching_evaluation() -> None:
    """Verify Dimension C multi-pair endpoint matching evaluation logic."""
    expected = ExpectedEndpointPair(
        pair_id="M1",
        spec_path="/api/v1/health",
        spec_method="GET",
        source_path="/api/v1/health",
        source_method="GET",
        expected_match_state="EXACT_MATCH",
    )
    pair = MatchedEndpointPair(
        spec_path="/api/v1/health",
        spec_method="GET",
        source_path="/api/v1/health",
        source_method="GET",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/api/v1/health",
    )
    res = MultiLayerAnalysisResult(
        spec_only_findings=(),
        source_only_findings=(),
        correlated_findings=(),
        matched_endpoints=(pair,),
        unmatched_spec_endpoints=(),
        unmatched_source_endpoints=(),
    )
    eval_res = evaluate_endpoint_pair(expected, res)
    assert eval_res["is_correct"]

    dim_c_score = compute_dimension_c_score([eval_res])
    assert dim_c_score.accuracy == 1.0


def test_full_evaluation_experiment_runner(tmp_path: Path) -> None:
    """Execute end-to-end evaluation runner and report generation."""
    report_data = run_evaluation_experiment(runs_dir=tmp_path / "runs")
    assert report_data.dataset_version == "6.0.0"
    assert "SPEC_ONLY" in report_data.mode_results
    assert "SOURCE_ONLY" in report_data.mode_results
    assert "CORRELATED" in report_data.mode_results

    # Generate JSON and HTML reports
    reports_dir = tmp_path / "reports"
    generate_json_artifacts(report_data, reports_dir)
    html_path = generate_html_report(report_data, reports_dir)

    assert (reports_dir / "metrics.json").exists()
    assert (reports_dir / "classifications.json").exists()
    assert (reports_dir / "endpoint_matching.json").exists()
    assert (reports_dir / "evidence_completeness.json").exists()
    assert (reports_dir / "explainability.json").exists()
    assert html_path.exists()


def test_dynamic_correlation_effect_trace_generation() -> None:
    """Verify trace report generator dynamically computes correlation effects
    including SECRET-001.
    """
    from app.evaluation.reporter import compute_correlation_effects

    mock_classifications: dict[str, list[dict[str, Any]]] = {
        "SPEC_ONLY": [
            {"proposition_id": "PROP-SECRET-001", "outcome": "FN", "finding_rule_id": None},
            {"proposition_id": "PROP-CUSTOM-999", "outcome": "TN", "finding_rule_id": None},
        ],
        "SOURCE_ONLY": [
            {
                "proposition_id": "PROP-SECRET-001",
                "outcome": "TP",
                "finding_rule_id": "API-SECRET-001",
            },
            {
                "proposition_id": "PROP-CUSTOM-999",
                "outcome": "TP",
                "finding_rule_id": "CUSTOM-RULE",
            },
        ],
        "CORRELATED": [
            {"proposition_id": "PROP-SECRET-001", "outcome": "FN", "finding_rule_id": None},
            {"proposition_id": "PROP-CUSTOM-999", "outcome": "TN", "finding_rule_id": None},
        ],
    }

    effects = compute_correlation_effects(
        {p["proposition_id"]: p for p in mock_classifications["SPEC_ONLY"]},
        {p["proposition_id"]: p for p in mock_classifications["SOURCE_ONLY"]},
        {p["proposition_id"]: p for p in mock_classifications["CORRELATED"]},
    )

    p_ids = [e["proposition_id"] for e in effects]

    # 1. Proves SECRET-001 is included dynamically with FN_INTRODUCED
    assert "PROP-SECRET-001" in p_ids
    sec_eff = [e for e in effects if e["proposition_id"] == "PROP-SECRET-001"][0]
    assert sec_eff["effect_type"] == "FN_INTRODUCED"
    assert sec_eff["source_outcome"] == "TP"
    assert sec_eff["corr_outcome"] == "FN"

    # 2. Proves arbitrary future changed propositions automatically appear (no hardcoded list)
    assert "PROP-CUSTOM-999" in p_ids
    custom_eff = [e for e in effects if e["proposition_id"] == "PROP-CUSTOM-999"][0]
    assert custom_eff["effect_type"] == "TP_LOST"
