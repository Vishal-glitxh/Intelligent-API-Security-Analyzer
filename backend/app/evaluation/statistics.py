import math
import random
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

from app.evaluation.metrics import compute_metric_population
from app.evaluation.models import PropositionClassification


@dataclass(frozen=True)
class ConfidenceInterval:
    metric: str
    mode: str
    estimate: float | None
    confidence_level: float
    method: str
    sample_size: int
    lower: float | None
    upper: float | None


@dataclass(frozen=True)
class F1ConfidenceInterval:
    metric: str
    mode: str
    estimate: float | None
    confidence_level: float
    method: str
    sample_size: int
    seed: int
    bootstrap_samples: int
    lower: float | None
    upper: float | None


@dataclass(frozen=True)
class ModeComparisonItem:
    metric: str
    baseline_mode: str
    comparison_mode: str
    baseline_value: float | None
    comparison_value: float | None
    absolute_difference: float | None
    statistically_significant: bool
    notes: str


@dataclass(frozen=True)
class PropositionTransitionRecord:
    proposition_id: str
    case_id: str
    category: str
    endpoint: str
    method: str
    spec_outcome: str
    source_outcome: str
    corr_outcome: str
    spec_to_corr: str
    source_to_corr: str
    effect_type: str
    rationale: str


@dataclass(frozen=True)
class TransitionSummary:
    comparison: str
    transition_counts: dict[str, int]
    propositions_by_transition: dict[str, list[str]]


@dataclass(frozen=True)
class ErrorTaxonomyItem:
    case_id: str
    proposition_id: str
    category: str
    mode: str
    outcome: str
    error_source_category: str
    rationale: str


@dataclass(frozen=True)
class StatisticalAnalysisResult:
    dataset_version: str
    total_cases: int
    dimension_a_propositions_count: int
    confidence_intervals: list[dict[str, Any]]
    mode_comparisons: list[dict[str, Any]]
    correlation_effects: dict[str, Any]
    error_analysis: dict[str, Any]
    limitations: list[str]


def compute_wilson_score_interval(
    k: int,
    n: int,
    confidence_level: float = 0.95,
) -> tuple[float | None, float | None]:
    """Compute 95% Wilson Score confidence interval for a binomial proportion k/n."""
    if n <= 0:
        return None, None

    p_hat = k / n
    if confidence_level == 0.95:
        z = 1.959963984540054
    else:
        z = 1.959963984540054

    z2 = z * z
    denom = 1 + z2 / n
    center = (p_hat + z2 / (2 * n)) / denom
    margin = (z / denom) * math.sqrt((p_hat * (1 - p_hat) / n) + (z2 / (4 * n * n)))

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)

    return round(lower, 4), round(upper, 4)


def compute_bootstrap_f1_ci(
    classifications: Sequence[PropositionClassification],
    mode: str,
    confidence_level: float = 0.95,
    n_resamples: int = 10000,
    seed: int = 42,
) -> F1ConfidenceInterval:
    """Compute 95% bootstrap percentile confidence interval for F1 score."""
    pop = compute_metric_population(classifications)
    estimate = pop.f1

    if not classifications or estimate is None:
        return F1ConfidenceInterval(
            metric="f1",
            mode=mode,
            estimate=estimate,
            confidence_level=confidence_level,
            method="bootstrap_percentile",
            sample_size=len(classifications),
            seed=seed,
            bootstrap_samples=n_resamples,
            lower=None,
            upper=None,
        )

    rng = random.Random(seed)
    n = len(classifications)
    bootstrap_f1s: list[float] = []

    for _ in range(n_resamples):
        sample = [rng.choice(classifications) for _ in range(n)]
        b_pop = compute_metric_population(sample)
        if b_pop.f1 is not None:
            bootstrap_f1s.append(b_pop.f1)

    if not bootstrap_f1s:
        return F1ConfidenceInterval(
            metric="f1",
            mode=mode,
            estimate=estimate,
            confidence_level=confidence_level,
            method="bootstrap_percentile",
            sample_size=n,
            seed=seed,
            bootstrap_samples=n_resamples,
            lower=None,
            upper=None,
        )

    bootstrap_f1s.sort()
    alpha = 1.0 - confidence_level
    lower_idx = max(0, int((alpha / 2.0) * len(bootstrap_f1s)))
    upper_idx = min(len(bootstrap_f1s) - 1, int((1.0 - alpha / 2.0) * len(bootstrap_f1s)))

    lower = round(bootstrap_f1s[lower_idx], 4)
    upper = round(bootstrap_f1s[upper_idx], 4)

    return F1ConfidenceInterval(
        metric="f1",
        mode=mode,
        estimate=round(estimate, 4) if estimate is not None else None,
        confidence_level=confidence_level,
        method="bootstrap_percentile",
        sample_size=n,
        seed=seed,
        bootstrap_samples=n_resamples,
        lower=lower,
        upper=upper,
    )


def compute_all_confidence_intervals(
    mode_results: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compute 95% confidence intervals across all metrics for each mode."""
    ci_list: list[dict[str, Any]] = []

    for mode_name, mode_res in mode_results.items():
        dim_a = mode_res.dimension_a
        classifications = dim_a.classifications
        pop = dim_a.overall_metrics

        # 1. Precision CI (Wilson)
        k_prec = pop.tp
        n_prec = pop.tp + pop.fp
        low_prec, up_prec = compute_wilson_score_interval(k_prec, n_prec)
        ci_list.append(
            asdict(
                ConfidenceInterval(
                    metric="precision",
                    mode=mode_name,
                    estimate=round(pop.precision, 4) if pop.precision is not None else None,
                    confidence_level=0.95,
                    method="wilson_score",
                    sample_size=n_prec,
                    lower=low_prec,
                    upper=up_prec,
                )
            )
        )

        # 2. Recall CI (Wilson)
        k_rec = pop.tp
        n_rec = pop.tp + pop.fn
        low_rec, up_rec = compute_wilson_score_interval(k_rec, n_rec)
        ci_list.append(
            asdict(
                ConfidenceInterval(
                    metric="recall",
                    mode=mode_name,
                    estimate=round(pop.recall, 4) if pop.recall is not None else None,
                    confidence_level=0.95,
                    method="wilson_score",
                    sample_size=n_rec,
                    lower=low_rec,
                    upper=up_rec,
                )
            )
        )

        # 3. FPR CI (Wilson)
        k_fpr = pop.fp
        n_fpr = pop.fp + pop.tn
        low_fpr, up_fpr = compute_wilson_score_interval(k_fpr, n_fpr)
        ci_list.append(
            asdict(
                ConfidenceInterval(
                    metric="fpr",
                    mode=mode_name,
                    estimate=round(pop.fpr, 4) if pop.fpr is not None else None,
                    confidence_level=0.95,
                    method="wilson_score",
                    sample_size=n_fpr,
                    lower=low_fpr,
                    upper=up_fpr,
                )
            )
        )

        # 4. FNR CI (Wilson)
        k_fnr = pop.fn
        n_fnr = pop.fn + pop.tp
        low_fnr, up_fnr = compute_wilson_score_interval(k_fnr, n_fnr)
        ci_list.append(
            asdict(
                ConfidenceInterval(
                    metric="fnr",
                    mode=mode_name,
                    estimate=round(pop.fnr, 4) if pop.fnr is not None else None,
                    confidence_level=0.95,
                    method="wilson_score",
                    sample_size=n_fnr,
                    lower=low_fnr,
                    upper=up_fnr,
                )
            )
        )

        # 5. F1 CI (Bootstrap)
        f1_ci = compute_bootstrap_f1_ci(classifications, mode=mode_name)
        ci_list.append(asdict(f1_ci))

        # 6. Dimension B Correlation Accuracy CI (only for CORRELATED mode)
        if mode_name == "CORRELATED":
            dim_b_score = mode_res.dimension_b.score
            k_b = dim_b_score.correct_count
            n_b = dim_b_score.total_count
            low_b, up_b = compute_wilson_score_interval(k_b, n_b)
            ci_list.append(
                asdict(
                    ConfidenceInterval(
                        metric="dimension_b_correlation_accuracy",
                        mode=mode_name,
                        estimate=round(dim_b_score.accuracy, 4),
                        confidence_level=0.95,
                        method="wilson_score",
                        sample_size=n_b,
                        lower=low_b,
                        upper=up_b,
                    )
                )
            )

            # 7. Dimension C Endpoint Match Accuracy CI (only for CORRELATED mode)
            dim_c_score = mode_res.dimension_c.score
            k_c = dim_c_score.correct_count
            n_c = dim_c_score.total_count
            low_c, up_c = compute_wilson_score_interval(k_c, n_c)
            ci_list.append(
                asdict(
                    ConfidenceInterval(
                        metric="dimension_c_endpoint_match_accuracy",
                        mode=mode_name,
                        estimate=round(dim_c_score.accuracy, 4),
                        confidence_level=0.95,
                        method="wilson_score",
                        sample_size=n_c,
                        lower=low_c,
                        upper=up_c,
                    )
                )
            )

    return ci_list


def compute_mode_comparisons(
    mode_results: dict[str, Any],
) -> list[dict[str, Any]]:
    """Compute absolute metric comparisons between CORRELATED and single-layer baselines."""
    comparisons: list[dict[str, Any]] = []

    corr_res = mode_results.get("CORRELATED")
    if not corr_res:
        return comparisons

    corr_metrics = corr_res.dimension_a.overall_metrics

    metric_names = ("precision", "recall", "f1", "fpr", "fnr")

    for baseline_name in ("SPEC_ONLY", "SOURCE_ONLY"):
        base_res = mode_results.get(baseline_name)
        if not base_res:
            continue
        base_metrics = base_res.dimension_a.overall_metrics

        for m in metric_names:
            base_val = getattr(base_metrics, m)
            corr_val = getattr(corr_metrics, m)

            if base_val is not None and corr_val is not None:
                diff = round(corr_val - base_val, 4)
                base_v_round = round(base_val, 4)
                corr_v_round = round(corr_val, 4)
            else:
                diff = None
                base_v_round = round(base_val, 4) if base_val is not None else None
                corr_v_round = round(corr_val, 4) if corr_val is not None else None

            notes = (
                f"Absolute difference comparing {baseline_name} against CORRELATED mode. "
                "Statistical significance is not claimed due to small benchmark sample size "
                "(N=22 propositions)."
            )

            comparisons.append(
                asdict(
                    ModeComparisonItem(
                        metric=m,
                        baseline_mode=baseline_name,
                        comparison_mode="CORRELATED",
                        baseline_value=base_v_round,
                        comparison_value=corr_v_round,
                        absolute_difference=diff,
                        statistically_significant=False,
                        notes=notes,
                    )
                )
            )

    return comparisons


def compute_correlation_effect_transitions(
    mode_results: dict[str, Any],
) -> dict[str, Any]:
    """Dynamically discover propositions and track transition pathways across modes."""
    spec_mode = mode_results.get("SPEC_ONLY")
    source_mode = mode_results.get("SOURCE_ONLY")
    corr_mode = mode_results.get("CORRELATED")

    if not spec_mode or not source_mode or not corr_mode:
        return {"records": [], "spec_to_corr": {}, "source_to_corr": {}}

    spec_map = {c.proposition_id: c for c in spec_mode.dimension_a.classifications}
    source_map = {c.proposition_id: c for c in source_mode.dimension_a.classifications}
    corr_map = {c.proposition_id: c for c in corr_mode.dimension_a.classifications}

    all_prop_ids = sorted(list(spec_map.keys()))

    records: list[dict[str, Any]] = []

    spec_counts: dict[str, int] = {}
    spec_props: dict[str, list[str]] = {}

    source_counts: dict[str, int] = {}
    source_props: dict[str, list[str]] = {}

    for pid in all_prop_ids:
        sp_c = spec_map[pid]
        so_c = source_map[pid]
        co_c = corr_map[pid]

        sp_out = sp_c.outcome.value
        so_out = so_c.outcome.value
        co_out = co_c.outcome.value

        spec_trans = f"{sp_out}_TO_{co_out}"
        source_trans = f"{so_out}_TO_{co_out}"

        spec_counts[spec_trans] = spec_counts.get(spec_trans, 0) + 1
        spec_props.setdefault(spec_trans, []).append(pid)

        source_counts[source_trans] = source_counts.get(source_trans, 0) + 1
        source_props.setdefault(source_trans, []).append(pid)

        # Categorize overall correlation effect
        if (sp_out == "FN" or so_out == "FN") and co_out == "TP":
            effect_type = "FN_REMOVED"
        elif (sp_out == "FP" or so_out == "FP") and co_out == "TN":
            effect_type = "FP_REMOVED"
        elif so_out == "TP" and co_out == "FN":
            effect_type = "FN_INTRODUCED"
        elif sp_out == "TN" and so_out == "TN" and co_out == "TP":
            effect_type = "TP_INTRODUCED"
        elif sp_out == "TN" and so_out == "TN" and co_out == "FP":
            effect_type = "NEW_FP"
        else:
            effect_type = f"{so_out}_TO_{co_out}"

        rationale = (
            co_c.rationale
            or f"Transitioned from SPEC={sp_out}, SOURCE={so_out} to CORRELATED={co_out}"
        )

        rec = PropositionTransitionRecord(
            proposition_id=pid,
            case_id=sp_c.case_id,
            category=sp_c.category,
            endpoint=sp_c.endpoint,
            method=sp_c.method,
            spec_outcome=sp_out,
            source_outcome=so_out,
            corr_outcome=co_out,
            spec_to_corr=spec_trans,
            source_to_corr=source_trans,
            effect_type=effect_type,
            rationale=rationale,
        )
        records.append(asdict(rec))

    return {
        "proposition_count": len(all_prop_ids),
        "records": records,
        "spec_to_correlated_summary": asdict(
            TransitionSummary(
                comparison="SPEC_ONLY_TO_CORRELATED",
                transition_counts=spec_counts,
                propositions_by_transition=spec_props,
            )
        ),
        "source_to_correlated_summary": asdict(
            TransitionSummary(
                comparison="SOURCE_ONLY_TO_CORRELATED",
                transition_counts=source_counts,
                propositions_by_transition=source_props,
            )
        ),
    }


def compute_error_taxonomy_analysis(
    mode_results: dict[str, Any],
) -> dict[str, Any]:
    """Taxonomize false positives and false negatives into explicit error source categories."""
    error_items: list[dict[str, Any]] = []
    category_counts: dict[str, dict[str, int]] = {
        "SPEC_ONLY": {},
        "SOURCE_ONLY": {},
        "CORRELATED": {},
    }

    for mode_name, mode_res in mode_results.items():
        classifications = mode_res.dimension_a.classifications

        for c in classifications:
            outcome = c.outcome.value
            if outcome in ("TP", "TN"):
                continue

            # Categorize error source
            if c.proposition_id == "PROP-SECRET-001" and mode_name == "CORRELATED":
                err_cat = "SOURCE_INTRINSIC_NON_ENDPOINT"
                rat = (
                    "Hardcoded source secret without OpenAPI counterpart. Non-endpoint "
                    "finding intentionally excluded from cross-layer correlation pipeline; "
                    "not a correlation engine defect."
                )
            elif mode_name == "SPEC_ONLY":
                err_cat = "SPECIFICATION"
                rat = (
                    "Specification-only analysis lacks source code execution context "
                    f"for {c.proposition_id} ({c.condition})."
                )
            elif mode_name == "SOURCE_ONLY":
                err_cat = "SOURCE"
                rat = (
                    "Source static analysis lacks OpenAPI specification contract context "
                    f"for {c.proposition_id} ({c.condition})."
                )
            elif mode_name == "CORRELATED" and outcome == "FN":
                if c.category in ("secrets", "sensitive_data"):
                    err_cat = "SOURCE_INTRINSIC_NON_ENDPOINT"
                    rat = (
                        "Non-endpoint or schema-masked finding omitted from correlation "
                        f"findings for {c.proposition_id}."
                    )
                else:
                    err_cat = "CORRELATION"
                    rat = f"Correlation engine rule heuristic did not match for {c.proposition_id}."
            elif mode_name == "CORRELATED" and outcome == "FP":
                err_cat = "CORRELATION"
                rat = f"Correlation engine emitted unrefuted false positive for {c.proposition_id}."
            else:
                err_cat = "OTHER"
                rat = f"Uncategorized error for proposition {c.proposition_id}."

            category_counts[mode_name][err_cat] = category_counts[mode_name].get(err_cat, 0) + 1

            error_item = ErrorTaxonomyItem(
                case_id=c.case_id,
                proposition_id=c.proposition_id,
                category=c.category,
                mode=mode_name,
                outcome=outcome,
                error_source_category=err_cat,
                rationale=rat,
            )
            error_items.append(asdict(error_item))

    return {
        "total_errors_analyzed": len(error_items),
        "error_category_counts_by_mode": category_counts,
        "error_details": error_items,
    }


def get_research_limitations() -> list[str]:
    """Return explicit research limitations for Phase 7 report."""
    return [
        "Benchmark contains 24 total benchmark cases and 22 Dimension-A security propositions.",
        (
            "Dimension-A propositions are evaluated against a controlled, synthetic "
            "benchmark dataset."
        ),
        (
            "Confidence intervals (95% Wilson score and bootstrap percentile) reflect "
            "small-sample uncertainty bounds (N=22)."
        ),
        (
            "Experimental metrics and precision/recall tradeoffs should not be "
            "extrapolated to arbitrary commercial REST APIs without broader sampling."
        ),
        (
            "The CORRELATED layer is a cross-layer evidence synthesis layer, not a "
            "cumulative union of all single-layer findings."
        ),
        (
            "Source-intrinsic non-endpoint findings (e.g., standalone hardcoded secrets "
            "without OpenAPI counterparts) remain absent from CORRELATED findings by design."
        ),
        ("Ground-truth declarations govern classification metrics and error taxonomy assignments."),
    ]


def run_phase7_statistical_analysis(
    report_data: Any,
) -> StatisticalAnalysisResult:
    """Execute complete Phase 7 statistical analysis pipeline over evaluation report data."""
    mode_results = report_data.mode_results

    ci_list = compute_all_confidence_intervals(mode_results)
    mode_comps = compute_mode_comparisons(mode_results)
    corr_effects = compute_correlation_effect_transitions(mode_results)
    error_analysis = compute_error_taxonomy_analysis(mode_results)
    limitations = get_research_limitations()

    return StatisticalAnalysisResult(
        dataset_version=report_data.dataset_version,
        total_cases=len(mode_results["CORRELATED"].dimension_a.classifications),  # or 24
        dimension_a_propositions_count=corr_effects["proposition_count"],
        confidence_intervals=ci_list,
        mode_comparisons=mode_comps,
        correlation_effects=corr_effects,
        error_analysis=error_analysis,
        limitations=limitations,
    )
