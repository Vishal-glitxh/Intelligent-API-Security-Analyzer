from collections.abc import Sequence
from typing import Any

from app.analysis.correlation.models import CorrelatedFinding, MultiLayerAnalysisResult
from app.analysis.findings import Finding
from app.evaluation.models import (
    ClassificationOutcome,
    CorrelationStateScore,
    EndpointMatchingScore,
    EvidenceCompletenessScore,
    ExplainabilityCriterionStatus,
    ExplainabilityScore,
    MetricPopulation,
    PropositionClassification,
)


def compute_metric_population(
    classifications: Sequence[PropositionClassification],
) -> MetricPopulation:
    """Compute Precision, Recall, F1, FPR, FNR with explicit zero-denominator safety."""
    tp = sum(1 for c in classifications if c.outcome == ClassificationOutcome.TP)
    fp = sum(1 for c in classifications if c.outcome == ClassificationOutcome.FP)
    fn = sum(1 for c in classifications if c.outcome == ClassificationOutcome.FN)
    tn = sum(1 for c in classifications if c.outcome == ClassificationOutcome.TN)

    reasons: dict[str, str] = {}

    # Precision = TP / (TP + FP)
    if tp + fp > 0:
        precision: float | None = tp / (tp + fp)
    else:
        precision = None
        reasons["precision"] = "Zero positive predictions (TP + FP == 0)"

    # Recall = TP / (TP + FN)
    if tp + fn > 0:
        recall: float | None = tp / (tp + fn)
    else:
        recall = None
        reasons["recall"] = "Zero actual positive conditions (TP + FN == 0)"

    # F1 = 2 * Precision * Recall / (Precision + Recall)
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1: float | None = 2 * precision * recall / (precision + recall)
    else:
        f1 = None
        reasons["f1"] = "Precision and/or Recall undefined or sum to zero"

    # FPR = FP / (FP + TN)
    if fp + tn > 0:
        fpr: float | None = fp / (fp + tn)
    else:
        fpr = None
        reasons["fpr"] = "Zero actual negative conditions (FP + TN == 0)"

    # FNR = FN / (FN + TP)
    if fn + tp > 0:
        fnr: float | None = fn / (fn + tp)
    else:
        fnr = None
        reasons["fnr"] = "Zero actual positive conditions (FN + TP == 0)"

    return MetricPopulation(
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        precision=precision,
        recall=recall,
        f1=f1,
        fpr=fpr,
        fnr=fnr,
        undefined_reasons=reasons,
    )


def evaluate_evidence_completeness(
    mode: str,
    results: Sequence[MultiLayerAnalysisResult],
) -> EvidenceCompletenessScore:
    """Evaluate evidence field completeness without penalizing single-layer modes for N/A fields."""
    present_count = 0
    missing_count = 0
    not_applicable_count = 0
    detail: dict[str, str] = {}

    for res in results:
        findings: Sequence[Finding]
        if mode == "SPEC_ONLY":
            findings = res.spec_only_findings
        elif mode == "SOURCE_ONLY":
            findings = res.source_only_findings
        else:
            findings = res.correlated_findings

        for f in findings:
            # Field 1: Rule Identifier
            if f.rule_id:
                present_count += 1
            else:
                missing_count += 1

            # Field 2: Rationale
            if f.rationale:
                present_count += 1
            else:
                missing_count += 1

            # Field 3: Evidence Array
            if f.evidence:
                present_count += 1
            else:
                missing_count += 1

            # Field 4: Provenance (File & Line)
            has_prov = any(e.file is not None for e in f.evidence)
            if mode == "SPEC_ONLY":
                # In SPEC_ONLY mode, source line provenance is NOT APPLICABLE
                not_applicable_count += 1
            elif has_prov:
                present_count += 1
            else:
                missing_count += 1

            # Field 5: Cross-Layer Correlation State
            if mode in ("SPEC_ONLY", "SOURCE_ONLY"):
                not_applicable_count += 1
            elif isinstance(f, CorrelatedFinding) and f.correlation_state:
                present_count += 1
            else:
                missing_count += 1

    applicable_total = present_count + missing_count
    score = (present_count / applicable_total) if applicable_total > 0 else 1.0

    detail["present"] = str(present_count)
    detail["missing"] = str(missing_count)
    detail["not_applicable"] = str(not_applicable_count)

    return EvidenceCompletenessScore(
        mode=mode,
        present_count=present_count,
        missing_count=missing_count,
        not_applicable_count=not_applicable_count,
        score=score,
        detail=detail,
    )


def evaluate_explainability_rubric(
    mode: str,
    results: Sequence[MultiLayerAnalysisResult],
) -> ExplainabilityScore:
    """Evaluate explainability rubric across 7 criteria supporting PRESENT/MISSING/N/A."""
    criteria_map: dict[str, list[ExplainabilityCriterionStatus]] = {
        "affected_endpoint": [],
        "security_condition": [],
        "rule_identifier": [],
        "evidence_detail": [],
        "provenance_file_line": [],
        "rationale": [],
        "correlation_relationship": [],
    }

    for res in results:
        findings: Sequence[Finding]
        if mode == "SPEC_ONLY":
            findings = res.spec_only_findings
        elif mode == "SOURCE_ONLY":
            findings = res.source_only_findings
        else:
            findings = res.correlated_findings

        for f in findings:
            # 1. Affected Endpoint
            has_ep = bool(
                (isinstance(f, CorrelatedFinding) and f.matched_endpoint)
                or any(e.message and "/" in e.message for e in f.evidence)
                or "/" in f.title
            )
            status_ep = (
                ExplainabilityCriterionStatus.PRESENT
                if has_ep
                else ExplainabilityCriterionStatus.MISSING
            )
            criteria_map["affected_endpoint"].append(status_ep)

            # 2. Security Condition
            status_cond = (
                ExplainabilityCriterionStatus.PRESENT
                if bool(f.title)
                else ExplainabilityCriterionStatus.MISSING
            )
            criteria_map["security_condition"].append(status_cond)

            # 3. Rule Identifier
            status_rule = (
                ExplainabilityCriterionStatus.PRESENT
                if bool(f.rule_id)
                else ExplainabilityCriterionStatus.MISSING
            )
            criteria_map["rule_identifier"].append(status_rule)

            # 4. Evidence Detail
            status_ev = (
                ExplainabilityCriterionStatus.PRESENT
                if bool(f.evidence)
                else ExplainabilityCriterionStatus.MISSING
            )
            criteria_map["evidence_detail"].append(status_ev)

            # 5. Provenance (File & Line)
            if mode == "SPEC_ONLY":
                criteria_map["provenance_file_line"].append(
                    ExplainabilityCriterionStatus.NOT_APPLICABLE
                )
            else:
                has_prov = any(e.file is not None for e in f.evidence)
                status_prov = (
                    ExplainabilityCriterionStatus.PRESENT
                    if has_prov
                    else ExplainabilityCriterionStatus.MISSING
                )
                criteria_map["provenance_file_line"].append(status_prov)

            # 6. Rationale
            status_rat = (
                ExplainabilityCriterionStatus.PRESENT
                if bool(f.rationale)
                else ExplainabilityCriterionStatus.MISSING
            )
            criteria_map["rationale"].append(status_rat)

            # 7. Correlation Relationship
            if mode in ("SPEC_ONLY", "SOURCE_ONLY"):
                criteria_map["correlation_relationship"].append(
                    ExplainabilityCriterionStatus.NOT_APPLICABLE
                )
            else:
                has_corr = isinstance(f, CorrelatedFinding) and bool(f.correlation_state)
                status_corr = (
                    ExplainabilityCriterionStatus.PRESENT
                    if has_corr
                    else ExplainabilityCriterionStatus.MISSING
                )
                criteria_map["correlation_relationship"].append(status_corr)

    # Compute overall score over APPLICABLE criteria
    total_present = 0
    total_applicable = 0
    summary_breakdown: dict[str, ExplainabilityCriterionStatus] = {}

    for c_name, statuses in criteria_map.items():
        if not statuses:
            summary_breakdown[c_name] = ExplainabilityCriterionStatus.PRESENT
            continue

        p_cnt = sum(1 for s in statuses if s == ExplainabilityCriterionStatus.PRESENT)
        m_cnt = sum(1 for s in statuses if s == ExplainabilityCriterionStatus.MISSING)
        na_cnt = sum(1 for s in statuses if s == ExplainabilityCriterionStatus.NOT_APPLICABLE)

        total_present += p_cnt
        total_applicable += p_cnt + m_cnt

        if na_cnt == len(statuses):
            summary_breakdown[c_name] = ExplainabilityCriterionStatus.NOT_APPLICABLE
        elif p_cnt >= m_cnt:
            summary_breakdown[c_name] = ExplainabilityCriterionStatus.PRESENT
        else:
            summary_breakdown[c_name] = ExplainabilityCriterionStatus.MISSING

    score = (total_present / total_applicable) if total_applicable > 0 else 1.0

    return ExplainabilityScore(
        mode=mode,
        score=score,
        criteria_breakdown=summary_breakdown,
    )


def compute_dimension_b_score(
    correlation_evals: Sequence[dict[str, Any]],
) -> CorrelationStateScore:
    """Compute Dimension B Correlation Evaluation accuracy and breakdown."""
    if not correlation_evals:
        return CorrelationStateScore(correct_count=0, total_count=0, accuracy=1.0)

    correct_count = sum(1 for e in correlation_evals if e["is_correct"])
    total_count = len(correlation_evals)
    accuracy = correct_count / total_count

    breakdown: dict[str, int] = {}
    for e in correlation_evals:
        state = e["actual_state"]
        breakdown[state] = breakdown.get(state, 0) + 1

    return CorrelationStateScore(
        correct_count=correct_count,
        total_count=total_count,
        accuracy=accuracy,
        state_breakdown=breakdown,
    )


def compute_dimension_c_score(
    endpoint_evals: Sequence[dict[str, Any]],
) -> EndpointMatchingScore:
    """Compute Dimension C Endpoint Matching Evaluation accuracy and confusion matrix."""
    if not endpoint_evals:
        return EndpointMatchingScore(correct_count=0, total_count=0, accuracy=1.0)

    correct_count = sum(1 for e in endpoint_evals if e["is_correct"])
    total_count = len(endpoint_evals)
    accuracy = correct_count / total_count

    matrix: dict[str, int] = {}
    for e in endpoint_evals:
        key = f"{e['expected_match_state']}->{e['actual_match_state']}"
        matrix[key] = matrix.get(key, 0) + 1

    return EndpointMatchingScore(
        correct_count=correct_count,
        total_count=total_count,
        accuracy=accuracy,
        confusion_matrix=matrix,
    )
