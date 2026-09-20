from collections.abc import Sequence
from typing import Any

from app.analysis.correlation.models import CorrelatedFinding, MultiLayerAnalysisResult
from app.analysis.findings import Finding
from app.evaluation.models import (
    ClassificationOutcome,
    ExpectedCorrelationState,
    ExpectedEndpointPair,
    PropositionClassification,
    SecurityProposition,
)

# Rule category mappings to standard security categories
CATEGORY_RULE_MAP = {
    "authentication": {"MISSING_AUTH", "INCONSISTENT_AUTH", "SRC-002", "AUTH_MISSING"},
    "authorization": {"BOLA_IDOR_INDICATOR", "SRC-003", "AUTHZ_MISSING"},
    "input_validation": {"INPUT_CONSTRAINTS", "UNCONSTRAINED_INPUT"},
    "sensitive_data": {"SENSITIVE_DATA_EXPOSURE", "SENSITIVE_DATA"},
    "secrets": {"HARDCODED_SECRET", "SRC-001"},
}


def _rule_matches_category(rule_id: str, category: str) -> bool:
    """Check whether a rule_id belongs to the evaluated security category."""
    rule_upper = rule_id.upper()
    cat_lower = category.lower()

    if cat_lower == "authentication" and any(k in rule_upper for k in ("AUTH", "AUTHENTICATION")):
        return True
    if cat_lower == "authorization" and any(
        k in rule_upper for k in ("AUTHZ", "AUTHORIZATION", "BOLA", "IDOR")
    ):
        return True
    if cat_lower == "input_validation" and any(
        k in rule_upper for k in ("INPUT", "CONSTRAINT", "VALIDATION")
    ):
        return True
    if cat_lower == "sensitive_data" and any(
        k in rule_upper for k in ("DATA", "SENSITIVE", "EXPOSURE")
    ):
        return True
    if cat_lower == "secrets" and any(
        k in rule_upper for k in ("SECRET", "CREDENTIAL", "HARDCODED")
    ):
        return True

    allowed = CATEGORY_RULE_MAP.get(cat_lower, set())
    return any(a in rule_upper for a in allowed)


def find_matching_finding(
    findings: Sequence[Finding],
    proposition: SecurityProposition,
) -> Finding | None:
    """Find an analyzer finding matching the proposition category and endpoint."""
    for f in findings:
        if not _rule_matches_category(f.rule_id, proposition.category):
            continue

        # Check evidence for endpoint matching if present or endpoint field in CorrelatedFinding
        if proposition.endpoint == "N/A":
            return f

        # For correlated findings with matched_endpoint
        if isinstance(f, CorrelatedFinding) and f.matched_endpoint:
            ep = f.matched_endpoint
            if (
                ep.spec_path == proposition.endpoint
                or ep.canonical_matching_path == proposition.endpoint
            ):
                return f

        # Check evidence strings or rationale
        for ev in f.evidence:
            if ev.message and proposition.endpoint in ev.message:
                return f
            if ev.file and proposition.endpoint in ev.file:
                return f

        if proposition.endpoint in f.title or proposition.endpoint in f.rationale:
            return f

    return None


def evaluate_security_proposition(
    proposition: SecurityProposition,
    case_id: str,
    findings: Sequence[Finding],
) -> PropositionClassification:
    """Evaluate a single security proposition returning TP, FP, FN, or TN."""
    matching_finding = find_matching_finding(findings, proposition)
    finding_present = matching_finding is not None
    rule_id = matching_finding.rule_id if matching_finding else None

    if proposition.expected:
        if finding_present:
            outcome = ClassificationOutcome.TP
            rat = (
                f"Security condition expected present for '{proposition.endpoint}'; "
                f"matching finding '{rule_id}' detected."
            )
        else:
            outcome = ClassificationOutcome.FN
            rat = (
                f"Security condition expected present for '{proposition.endpoint}'; "
                f"no matching finding detected."
            )
    else:
        if finding_present:
            outcome = ClassificationOutcome.FP
            rat = (
                f"Security condition expected absent/safe for '{proposition.endpoint}'; "
                f"finding '{rule_id}' reported."
            )
        else:
            outcome = ClassificationOutcome.TN
            rat = (
                f"Security condition expected absent/safe for '{proposition.endpoint}'; "
                f"no finding reported."
            )

    return PropositionClassification(
        proposition_id=proposition.proposition_id,
        case_id=case_id,
        category=proposition.category,
        endpoint=proposition.endpoint,
        method=proposition.method,
        condition=proposition.condition,
        expected=proposition.expected,
        outcome=outcome,
        finding_rule_id=rule_id,
        rationale=rat,
    )


def evaluate_correlation_state(
    expected_corr: ExpectedCorrelationState,
    result: MultiLayerAnalysisResult,
) -> dict[str, Any]:
    """Evaluate Dimension B correlation state expectation against analysis result."""
    actual_state = "INCONCLUSIVE"
    matching_finding: CorrelatedFinding | None = None

    for cf in result.correlated_findings:
        if _rule_matches_category(cf.rule_id, expected_corr.category):
            if expected_corr.endpoint == "N/A" or (
                cf.matched_endpoint and cf.matched_endpoint.spec_path == expected_corr.endpoint
            ):
                actual_state = cf.correlation_state
                matching_finding = cf
                break

    is_correct = actual_state == expected_corr.expected_state
    return {
        "target_id": expected_corr.target_id,
        "category": expected_corr.category,
        "endpoint": expected_corr.endpoint,
        "expected_state": expected_corr.expected_state,
        "actual_state": actual_state,
        "is_correct": is_correct,
        "finding_rule_id": matching_finding.rule_id if matching_finding else None,
    }


def evaluate_endpoint_pair(
    expected_pair: ExpectedEndpointPair,
    result: MultiLayerAnalysisResult,
) -> dict[str, Any]:
    """Evaluate Dimension C endpoint match expectation against analysis result."""
    actual_match_state = "NO_MATCH"

    for mp in result.matched_endpoints:
        if mp.spec_path == expected_pair.spec_path and mp.spec_method == expected_pair.spec_method:
            actual_match_state = str(mp.match_state)
            break

    is_correct = actual_match_state == expected_pair.expected_match_state
    return {
        "pair_id": expected_pair.pair_id,
        "spec_path": expected_pair.spec_path,
        "spec_method": expected_pair.spec_method,
        "expected_match_state": expected_pair.expected_match_state,
        "actual_match_state": actual_match_state,
        "is_correct": is_correct,
    }
