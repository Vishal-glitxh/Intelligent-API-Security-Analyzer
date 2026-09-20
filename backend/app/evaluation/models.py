from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class GroundTruthLabel(StrEnum):
    SECURITY_CONDITION_PRESENT = "SECURITY_CONDITION_PRESENT"
    SECURITY_CONDITION_ABSENT = "SECURITY_CONDITION_ABSENT"
    INTENTIONAL_PUBLIC = "INTENTIONAL_PUBLIC"
    CROSS_LAYER_CONTRADICTION = "CROSS_LAYER_CONTRADICTION"
    ENDPOINT_MATCH = "ENDPOINT_MATCH"


class ClassificationOutcome(StrEnum):
    TP = "TP"
    FP = "FP"
    FN = "FN"
    TN = "TN"


class ExplainabilityCriterionStatus(StrEnum):
    PRESENT = "PRESENT"
    MISSING = "MISSING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class SecurityProposition:
    proposition_id: str
    category: str
    endpoint: str
    method: str
    condition: str
    expected: bool


@dataclass(frozen=True)
class ExpectedEndpointPair:
    pair_id: str
    spec_path: str
    spec_method: str
    source_path: str | None
    source_method: str | None
    expected_match_state: str


@dataclass(frozen=True)
class ExpectedCorrelationState:
    target_id: str
    category: str
    endpoint: str
    method: str
    expected_state: str


@dataclass(frozen=True)
class CaseGroundTruth:
    case_id: str
    category: str
    description: str
    ground_truth_label: GroundTruthLabel
    propositions: tuple[SecurityProposition, ...] = ()
    expected_endpoint_pairs: tuple[ExpectedEndpointPair, ...] = ()
    expected_correlations: tuple[ExpectedCorrelationState, ...] = ()
    rationale: str = ""
    dataset_version: str = "6.0.0"
    evaluation_role: str = "FINAL"


@dataclass(frozen=True)
class PropositionClassification:
    proposition_id: str
    case_id: str
    category: str
    endpoint: str
    method: str
    condition: str
    expected: bool
    outcome: ClassificationOutcome
    finding_rule_id: str | None = None
    rationale: str = ""


@dataclass(frozen=True)
class MetricPopulation:
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float | None
    recall: float | None
    f1: float | None
    fpr: float | None
    fnr: float | None
    undefined_reasons: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class EvidenceCompletenessScore:
    mode: str
    present_count: int
    missing_count: int
    not_applicable_count: int
    score: float
    detail: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ExplainabilityScore:
    mode: str
    score: float
    criteria_breakdown: dict[str, ExplainabilityCriterionStatus] = field(default_factory=dict)


@dataclass(frozen=True)
class EndpointMatchingScore:
    correct_count: int
    total_count: int
    accuracy: float
    confusion_matrix: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class CorrelationStateScore:
    correct_count: int
    total_count: int
    accuracy: float
    state_breakdown: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class DimensionAResult:
    overall_metrics: MetricPopulation
    category_metrics: dict[str, MetricPopulation]
    classifications: tuple[PropositionClassification, ...]


@dataclass(frozen=True)
class DimensionBResult:
    score: CorrelationStateScore
    details: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class DimensionCResult:
    score: EndpointMatchingScore
    details: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class EvaluationModeResult:
    mode: str
    dimension_a: DimensionAResult
    dimension_b: DimensionBResult
    dimension_c: DimensionCResult
    evidence_completeness: EvidenceCompletenessScore
    explainability: ExplainabilityScore


@dataclass(frozen=True)
class EvaluationReportData:
    experiment_id: str
    dataset_version: str
    analyzer_version: str
    rule_set_version: str
    config_version: str
    python_version: str
    platform_info: str
    execution_timestamp: str
    mode_results: dict[str, EvaluationModeResult]
