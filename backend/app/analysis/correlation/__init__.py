from app.analysis.correlation.engine import CorrelationEngine
from app.analysis.correlation.matcher import match_endpoints, normalize_to_canonical_template
from app.analysis.correlation.metrics import ResearchEvaluationMetrics, compute_correlation_metrics
from app.analysis.correlation.models import (
    AnalysisLayer,
    CorrelatedEvidencePair,
    CorrelatedFinding,
    CorrelationState,
    EndpointMatchState,
    MatchedEndpointPair,
    MultiLayerAnalysisResult,
)

__all__ = [
    "AnalysisLayer",
    "CorrelatedEvidencePair",
    "CorrelatedFinding",
    "CorrelationEngine",
    "CorrelationState",
    "EndpointMatchState",
    "MatchedEndpointPair",
    "MultiLayerAnalysisResult",
    "ResearchEvaluationMetrics",
    "compute_correlation_metrics",
    "match_endpoints",
    "normalize_to_canonical_template",
]
