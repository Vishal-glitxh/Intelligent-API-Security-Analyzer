from abc import ABC, abstractmethod
from collections.abc import Sequence

from app.analysis.context import AnalysisContext
from app.analysis.correlation.models import CorrelatedFinding, MatchedEndpointPair
from app.analysis.findings import Finding


class CorrelationRule(ABC):
    """Abstract base class for deterministic multi-layer evidence correlation rules."""

    rule_id: str
    rule_version: str = "1.0.0"

    @abstractmethod
    def correlate(
        self,
        context: AnalysisContext,
        matched_pairs: Sequence[MatchedEndpointPair],
        spec_findings: Sequence[Finding],
        source_findings: Sequence[Finding],
    ) -> list[CorrelatedFinding]:
        """Evaluates matched cross-layer endpoint pairs and findings, emitting findings."""
        pass
