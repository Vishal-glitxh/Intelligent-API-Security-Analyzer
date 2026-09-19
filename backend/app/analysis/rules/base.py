from abc import ABC, abstractmethod

from app.analysis.context import AnalysisContext
from app.analysis.findings import Finding


class SecurityRule(ABC):
    rule_id: str
    rule_version: str

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Return evidence-backed findings for the supplied context."""
        raise NotImplementedError
