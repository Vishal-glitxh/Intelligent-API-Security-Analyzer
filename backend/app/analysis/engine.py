from dataclasses import dataclass
from datetime import UTC, datetime

from app.analysis.context import AnalysisContext
from app.analysis.findings import Finding
from app.analysis.rules.registry import RuleRegistry

ENGINE_VERSION = "0.1.0"
RULE_SET_VERSION = "0.1.0"


@dataclass(frozen=True)
class AnalysisResult:
    """Immutable result of an analysis run capturing findings and execution metadata."""

    findings: tuple[Finding, ...]
    evaluated_rules_count: int
    engine_version: str
    rule_set_version: str
    config_version: str
    started_at: datetime
    completed_at: datetime
    spec_hash: str | None = None
    source_hash: str | None = None


class AnalysisEngine:
    def __init__(
        self,
        registry: RuleRegistry,
        engine_version: str = ENGINE_VERSION,
        rule_set_version: str = RULE_SET_VERSION,
        config_version: str = "1.0.0",
    ) -> None:
        self.registry = registry
        self.engine_version = engine_version
        self.rule_set_version = rule_set_version
        self.config_version = config_version

    def analyze(self, context: AnalysisContext) -> AnalysisResult:
        started_at = datetime.now(UTC)
        findings: list[Finding] = []
        rules = self.registry.all()

        for rule in rules:
            findings.extend(rule.analyze(context))

        completed_at = datetime.now(UTC)

        spec_hash: str | None = None
        if context.specification and context.specification.spec_hash:
            spec_hash = context.specification.spec_hash
        elif context.metadata and context.metadata.spec_hash:
            spec_hash = context.metadata.spec_hash

        source_hash: str | None = None
        if context.source and context.source.source_hash:
            source_hash = context.source.source_hash
        elif context.metadata and context.metadata.source_hash:
            source_hash = context.metadata.source_hash

        config_version = (
            context.metadata.config_version if context.metadata else self.config_version
        )

        return AnalysisResult(
            findings=tuple(findings),
            evaluated_rules_count=len(rules),
            engine_version=self.engine_version,
            rule_set_version=self.rule_set_version,
            config_version=config_version,
            started_at=started_at,
            completed_at=completed_at,
            spec_hash=spec_hash,
            source_hash=source_hash,
        )
