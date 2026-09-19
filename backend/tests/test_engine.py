from datetime import datetime

from app.analysis.context import (
    AnalysisContext,
    NormalizedOpenAPI,
    NormalizedSourceTree,
    ScanMetadata,
)
from app.analysis.engine import ENGINE_VERSION, RULE_SET_VERSION, AnalysisEngine
from app.analysis.findings import Evidence, Finding, Severity
from app.analysis.rules.base import SecurityRule
from app.analysis.rules.registry import RuleRegistry


class RuleOne(SecurityRule):
    rule_id = "SEC-001"
    rule_version = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        ev = Evidence(kind="test", message="Indicator from rule 1", file="api.py", line=10)
        return [
            Finding(
                rule_id=self.rule_id,
                rule_version=self.rule_version,
                title="Finding 1",
                severity=Severity.LOW,
                confidence=0.6,
                rationale="Test rationale 1",
                remediation="Test remediation 1",
                evidence=(ev,),
            )
        ]


class RuleTwo(SecurityRule):
    rule_id = "SEC-002"
    rule_version = "2.0.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        ev = Evidence(kind="test", message="Indicator from rule 2", file="spec.yaml", line=20)
        return [
            Finding(
                rule_id=self.rule_id,
                rule_version=self.rule_version,
                title="Finding 2",
                severity=Severity.HIGH,
                confidence=0.9,
                rationale="Test rationale 2",
                remediation="Test remediation 2",
                evidence=(ev,),
            )
        ]


def test_analysis_engine_dispatches_and_aggregates_findings() -> None:
    registry = RuleRegistry()
    registry.register(RuleOne())
    registry.register(RuleTwo())

    engine = AnalysisEngine(registry=registry)
    context = AnalysisContext()
    result = engine.analyze(context)

    assert result.evaluated_rules_count == 2
    assert len(result.findings) == 2
    assert {f.rule_id for f in result.findings} == {"SEC-001", "SEC-002"}
    assert result.engine_version == ENGINE_VERSION
    assert result.rule_set_version == RULE_SET_VERSION
    assert result.config_version == "1.0.0"
    assert isinstance(result.started_at, datetime)
    assert isinstance(result.completed_at, datetime)
    assert result.completed_at >= result.started_at


def test_analysis_engine_reproducibility_hashes() -> None:
    registry = RuleRegistry()
    registry.register(RuleOne())

    engine = AnalysisEngine(
        registry=registry,
        engine_version="0.2.0",
        rule_set_version="1.5.0",
        config_version="scan-cfg-v2",
    )
    spec = NormalizedOpenAPI(title="Test", spec_hash="sha256:spec_hash_val")
    source = NormalizedSourceTree(source_hash="sha256:source_hash_val")
    metadata = ScanMetadata(
        engine_version="0.2.0",
        rule_set_version="1.5.0",
        config_version="scan-cfg-v2",
        spec_hash="sha256:spec_hash_val",
        source_hash="sha256:source_hash_val",
    )
    context = AnalysisContext(specification=spec, source=source, metadata=metadata)

    result = engine.analyze(context)

    assert result.engine_version == "0.2.0"
    assert result.rule_set_version == "1.5.0"
    assert result.config_version == "scan-cfg-v2"
    assert result.spec_hash == "sha256:spec_hash_val"
    assert result.source_hash == "sha256:source_hash_val"
    assert result.evaluated_rules_count == 1
    assert len(result.findings) == 1
