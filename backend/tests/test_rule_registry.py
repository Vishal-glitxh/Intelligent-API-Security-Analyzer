import pytest
from app.analysis.context import AnalysisContext
from app.analysis.findings import Finding
from app.analysis.rules.base import SecurityRule
from app.analysis.rules.registry import RuleRegistry


class DummyRule(SecurityRule):
    rule_id = "TEST-001"
    rule_version = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        return []


class AnotherRule(SecurityRule):
    rule_id = "TEST-002"
    rule_version = "1.1.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        return []


def test_registry_registers_rule() -> None:
    registry = RuleRegistry()
    rule = DummyRule()
    registry.register(rule)
    assert [r.rule_id for r in registry.all()] == ["TEST-001"]
    assert registry.get("TEST-001") is rule
    assert registry.get("NON-EXISTENT") is None
    assert len(registry) == 1


def test_registry_rejects_duplicate_rule() -> None:
    registry = RuleRegistry()
    registry.register(DummyRule())

    with pytest.raises(ValueError, match="Duplicate rule id: TEST-001"):
        registry.register(DummyRule())


def test_registry_isolation() -> None:
    registry_a = RuleRegistry()
    registry_b = RuleRegistry()

    registry_a.register(DummyRule())
    registry_b.register(AnotherRule())

    assert len(registry_a) == 1
    assert registry_a.get("TEST-001") is not None
    assert registry_a.get("TEST-002") is None

    assert len(registry_b) == 1
    assert registry_b.get("TEST-001") is None
    assert registry_b.get("TEST-002") is not None


def test_registry_clear() -> None:
    registry = RuleRegistry()
    registry.register(DummyRule())
    assert len(registry) == 1
    registry.clear()
    assert len(registry) == 0
    assert registry.all() == ()
