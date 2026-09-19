from pathlib import Path

from app.analysis.context import AnalysisContext
from app.analysis.engine import AnalysisEngine
from app.analysis.rules.builtin import register_builtin_rules
from app.analysis.rules.registry import RuleRegistry
from app.analysis.source import normalize_source_tree
from app.analysis.source.loader import load_source_from_disk

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "source"


def test_source_analysis_reproducibility() -> None:
    # Run 1
    loaded1 = load_source_from_disk(FIXTURES_DIR)
    tree1 = normalize_source_tree(loaded1)
    registry1 = RuleRegistry()
    register_builtin_rules(registry1)
    engine1 = AnalysisEngine(registry=registry1)
    res1 = engine1.analyze(AnalysisContext(source=tree1))

    # Run 2
    loaded2 = load_source_from_disk(FIXTURES_DIR)
    tree2 = normalize_source_tree(loaded2)
    registry2 = RuleRegistry()
    register_builtin_rules(registry2)
    engine2 = AnalysisEngine(registry=registry2)
    res2 = engine2.analyze(AnalysisContext(source=tree2))

    # Assert identical hashes
    assert res1.source_hash == res2.source_hash
    assert res1.source_hash is not None

    # Assert identical findings count & ordering
    assert len(res1.findings) == len(res2.findings)
    for f1, f2 in zip(res1.findings, res2.findings, strict=True):
        assert f1.rule_id == f2.rule_id
        assert f1.title == f2.title
        assert f1.severity == f2.severity
        assert f1.confidence == f2.confidence
        assert f1.evidence == f2.evidence
