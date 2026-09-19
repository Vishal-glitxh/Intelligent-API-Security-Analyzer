from pathlib import Path

from app.analysis.context import AnalysisContext, ScanMetadata
from app.analysis.engine import AnalysisEngine
from app.analysis.openapi.loader import load_openapi_spec
from app.analysis.openapi.normalizer import normalize_openapi_spec
from app.analysis.openapi.validator import validate_openapi_spec
from app.analysis.rules.builtin import register_builtin_rules
from app.analysis.rules.registry import RuleRegistry

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "openapi"


def test_end_to_end_analysis_reproducibility() -> None:
    yaml_path = FIXTURES_DIR / "vulnerable_spec.yaml"
    content = yaml_path.read_text(encoding="utf-8")

    # Run 1
    loaded_1 = load_openapi_spec(content, file_path=str(yaml_path))
    validate_openapi_spec(loaded_1.raw_data)
    norm_1 = normalize_openapi_spec(loaded_1)
    meta_1 = ScanMetadata(
        engine_version="0.1.0",
        rule_set_version="0.1.0",
        config_version="1.0.0",
        spec_hash=norm_1.spec_hash,
    )
    ctx_1 = AnalysisContext(specification=norm_1, metadata=meta_1)

    registry_1 = RuleRegistry()
    register_builtin_rules(registry_1)
    engine_1 = AnalysisEngine(registry=registry_1)
    result_1 = engine_1.analyze(ctx_1)

    # Run 2
    loaded_2 = load_openapi_spec(content, file_path=str(yaml_path))
    validate_openapi_spec(loaded_2.raw_data)
    norm_2 = normalize_openapi_spec(loaded_2)
    meta_2 = ScanMetadata(
        engine_version="0.1.0",
        rule_set_version="0.1.0",
        config_version="1.0.0",
        spec_hash=norm_2.spec_hash,
    )
    ctx_2 = AnalysisContext(specification=norm_2, metadata=meta_2)

    registry_2 = RuleRegistry()
    register_builtin_rules(registry_2)
    engine_2 = AnalysisEngine(registry=registry_2)
    result_2 = engine_2.analyze(ctx_2)

    # Reproducibility assertions
    assert result_1.spec_hash == result_2.spec_hash
    assert result_1.evaluated_rules_count == result_2.evaluated_rules_count
    assert result_1.evaluated_rules_count == len(registry_1.all())
    assert len(result_1.findings) == len(result_2.findings)

    # Findings comparison
    for f1, f2 in zip(result_1.findings, result_2.findings, strict=True):
        assert f1.rule_id == f2.rule_id
        assert f1.title == f2.title
        assert f1.severity == f2.severity
        assert f1.confidence == f2.confidence
        assert f1.rationale == f2.rationale
        assert len(f1.evidence) == len(f2.evidence)
        for ev1, ev2 in zip(f1.evidence, f2.evidence, strict=True):
            assert ev1.kind == ev2.kind
            assert ev1.message == ev2.message
            assert ev1.file == ev2.file
            assert ev1.line == ev2.line
            assert ev1.column == ev2.column
            assert ev1.provenance == ev2.provenance
