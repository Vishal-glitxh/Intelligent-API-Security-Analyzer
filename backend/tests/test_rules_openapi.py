from pathlib import Path

from app.analysis.context import AnalysisContext
from app.analysis.findings import Severity
from app.analysis.openapi.loader import load_openapi_spec
from app.analysis.openapi.normalizer import normalize_openapi_spec
from app.analysis.rules.openapi import (
    BolaIdorIndicatorRule,
    InconsistentAuthRule,
    InputConstraintsRule,
    MissingAuthRule,
    SensitiveDataExposureRule,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "openapi"


def _get_context_from_fixture(fixture_name: str) -> AnalysisContext:
    yaml_path = FIXTURES_DIR / fixture_name
    content = yaml_path.read_text(encoding="utf-8")
    loaded = load_openapi_spec(content, file_path=str(yaml_path))
    norm = normalize_openapi_spec(loaded)
    return AnalysisContext(specification=norm)


# ==============================================================================
# 1. API-AUTH-001: MissingAuthRule
# ==============================================================================


def test_auth_missing_positive() -> None:
    ctx = _get_context_from_fixture("vulnerable_spec.yaml")
    rule = MissingAuthRule()
    findings = rule.analyze(ctx)

    matching = [f for f in findings if "/vulnerable/items" in f.title]
    assert len(matching) == 1
    f = matching[0]
    assert f.rule_id == "API-AUTH-001"
    assert f.severity == Severity.HIGH
    assert f.confidence == 0.85
    assert len(f.evidence) >= 1
    assert "no effective security" in f.evidence[0].message or "overrides" in f.evidence[0].message


def test_auth_missing_negative() -> None:
    ctx = _get_context_from_fixture("secure_spec.yaml")
    rule = MissingAuthRule()
    findings = rule.analyze(ctx)
    # Fully secured spec with global security produces no missing auth findings
    assert len(findings) == 0


def test_auth_missing_edge_case() -> None:
    # Empty context without specification
    empty_ctx = AnalysisContext()
    rule = MissingAuthRule()
    assert rule.analyze(empty_ctx) == []


def test_auth_missing_evidence_location() -> None:
    ctx = _get_context_from_fixture("vulnerable_spec.yaml")
    rule = MissingAuthRule()
    findings = rule.analyze(ctx)
    assert len(findings) > 0
    ev = findings[0].evidence[0]
    assert ev.file is not None
    assert ev.line is not None and ev.line >= 1
    assert ev.column is not None and ev.column >= 1
    assert ev.provenance is not None and ev.provenance.startswith("spec:")


# ==============================================================================
# 2. API-AUTH-002: InconsistentAuthRule
# ==============================================================================


def test_auth_inconsistent_positive() -> None:
    ctx = _get_context_from_fixture("vulnerable_spec.yaml")
    rule = InconsistentAuthRule()
    findings = rule.analyze(ctx)

    matching = [f for f in findings if "/vulnerable/records/{id}" in f.title]
    assert len(matching) == 1
    f = matching[0]
    assert f.rule_id == "API-AUTH-002"
    assert f.severity == Severity.HIGH
    assert f.confidence == 0.80
    assert len(f.evidence) == 2
    assert "sibling" in f.evidence[1].message.lower()


def test_auth_inconsistent_negative() -> None:
    ctx = _get_context_from_fixture("secure_spec.yaml")
    rule = InconsistentAuthRule()
    findings = rule.analyze(ctx)
    assert len(findings) == 0


def test_auth_inconsistent_edge_case() -> None:
    empty_ctx = AnalysisContext()
    rule = InconsistentAuthRule()
    assert rule.analyze(empty_ctx) == []


def test_auth_inconsistent_evidence_location() -> None:
    ctx = _get_context_from_fixture("vulnerable_spec.yaml")
    rule = InconsistentAuthRule()
    findings = rule.analyze(ctx)
    assert len(findings) > 0
    f = findings[0]
    assert len(f.evidence) >= 2
    assert f.evidence[0].provenance is not None
    assert f.evidence[1].provenance is not None


# ==============================================================================
# 3. API-INPUT-001: InputConstraintsRule
# ==============================================================================


def test_input_constraints_positive() -> None:
    ctx = _get_context_from_fixture("vulnerable_spec.yaml")
    rule = InputConstraintsRule()
    findings = rule.analyze(ctx)

    # limit and redirect_url should be flagged
    titles = [f.title for f in findings]
    assert any("limit" in t for t in titles)
    assert any("redirect_url" in t for t in titles)

    limit_finding = next(f for f in findings if "limit" in f.title)
    assert limit_finding.rule_id == "API-INPUT-001"
    assert limit_finding.severity == Severity.MEDIUM
    assert limit_finding.confidence == 0.75
    assert "maximum" in limit_finding.evidence[0].message


def test_input_constraints_negative() -> None:
    ctx = _get_context_from_fixture("secure_spec.yaml")
    rule = InputConstraintsRule()
    findings = rule.analyze(ctx)
    assert len(findings) == 0


def test_input_constraints_edge_case() -> None:
    empty_ctx = AnalysisContext()
    rule = InputConstraintsRule()
    assert rule.analyze(empty_ctx) == []


def test_input_constraints_evidence_location() -> None:
    ctx = _get_context_from_fixture("vulnerable_spec.yaml")
    rule = InputConstraintsRule()
    findings = rule.analyze(ctx)
    assert len(findings) > 0
    ev = findings[0].evidence[0]
    assert ev.file is not None
    assert ev.provenance is not None and "parameters" in ev.provenance


# ==============================================================================
# 4. API-DATA-001: SensitiveDataExposureRule
# ==============================================================================


def test_sensitive_data_positive() -> None:
    ctx = _get_context_from_fixture("vulnerable_spec.yaml")
    rule = SensitiveDataExposureRule()
    findings = rule.analyze(ctx)

    titles = [f.title for f in findings]
    assert any("password" in t for t in titles)
    assert any("api_key" in t for t in titles)

    pwd_finding = next(f for f in findings if "password" in f.title)
    assert pwd_finding.rule_id == "API-DATA-001"
    assert pwd_finding.severity == Severity.HIGH
    assert pwd_finding.confidence >= 0.85
    assert "password" in pwd_finding.evidence[0].message


def test_sensitive_data_negative() -> None:
    ctx = _get_context_from_fixture("secure_spec.yaml")
    rule = SensitiveDataExposureRule()
    findings = rule.analyze(ctx)
    assert len(findings) == 0


def test_sensitive_data_edge_case() -> None:
    empty_ctx = AnalysisContext()
    rule = SensitiveDataExposureRule()
    assert rule.analyze(empty_ctx) == []


def test_sensitive_data_evidence_location() -> None:
    ctx = _get_context_from_fixture("vulnerable_spec.yaml")
    rule = SensitiveDataExposureRule()
    findings = rule.analyze(ctx)
    assert len(findings) > 0
    ev = findings[0].evidence[0]
    assert ev.file is not None
    assert ev.provenance is not None and (
        "UserProfile" in ev.provenance or "properties" in ev.provenance
    )


# ==============================================================================
# 5. API-AUTHZ-001: BolaIdorIndicatorRule
# ==============================================================================


def test_bola_idor_positive() -> None:
    ctx = _get_context_from_fixture("vulnerable_spec.yaml")
    rule = BolaIdorIndicatorRule()
    findings = rule.analyze(ctx)

    matching = [f for f in findings if "accountId" in f.title or "accounts" in f.title]
    assert len(matching) == 1
    f = matching[0]
    assert f.rule_id == "API-AUTHZ-001"
    assert "architectural indicator" in f.title
    assert f.severity == Severity.HIGH
    assert f.confidence == 0.65
    assert "accountId" in f.evidence[0].message


def test_bola_idor_negative() -> None:
    ctx = _get_context_from_fixture("secure_spec.yaml")
    rule = BolaIdorIndicatorRule()
    findings = rule.analyze(ctx)
    # secure_spec has fine-grained authorization scopes (account:self) so no BOLA finding is emitted
    assert len(findings) == 0


def test_bola_idor_edge_case() -> None:
    empty_ctx = AnalysisContext()
    rule = BolaIdorIndicatorRule()
    assert rule.analyze(empty_ctx) == []


def test_bola_idor_evidence_location() -> None:
    ctx = _get_context_from_fixture("vulnerable_spec.yaml")
    rule = BolaIdorIndicatorRule()
    findings = rule.analyze(ctx)
    assert len(findings) > 0
    ev = findings[0].evidence[0]
    assert ev.file is not None
    assert ev.provenance is not None and "paths" in ev.provenance
