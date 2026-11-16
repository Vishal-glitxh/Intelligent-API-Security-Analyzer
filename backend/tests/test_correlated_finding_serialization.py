from app.analysis.correlation.models import CorrelatedFinding
from app.analysis.findings import Evidence, Finding, Severity
from app.repositories.scan import _serialize_correlated_finding


def _child_finding(rule_id: str, title: str, severity: Severity) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_version="1.0.0",
        title=title,
        severity=severity,
        confidence=0.8,
        rationale=f"Rationale for {title}.",
        remediation=f"Remediation for {title}.",
        evidence=(Evidence(kind="child", message=f"Evidence for {title}."),),
    )


def test_correlated_finding_serialization_keeps_parent_evidence_and_provenance() -> None:
    correlation_evidence = Evidence(
        kind="correlation",
        message="Parent-only evidence remains distinct.",
        file="src/routes.py",
        line=42,
        source_hash="sha256:parent",
        provenance="correlation-rule:CORR-001",
    )
    correlated = CorrelatedFinding(
        rule_id="CORR-001",
        rule_version="1.0.0",
        title="Cross-layer ownership divergence",
        severity=Severity.CRITICAL,
        confidence=0.95,
        rationale="The layers disagree about ownership enforcement.",
        remediation="Verify ownership before returning the object.",
        evidence=(correlation_evidence,),
        spec_findings=(
            _child_finding("SPEC-001", "Specification child one", Severity.HIGH),
            _child_finding("SPEC-002", "Specification child two", Severity.MEDIUM),
        ),
        source_findings=(
            _child_finding("SRC-001", "Source child one", Severity.LOW),
            _child_finding("SRC-002", "Source child two", Severity.HIGH),
        ),
    )

    serialized = _serialize_correlated_finding(correlated)

    assert serialized["severity"] == "critical"
    assert serialized["confidence"] == 0.95
    assert serialized["rationale"] == correlated.rationale
    assert serialized["remediation"] == correlated.remediation
    assert serialized["evidence"] == [
        {
            "kind": "correlation",
            "message": "Parent-only evidence remains distinct.",
            "file": "src/routes.py",
            "line": 42,
            "column": None,
            "end_line": None,
            "end_column": None,
            "source_hash": "sha256:parent",
            "provenance": "correlation-rule:CORR-001",
            "location": {
                "file": "src/routes.py",
                "line": 42,
                "column": None,
                "end_line": None,
                "end_column": None,
            },
        }
    ]
    assert [finding["rule_id"] for finding in serialized["spec_findings"]] == [
        "SPEC-001",
        "SPEC-002",
    ]
    assert [finding["rule_id"] for finding in serialized["source_findings"]] == [
        "SRC-001",
        "SRC-002",
    ]
    assert "evidence_pairs" not in serialized
    assert "divergence_details" not in serialized
