from dataclasses import FrozenInstanceError

import pytest
from app.analysis.findings import Evidence, Finding, Severity


def test_evidence_creation_and_validation() -> None:
    ev = Evidence(
        kind="openapi_schema",
        message="Missing required security scheme",
        file="openapi.yaml",
        line=12,
        column=4,
        source_hash="sha256:abcd",
        provenance="spec:paths./users.get",
    )
    assert ev.kind == "openapi_schema"
    assert ev.message == "Missing required security scheme"
    assert ev.file == "openapi.yaml"
    assert ev.line == 12
    assert ev.column == 4
    assert ev.source_hash == "sha256:abcd"
    assert ev.provenance == "spec:paths./users.get"


def test_evidence_source_location_optional() -> None:
    ev = Evidence(kind="system_config", message="TLS 1.0 enabled")
    assert ev.file is None
    assert ev.line is None
    assert ev.column is None


def test_evidence_rejects_empty_fields() -> None:
    with pytest.raises(ValueError, match="Evidence 'kind' must be a non-empty string"):
        Evidence(kind="", message="Valid message")

    with pytest.raises(ValueError, match="Evidence 'message' must be a non-empty string"):
        Evidence(kind="spec", message="")

    with pytest.raises(ValueError, match="Evidence 'line' must be greater than or equal to 1"):
        Evidence(kind="spec", message="Valid", line=0)

    with pytest.raises(ValueError, match="Evidence 'column' must be greater than or equal to 1"):
        Evidence(kind="spec", message="Valid", column=-1)


def test_finding_valid_creation() -> None:
    ev = Evidence(
        kind="source_ast", message="Unprotected endpoint handler", file="routes.py", line=45
    )
    finding = Finding(
        rule_id="RULE-AUTH-001",
        rule_version="1.0.0",
        title="Missing Authentication on Sensitive Endpoint",
        severity=Severity.HIGH,
        confidence=0.85,
        rationale="Endpoint exposes PII without credential validation.",
        remediation="Apply authentication dependency to route.",
        evidence=(ev,),
    )
    assert finding.rule_id == "RULE-AUTH-001"
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.85
    assert len(finding.evidence) == 1
    assert finding.evidence[0] is ev


def test_finding_confidence_boundaries() -> None:
    ev = Evidence(kind="spec", message="Indicator found")

    # Valid boundary points: 0.0 and 1.0
    f_low = Finding(
        rule_id="R-1",
        rule_version="1.0",
        title="T",
        severity=Severity.LOW,
        confidence=0.0,
        rationale="R",
        remediation="Rem",
        evidence=(ev,),
    )
    assert f_low.confidence == 0.0

    f_high = Finding(
        rule_id="R-1",
        rule_version="1.0",
        title="T",
        severity=Severity.CRITICAL,
        confidence=1.0,
        rationale="R",
        remediation="Rem",
        evidence=(ev,),
    )
    assert f_high.confidence == 1.0

    # Invalid: below 0.0
    with pytest.raises(ValueError, match="Finding 'confidence' must be between 0.0 and 1.0"):
        Finding(
            rule_id="R-1",
            rule_version="1.0",
            title="T",
            severity=Severity.LOW,
            confidence=-0.01,
            rationale="R",
            remediation="Rem",
            evidence=(ev,),
        )

    # Invalid: above 1.0
    with pytest.raises(ValueError, match="Finding 'confidence' must be between 0.0 and 1.0"):
        Finding(
            rule_id="R-1",
            rule_version="1.0",
            title="T",
            severity=Severity.LOW,
            confidence=1.01,
            rationale="R",
            remediation="Rem",
            evidence=(ev,),
        )


def test_finding_requires_at_least_one_evidence() -> None:
    with pytest.raises(ValueError, match="Finding must retain at least one piece of evidence"):
        Finding(
            rule_id="R-1",
            rule_version="1.0",
            title="T",
            severity=Severity.MEDIUM,
            confidence=0.5,
            rationale="R",
            remediation="Rem",
            evidence=(),
        )


def test_finding_immutability() -> None:
    ev = Evidence(kind="spec", message="Indicator found")
    finding = Finding(
        rule_id="R-1",
        rule_version="1.0",
        title="T",
        severity=Severity.MEDIUM,
        confidence=0.5,
        rationale="R",
        remediation="Rem",
        evidence=(ev,),
    )

    with pytest.raises(FrozenInstanceError):
        finding.confidence = 0.9  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        ev.message = "Changed message"  # type: ignore[misc]


def test_finding_string_validation_errors() -> None:
    ev = Evidence(kind="spec", message="test")

    with pytest.raises(ValueError, match="Finding 'rule_id' must be a non-empty string"):
        Finding(
            rule_id="",
            rule_version="1",
            title="T",
            severity=Severity.LOW,
            confidence=0.5,
            rationale="R",
            remediation="Rem",
            evidence=(ev,),
        )

    with pytest.raises(ValueError, match="Finding 'rule_version' must be a non-empty string"):
        Finding(
            rule_id="R",
            rule_version="",
            title="T",
            severity=Severity.LOW,
            confidence=0.5,
            rationale="R",
            remediation="Rem",
            evidence=(ev,),
        )

    with pytest.raises(ValueError, match="Finding 'title' must be a non-empty string"):
        Finding(
            rule_id="R",
            rule_version="1",
            title="",
            severity=Severity.LOW,
            confidence=0.5,
            rationale="R",
            remediation="Rem",
            evidence=(ev,),
        )

    with pytest.raises(TypeError, match="Finding 'severity' must be a Severity enum"):
        Finding(
            rule_id="R",
            rule_version="1",
            title="T",
            severity="low",  # type: ignore[arg-type]
            confidence=0.5,
            rationale="R",
            remediation="Rem",
            evidence=(ev,),
        )

    with pytest.raises(ValueError, match="Finding 'rationale' must be a non-empty string"):
        Finding(
            rule_id="R",
            rule_version="1",
            title="T",
            severity=Severity.LOW,
            confidence=0.5,
            rationale="",
            remediation="Rem",
            evidence=(ev,),
        )

    with pytest.raises(ValueError, match="Finding 'remediation' must be a non-empty string"):
        Finding(
            rule_id="R",
            rule_version="1",
            title="T",
            severity=Severity.LOW,
            confidence=0.5,
            rationale="R",
            remediation="",
            evidence=(ev,),
        )


def test_finding_evidence_sequence_validation() -> None:
    ev = Evidence(kind="spec", message="test")

    # List conversion to tuple
    f_list = Finding(
        rule_id="R",
        rule_version="1",
        title="T",
        severity=Severity.LOW,
        confidence=0.5,
        rationale="R",
        remediation="Rem",
        evidence=[ev],
    )
    assert isinstance(f_list.evidence, tuple)

    # Non-sequence
    with pytest.raises(
        TypeError, match="Finding 'evidence' must be a sequence of Evidence objects"
    ):
        Finding(
            rule_id="R",
            rule_version="1",
            title="T",
            severity=Severity.LOW,
            confidence=0.5,
            rationale="R",
            remediation="Rem",
            evidence=123,  # type: ignore[arg-type]
        )

    # Non-Evidence item
    with pytest.raises(TypeError, match="All evidence items must be Evidence instances"):
        Finding(
            rule_id="R",
            rule_version="1",
            title="T",
            severity=Severity.LOW,
            confidence=0.5,
            rationale="R",
            remediation="Rem",
            evidence=["not-evidence"],  # type: ignore[list-item]
        )
