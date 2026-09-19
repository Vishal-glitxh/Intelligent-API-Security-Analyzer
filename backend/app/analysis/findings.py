from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Evidence:
    """Represents a discrete, verifiable piece of evidence supporting a finding."""

    kind: str
    message: str
    file: str | None = None
    line: int | None = None
    column: int | None = None
    source_hash: str | None = None
    provenance: str | None = None

    def __post_init__(self) -> None:
        if not self.kind or not self.kind.strip():
            raise ValueError("Evidence 'kind' must be a non-empty string.")
        if not self.message or not self.message.strip():
            raise ValueError("Evidence 'message' must be a non-empty string.")
        if self.line is not None and self.line < 1:
            raise ValueError("Evidence 'line' must be greater than or equal to 1.")
        if self.column is not None and self.column < 1:
            raise ValueError("Evidence 'column' must be greater than or equal to 1.")


@dataclass(frozen=True)
class Finding:
    """Represents a deterministic, evidence-backed security finding."""

    rule_id: str
    rule_version: str
    title: str
    severity: Severity
    confidence: float
    rationale: str
    remediation: str
    evidence: Sequence[Evidence] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.rule_id or not self.rule_id.strip():
            raise ValueError("Finding 'rule_id' must be a non-empty string.")
        if not self.rule_version or not self.rule_version.strip():
            raise ValueError("Finding 'rule_version' must be a non-empty string.")
        if not self.title or not self.title.strip():
            raise ValueError("Finding 'title' must be a non-empty string.")
        if not isinstance(self.severity, Severity):
            raise TypeError(
                f"Finding 'severity' must be a Severity enum instance, got {type(self.severity)}."
            )
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"Finding 'confidence' must be between 0.0 and 1.0, got {self.confidence}."
            )
        if not self.rationale or not self.rationale.strip():
            raise ValueError("Finding 'rationale' must be a non-empty string.")
        if not self.remediation or not self.remediation.strip():
            raise ValueError("Finding 'remediation' must be a non-empty string.")

        # Normalize sequence of evidence to tuple if necessary
        ev_tuple: tuple[Evidence, ...]
        if isinstance(self.evidence, tuple):
            ev_tuple = self.evidence
        elif isinstance(self.evidence, Sequence):
            ev_tuple = tuple(self.evidence)
            object.__setattr__(self, "evidence", ev_tuple)
        else:
            raise TypeError("Finding 'evidence' must be a sequence of Evidence objects.")

        if len(ev_tuple) == 0:
            raise ValueError("Finding must retain at least one piece of evidence.")

        for ev in ev_tuple:
            if not isinstance(ev, Evidence):
                raise TypeError(f"All evidence items must be Evidence instances, got {type(ev)}.")
