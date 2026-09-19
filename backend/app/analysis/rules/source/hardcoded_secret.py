from app.analysis.context import (
    AnalysisContext,
    EvidenceCategory,
    EvidenceStrength,
)
from app.analysis.findings import Evidence, Finding, Severity
from app.analysis.rules.base import SecurityRule


class HardcodedSecretRule(SecurityRule):
    """API-SECRET-001: Potential hardcoded secret in source code.

    Evaluates assignments of string literals to credential-like variables.
    Distinguishes genuine secrets from environment configuration and placeholder values.
    """

    rule_id = "API-SECRET-001"
    rule_version = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        source = context.source
        if not source:
            return findings

        for ev in source.evidence:
            if ev.category != EvidenceCategory.SECRET:
                continue

            # Ignore placeholders / test values
            if ev.strength == EvidenceStrength.WEAK:
                continue

            file_path = ev.location.file if ev.location else "unknown"
            line = ev.location.line if ev.location else None
            col = ev.location.column if ev.location else None
            symbol = ev.symbol or "CREDENTIAL"

            is_strong = ev.strength == EvidenceStrength.STRONG
            severity = Severity.CRITICAL if is_strong else Severity.HIGH
            confidence = 0.85 if is_strong else 0.75

            finding_ev = Evidence(
                kind="source_hardcoded_secret",
                message=ev.message,
                file=file_path,
                line=line,
                column=col,
                provenance=f"source:{file_path}:{line}" if line else f"source:{file_path}",
            )

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    rule_version=self.rule_version,
                    title=f"Potential Hardcoded Secret Assigned to '{symbol}'",
                    severity=severity,
                    confidence=confidence,
                    rationale=(
                        "Credential-like variable is assigned a static string literal in "
                        "source code. Hardcoding secrets in source files risks exposure in "
                        "version control, build artifacts, and repository access."
                    ),
                    remediation=(
                        "Extract sensitive credentials to environment variables for local "
                        "development and a secure secret manager for production. If this "
                        "credential was committed to version control, rotate it immediately."
                    ),
                    evidence=(finding_ev,),
                )
            )

        return findings
