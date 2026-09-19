import ast
import re
from dataclasses import dataclass

from app.analysis.context import (
    EvidenceCategory,
    EvidenceStrength,
    SourceSecurityEvidence,
)
from app.analysis.source.parser import ParsedAssignment, ParsedModule

_STRONG_SECRET_NAMES = {
    "api_key",
    "apikey",
    "secret_key",
    "secret",
    "private_key",
    "aws_secret_access_key",
    "database_password",
    "db_password",
    "access_token",
    "refresh_token",
    "auth_token",
    "jwt_secret",
}

_MODERATE_SECRET_NAMES = {
    "password",
    "passwd",
    "token",
    "credential",
    "client_secret",
}

_PLACEHOLDER_SUBSTRINGS = {
    "changeme",
    "placeholder",
    "your_key",
    "your_secret",
    "example",
    "dummy",
    "todo",
    "xxx",
    "123456",
    "test_key",
    "test_secret",
}

_KNOWN_TOKEN_PATTERNS = [
    (re.compile(r"^AKIA[0-9A-Z]{16}$"), "AWS Access Key ID"),
    (re.compile(r"^ghp_[0-9a-zA-Z]{36}$"), "GitHub Personal Access Token"),
    (re.compile(r"^xox[baprs]-[0-9a-zA-Z-]{10,}$"), "Slack Token"),
    (re.compile(r"^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$"), "JWT Token"),
]


@dataclass(frozen=True)
class SecretEvidenceResult:
    is_hardcoded_secret: bool
    is_env_config: bool
    is_placeholder: bool
    secret_category: str
    redacted_value: str
    evidence: SourceSecurityEvidence


def redact_secret(value: str) -> str:
    """Redacts secret value preserving only short prefix and suffix."""
    if len(value) <= 6:
        return "***"
    return f"{value[:3]}...{value[-3:]}"


def _is_env_lookup(node: ast.AST) -> bool:
    """Detects whether assignment value comes from os.getenv, os.environ, or settings."""
    call_str = ast.unparse(node)
    if any(k in call_str for k in ("os.getenv", "os.environ", "getenv(", "environ.get")):
        return True
    if any(k in call_str for k in ("settings.", "config.", "BaseSettings")):
        return True
    return False


def _classify_assignment(
    assignment: ParsedAssignment,
    file_path: str,
) -> SecretEvidenceResult | None:
    target_clean = assignment.target_name.lower().replace("-", "_")

    # Check variable name match
    is_strong = any(
        target_clean == s or target_clean.endswith(f"_{s}") for s in _STRONG_SECRET_NAMES
    )
    is_moderate = any(
        target_clean == m or target_clean.endswith(f"_{m}") for m in _MODERATE_SECRET_NAMES
    )

    if not (is_strong or is_moderate):
        return None

    # Check if loaded safely from environment
    if _is_env_lookup(assignment.value_node):
        ev = SourceSecurityEvidence(
            category=EvidenceCategory.CONFIGURATION,
            strength=EvidenceStrength.STRONG,
            message=(
                f"Variable '{assignment.target_name}' safely loaded from environment "
                "or configuration."
            ),
            location=assignment.location,
            symbol=assignment.target_name,
            extracted_value="[ENV_LOOKUP]",
            rationale=(
                "Credential is appropriately extracted from environment or configuration "
                "rather than hardcoded."
            ),
        )
        return SecretEvidenceResult(
            is_hardcoded_secret=False,
            is_env_config=True,
            is_placeholder=False,
            secret_category="env_config",
            redacted_value="[ENV_LOOKUP]",
            evidence=ev,
        )

    # Must be a string literal to be a hardcoded secret
    if not isinstance(assignment.value_str, str):
        return None

    raw_val = assignment.value_str.strip()
    if len(raw_val) < 6:
        return None

    lower_val = raw_val.lower()
    is_placeholder = any(p in lower_val for p in _PLACEHOLDER_SUBSTRINGS)

    # Check for recognizable token formats
    is_token = False
    token_kind = ""
    for pat, desc in _KNOWN_TOKEN_PATTERNS:
        if pat.match(raw_val):
            is_token = True
            token_kind = desc
            break

    redacted = redact_secret(raw_val)

    if is_placeholder:
        ev = SourceSecurityEvidence(
            category=EvidenceCategory.SECRET,
            strength=EvidenceStrength.WEAK,
            message=(
                f"Variable '{assignment.target_name}' contains placeholder or "
                f"test credential: {redacted}"
            ),
            location=assignment.location,
            symbol=assignment.target_name,
            extracted_value=redacted,
            rationale=(
                "Identified placeholder or testing string matching credential naming pattern."
            ),
        )
        return SecretEvidenceResult(
            is_hardcoded_secret=False,
            is_env_config=False,
            is_placeholder=True,
            secret_category="placeholder",
            redacted_value=redacted,
            evidence=ev,
        )

    strength = EvidenceStrength.STRONG if (is_strong or is_token) else EvidenceStrength.MEDIUM
    desc = f" ({token_kind})" if is_token else ""
    ev = SourceSecurityEvidence(
        category=EvidenceCategory.SECRET,
        strength=strength,
        message=(
            f"Potential hardcoded secret assigned to '{assignment.target_name}'{desc}: {redacted}"
        ),
        location=assignment.location,
        symbol=assignment.target_name,
        extracted_value=redacted,
        rationale="Credential-like variable is directly assigned a string literal in source code.",
    )
    return SecretEvidenceResult(
        is_hardcoded_secret=True,
        is_env_config=False,
        is_placeholder=False,
        secret_category="token" if is_token else "credential",
        redacted_value=redacted,
        evidence=ev,
    )


def extract_secrets(module: ParsedModule) -> list[SourceSecurityEvidence]:
    """Scans module assignments for hardcoded secrets and environment config."""
    evidence_list: list[SourceSecurityEvidence] = []
    for assign in module.assignments:
        res = _classify_assignment(assign, module.file_path)
        if res:
            evidence_list.append(res.evidence)
    return evidence_list
