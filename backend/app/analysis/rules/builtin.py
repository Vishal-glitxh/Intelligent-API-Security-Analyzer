from app.analysis.rules.openapi.auth_inconsistent import InconsistentAuthRule
from app.analysis.rules.openapi.auth_missing import MissingAuthRule
from app.analysis.rules.openapi.bola_idor import BolaIdorIndicatorRule
from app.analysis.rules.openapi.input_constraints import InputConstraintsRule
from app.analysis.rules.openapi.sensitive_data import SensitiveDataExposureRule
from app.analysis.rules.registry import RuleRegistry
from app.analysis.rules.source.hardcoded_secret import HardcodedSecretRule
from app.analysis.rules.source.missing_auth import SourceMissingAuthRule
from app.analysis.rules.source.missing_authz import SourceMissingAuthzRule


def register_builtin_rules(registry: RuleRegistry) -> None:
    """Register all standard specification-level and source-level security rules."""
    # Phase 2: Specification-level rules
    registry.register(MissingAuthRule())
    registry.register(InconsistentAuthRule())
    registry.register(InputConstraintsRule())
    registry.register(SensitiveDataExposureRule())
    registry.register(BolaIdorIndicatorRule())

    # Phase 3: Source-level rules
    registry.register(HardcodedSecretRule())
    registry.register(SourceMissingAuthRule())
    registry.register(SourceMissingAuthzRule())
