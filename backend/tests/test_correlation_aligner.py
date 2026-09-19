from app.analysis.context import (
    AuthState,
    EvidenceCategory,
    EvidenceStrength,
    NormalizedOperation,
    NormalizedParameter,
    NormalizedSourceEndpoint,
    SourceLocation,
    SourceSecurityEvidence,
)
from app.analysis.correlation.aligner import (
    align_authentication_evidence,
    align_authorization_evidence,
    align_input_validation_evidence,
)
from app.analysis.correlation.models import (
    CorrelationState,
    EndpointMatchState,
    MatchedEndpointPair,
)
from app.analysis.findings import Evidence, Finding, Severity


def _make_pair(
    spec_path: str = "/api/v1/resource",
    spec_method: str = "POST",
    effective_security: tuple[dict[str, list[str]], ...] = (),
    parameters: tuple[NormalizedParameter, ...] = (),
    source_auth_state: AuthState = AuthState.AUTH_PRESENT,
    source_auth_evidence: tuple[SourceSecurityEvidence, ...] = (),
    object_access_evidence: tuple[SourceSecurityEvidence, ...] = (),
    authz_evidence: tuple[SourceSecurityEvidence, ...] = (),
    tenant_evidence: tuple[SourceSecurityEvidence, ...] = (),
    validation_evidence: tuple[SourceSecurityEvidence, ...] = (),
) -> MatchedEndpointPair:
    op = NormalizedOperation(
        method=spec_method.lower(),
        path=spec_path,
        effective_security=effective_security,
        parameters=parameters,
    )
    s_ep = NormalizedSourceEndpoint(
        method=spec_method.lower(),
        path=spec_path,
        raw_path=spec_path,
        handler_name="handler",
        file_path="routes.py",
        framework="fastapi",
        auth_state=source_auth_state,
        auth_evidence=source_auth_evidence,
        object_access_evidence=object_access_evidence,
        authz_evidence=authz_evidence,
        tenant_evidence=tenant_evidence,
        validation_evidence=validation_evidence,
    )
    return MatchedEndpointPair(
        spec_path=spec_path,
        spec_method=spec_method,
        source_path=spec_path,
        source_method=spec_method,
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path=spec_path,
        spec_operation=op,
        source_endpoint=s_ep,
    )


def test_align_authentication_supported_control() -> None:
    # Spec has security, Source has auth -> SUPPORTED
    pair = _make_pair(
        effective_security=({"bearerAuth": []},),
        source_auth_state=AuthState.AUTH_PRESENT,
        source_auth_evidence=(
            SourceSecurityEvidence(
                category=EvidenceCategory.AUTHENTICATION,
                strength=EvidenceStrength.STRONG,
                message="Depends(get_current_user)",
                location=SourceLocation(file="routes.py", line=10),
            ),
        ),
    )
    corr_state, ev_pairs, rationale = align_authentication_evidence(pair, [], [])
    assert corr_state == CorrelationState.SUPPORTED
    assert len(ev_pairs) == 1
    assert "consistent" in rationale.lower()


def test_align_authentication_contradicted_divergence() -> None:
    # Spec claims security, Source lacks evidence in scope -> CONTRADICTED
    pair = _make_pair(
        effective_security=({"bearerAuth": []},),
        source_auth_state=AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE,
    )
    corr_state, ev_pairs, rationale = align_authentication_evidence(pair, [], [])
    assert corr_state == CorrelationState.CONTRADICTED
    assert "divergence" in rationale.lower()


def test_align_authorization_bola_complementary() -> None:
    # Spec exposes ID parameter, Source queries object without authz check -> COMPLEMENTARY
    pair = _make_pair(
        parameters=(NormalizedParameter(name="user_id", param_in="path", required=True),),
        object_access_evidence=(
            SourceSecurityEvidence(
                category=EvidenceCategory.OBJECT_ACCESS,
                strength=EvidenceStrength.STRONG,
                message="db.query(User).get(user_id)",
                symbol="user_id",
            ),
        ),
        authz_evidence=(),
        tenant_evidence=(),
    )
    corr_state, ev_pairs, rationale = align_authorization_evidence(pair, [], [])
    assert corr_state == CorrelationState.COMPLEMENTARY
    assert "potential bola" in rationale.lower()


def test_align_authorization_supported_secured() -> None:
    # Spec exposes ID parameter, Source queries object WITH ownership check -> SUPPORTED
    pair = _make_pair(
        parameters=(NormalizedParameter(name="user_id", param_in="path", required=True),),
        object_access_evidence=(
            SourceSecurityEvidence(
                category=EvidenceCategory.OBJECT_ACCESS,
                strength=EvidenceStrength.STRONG,
                message="db.query(User).get(user_id)",
                symbol="user_id",
            ),
        ),
        authz_evidence=(
            SourceSecurityEvidence(
                category=EvidenceCategory.AUTHORIZATION,
                strength=EvidenceStrength.STRONG,
                message="current_user.id == user.id",
                symbol="ownership_check",
            ),
        ),
    )
    corr_state, ev_pairs, rationale = align_authorization_evidence(pair, [], [])
    assert corr_state == CorrelationState.SUPPORTED


def test_align_input_validation_contract_drift() -> None:
    # Spec lacks constraint, but source code implements check -> CONTRADICTED
    pair = _make_pair(
        validation_evidence=(
            SourceSecurityEvidence(
                category=EvidenceCategory.INPUT_VALIDATION,
                strength=EvidenceStrength.MEDIUM,
                message="if len(limit) > 100: raise",
                symbol="limit",
            ),
        ),
    )
    spec_f = Finding(
        rule_id="API-INPUT-001",
        rule_version="1.0.0",
        title="Potential Missing Constraint on 'limit' parameter",
        severity=Severity.MEDIUM,
        confidence=0.75,
        rationale="Missing maximum constraint",
        remediation="Add maximum",
        evidence=(Evidence(kind="spec_input", message="/api/v1/resource limit"),),
    )
    corr_state, ev_pairs, rationale = align_input_validation_evidence(pair, [spec_f], [])
    assert corr_state == CorrelationState.CONTRADICTED
    assert "omits validation constraint" in rationale.lower()
