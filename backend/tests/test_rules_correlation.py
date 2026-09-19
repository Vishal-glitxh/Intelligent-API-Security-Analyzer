from app.analysis.context import (
    AnalysisContext,
    AuthState,
    EvidenceCategory,
    EvidenceStrength,
    NormalizedEndpoint,
    NormalizedOpenAPI,
    NormalizedOperation,
    NormalizedParameter,
    NormalizedSourceEndpoint,
    NormalizedSourceTree,
    SourceLocation,
    SourceSecurityEvidence,
)
from app.analysis.correlation.models import (
    CorrelationState,
    EndpointMatchState,
    MatchedEndpointPair,
)
from app.analysis.findings import Evidence, Finding, Severity
from app.analysis.rules.correlation.auth_correlation import AuthenticationCorrelationRule
from app.analysis.rules.correlation.authz_correlation import ObjectAuthorizationCorrelationRule
from app.analysis.rules.correlation.input_constraints import InputConstraintsCorrelationRule
from app.analysis.rules.correlation.sensitive_data import SensitiveDataCorrelationRule
from app.analysis.rules.correlation.surface_divergence import SurfaceDivergenceCorrelationRule

# --- CORR-AUTH-001 TESTS ---


def test_corr_auth_001_positive_divergence() -> None:
    # 1. Positive Case: Spec declares security, source has AUTH_ABSENT_IN_ANALYZABLE_SCOPE
    op = NormalizedOperation(
        method="delete",
        path="/documents/{doc_id}",
        effective_security=({"bearerAuth": []},),
        location=SourceLocation(file="spec.yaml", line=20, column=5),
    )
    s_ep = NormalizedSourceEndpoint(
        method="delete",
        path="/documents/{doc_id}",
        raw_path="/documents/{doc_id}",
        handler_name="delete_doc",
        file_path="app/routes.py",
        framework="fastapi",
        auth_state=AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE,
        location=SourceLocation(file="app/routes.py", line=40, column=1),
    )
    pair = MatchedEndpointPair(
        spec_path="/documents/{doc_id}",
        spec_method="DELETE",
        source_path="/documents/{doc_id}",
        source_method="DELETE",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/documents/{param}",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    context = AnalysisContext()
    rule = AuthenticationCorrelationRule()
    findings = rule.correlate(context, [pair], [], [])

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "CORR-AUTH-001"
    assert f.severity == Severity.HIGH  # Mutation
    assert f.confidence == 0.80  # Exact research metadata value required
    assert f.correlation_state == CorrelationState.CONTRADICTED
    assert "Potential Authentication Divergence" in f.title


def test_corr_auth_001_negative_aligned() -> None:
    # 2. Negative Case: Spec declares security, source implements auth -> No divergence finding
    op = NormalizedOperation(
        method="post",
        path="/items",
        effective_security=({"bearerAuth": []},),
    )
    s_ep = NormalizedSourceEndpoint(
        method="post",
        path="/items",
        raw_path="/items",
        handler_name="create_item",
        file_path="app/routes.py",
        framework="fastapi",
        auth_state=AuthState.AUTH_PRESENT,
    )
    pair = MatchedEndpointPair(
        spec_path="/items",
        spec_method="POST",
        source_path="/items",
        source_method="POST",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/items",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    findings = AuthenticationCorrelationRule().correlate(AnalysisContext(), [pair], [], [])
    assert len(findings) == 0


def test_corr_auth_001_documentation_drift() -> None:
    # Spec claims public (no security), source implements authentication -> Drift (CONTRADICTED)
    op = NormalizedOperation(
        method="get",
        path="/public/status",
        effective_security=(),
    )
    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/public/status",
        raw_path="/public/status",
        handler_name="get_status",
        file_path="app/status.py",
        framework="fastapi",
        auth_state=AuthState.AUTH_PRESENT,
    )
    pair = MatchedEndpointPair(
        spec_path="/public/status",
        spec_method="GET",
        source_path="/public/status",
        source_method="GET",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/public/status",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    findings = AuthenticationCorrelationRule().correlate(AnalysisContext(), [pair], [], [])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "CORR-AUTH-001"
    assert f.correlation_state == CorrelationState.CONTRADICTED
    assert f.severity == Severity.LOW
    assert f.confidence == 0.80
    assert "API Documentation Drift" in f.title


def test_corr_auth_001_corroborated_mutation() -> None:
    # Both layers affirm lack of authentication on state-changing mutation -> SUPPORTED
    op = NormalizedOperation(
        method="post",
        path="/admin/purge",
        effective_security=(),
    )
    s_ep = NormalizedSourceEndpoint(
        method="post",
        path="/admin/purge",
        raw_path="/admin/purge",
        handler_name="purge_records",
        file_path="app/admin.py",
        framework="fastapi",
        auth_state=AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE,
    )
    pair = MatchedEndpointPair(
        spec_path="/admin/purge",
        spec_method="POST",
        source_path="/admin/purge",
        source_method="POST",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/admin/purge",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    findings = AuthenticationCorrelationRule().correlate(AnalysisContext(), [pair], [], [])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "CORR-AUTH-001"
    assert f.correlation_state == CorrelationState.SUPPORTED
    assert f.severity == Severity.HIGH
    assert f.confidence == 0.90
    assert "Corroborated Potential Missing Authentication" in f.title


def test_corr_auth_001_edge_case_and_location() -> None:
    # 3. Edge Case: Empty pair list
    findings = AuthenticationCorrelationRule().correlate(AnalysisContext(), [], [], [])
    assert findings == []

    # 4. Location retention assertion
    op = NormalizedOperation(
        method="get",
        path="/secure-data",
        effective_security=({"bearerAuth": []},),
        location=SourceLocation(file="spec.yaml", line=12, column=3),
    )
    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/secure-data",
        raw_path="/secure-data",
        handler_name="get_data",
        file_path="app/data.py",
        framework="fastapi",
        auth_state=AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE,
        location=SourceLocation(file="app/data.py", line=25, column=1),
    )
    pair = MatchedEndpointPair(
        spec_path="/secure-data",
        spec_method="GET",
        source_path="/secure-data",
        source_method="GET",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/secure-data",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    spec_f = Finding(
        rule_id="API-AUTH-001",
        rule_version="1.0.0",
        title="Spec auth finding",
        severity=Severity.MEDIUM,
        confidence=0.70,
        rationale="Spec test",
        remediation="Fix",
        evidence=(
            Evidence(
                kind="spec_auth",
                message="/secure-data missing",
                file="spec.yaml",
                line=12,
                column=3,
            ),
        ),
    )
    findings = AuthenticationCorrelationRule().correlate(AnalysisContext(), [pair], [spec_f], [])
    assert len(findings) == 1
    assert findings[0].evidence[0].file == "spec.yaml"
    assert findings[0].evidence[0].line == 12


# --- CORR-AUTHZ-001 TESTS ---


def test_corr_authz_001_positive_bola() -> None:
    # 1. Positive Case: Path parameter + DB lookup + NO authorization check -> COMPLEMENTARY
    op = NormalizedOperation(
        method="delete",
        path="/accounts/{account_id}",
        parameters=(NormalizedParameter(name="account_id", param_in="path", required=True),),
    )
    s_ep = NormalizedSourceEndpoint(
        method="delete",
        path="/accounts/{account_id}",
        raw_path="/accounts/{account_id}",
        handler_name="delete_account",
        file_path="app/routes.py",
        framework="fastapi",
        object_access_evidence=(
            SourceSecurityEvidence(
                category=EvidenceCategory.OBJECT_ACCESS,
                strength=EvidenceStrength.STRONG,
                message="Account.query.get(account_id)",
                symbol="account_id",
            ),
        ),
        authz_evidence=(),
        tenant_evidence=(),
    )
    pair = MatchedEndpointPair(
        spec_path="/accounts/{account_id}",
        spec_method="DELETE",
        source_path="/accounts/{account_id}",
        source_method="DELETE",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/accounts/{param}",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    findings = ObjectAuthorizationCorrelationRule().correlate(AnalysisContext(), [pair], [], [])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "CORR-AUTHZ-001"
    assert f.severity == Severity.HIGH
    assert f.confidence == 0.85
    assert f.correlation_state == CorrelationState.COMPLEMENTARY
    assert "Correlated Potential BOLA Indicator" in f.title


def test_corr_authz_001_negative_secured() -> None:
    # 2. Negative Case: Path parameter + DB lookup + WITH ownership check -> Safe (No BOLA finding)
    op = NormalizedOperation(
        method="get",
        path="/documents/{doc_id}",
        parameters=(NormalizedParameter(name="doc_id", param_in="path", required=True),),
    )
    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/documents/{doc_id}",
        raw_path="/documents/{doc_id}",
        handler_name="get_doc",
        file_path="app/routes.py",
        framework="fastapi",
        object_access_evidence=(
            SourceSecurityEvidence(
                category=EvidenceCategory.OBJECT_ACCESS,
                strength=EvidenceStrength.STRONG,
                message="Document.query.get(doc_id)",
                symbol="doc_id",
            ),
        ),
        authz_evidence=(
            SourceSecurityEvidence(
                category=EvidenceCategory.AUTHORIZATION,
                strength=EvidenceStrength.STRONG,
                message="current_user.id == doc.owner_id",
                symbol="ownership_check",
            ),
        ),
    )
    pair = MatchedEndpointPair(
        spec_path="/documents/{doc_id}",
        spec_method="GET",
        source_path="/documents/{doc_id}",
        source_method="GET",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/documents/{param}",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    findings = ObjectAuthorizationCorrelationRule().correlate(AnalysisContext(), [pair], [], [])
    assert len(findings) == 0


def test_corr_authz_001_edge_no_db_query() -> None:
    # 3. Edge Case: Path param exists, but source handler does not perform DB lookup
    # -> INCONCLUSIVE (0 findings)
    op = NormalizedOperation(
        method="get",
        path="/items/{item_id}",
        parameters=(NormalizedParameter(name="item_id", param_in="path", required=True),),
    )
    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/items/{item_id}",
        raw_path="/items/{item_id}",
        handler_name="get_static_item",
        file_path="app/items.py",
        framework="fastapi",
        object_access_evidence=(),
        authz_evidence=(),
        tenant_evidence=(),
    )
    pair = MatchedEndpointPair(
        spec_path="/items/{item_id}",
        spec_method="GET",
        source_path="/items/{item_id}",
        source_method="GET",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/items/{param}",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    findings = ObjectAuthorizationCorrelationRule().correlate(AnalysisContext(), [pair], [], [])
    assert len(findings) == 0


# --- CORR-DATA-001 TESTS ---


def test_corr_data_001_positive_sensitive() -> None:
    op = NormalizedOperation(
        method="get",
        path="/users/me",
    )
    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/users/me",
        raw_path="/users/me",
        handler_name="get_me",
        file_path="app/user.py",
        framework="fastapi",
    )
    pair = MatchedEndpointPair(
        spec_path="/users/me",
        spec_method="GET",
        source_path="/users/me",
        source_method="GET",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/users/me",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    spec_f = Finding(
        rule_id="API-DATA-001",
        rule_version="1.0.0",
        title="Potential Sensitive Data Exposure 'password_hash'",
        severity=Severity.HIGH,
        confidence=0.85,
        rationale="Schema exposes password_hash",
        remediation="Remove",
        evidence=(
            Evidence(
                kind="spec_response_schema",
                message="/users/me contains password_hash",
                file="spec.yaml",
                line=55,
                column=7,
            ),
        ),
    )
    findings = SensitiveDataCorrelationRule().correlate(AnalysisContext(), [pair], [spec_f], [])
    assert len(findings) == 1
    assert findings[0].rule_id == "CORR-DATA-001"
    assert findings[0].confidence == 0.90
    assert findings[0].evidence[0].file == "spec.yaml"


def test_corr_data_001_negative_no_sensitive_fields() -> None:
    # Negative Case: No sensitive data findings -> 0 correlated findings
    op = NormalizedOperation(method="get", path="/public/info")
    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/public/info",
        raw_path="/public/info",
        handler_name="get_info",
        file_path="app/info.py",
        framework="fastapi",
    )
    pair = MatchedEndpointPair(
        spec_path="/public/info",
        spec_method="GET",
        source_path="/public/info",
        source_method="GET",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/public/info",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    findings = SensitiveDataCorrelationRule().correlate(AnalysisContext(), [pair], [], [])
    assert len(findings) == 0


# --- CORR-INPUT-001 TESTS ---


def test_corr_input_001_positive_drift() -> None:
    # Spec lacks constraint, source enforces check in code -> CONTRADICTED
    op = NormalizedOperation(method="get", path="/items")
    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/items",
        raw_path="/items",
        handler_name="list_items",
        file_path="app/items.py",
        framework="fastapi",
        validation_evidence=(
            SourceSecurityEvidence(
                category=EvidenceCategory.INPUT_VALIDATION,
                strength=EvidenceStrength.MEDIUM,
                message="if limit > 50: raise",
                symbol="limit",
            ),
        ),
    )
    pair = MatchedEndpointPair(
        spec_path="/items",
        spec_method="GET",
        source_path="/items",
        source_method="GET",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/items",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    spec_f = Finding(
        rule_id="API-INPUT-001",
        rule_version="1.0.0",
        title="Missing constraint on 'limit'",
        severity=Severity.MEDIUM,
        confidence=0.75,
        rationale="Pagination missing max",
        remediation="Add max",
        evidence=(Evidence(kind="spec_param", message="/items limit"),),
    )
    findings = InputConstraintsCorrelationRule().correlate(AnalysisContext(), [pair], [spec_f], [])
    assert len(findings) == 1
    assert findings[0].correlation_state == CorrelationState.CONTRADICTED
    assert "Input Validation Contract Drift" in findings[0].title


def test_corr_input_001_corroborated_missing() -> None:
    # Spec lacks constraint AND source code has NO validation -> Corroborated (SUPPORTED)
    op = NormalizedOperation(method="get", path="/search")
    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/search",
        raw_path="/search",
        handler_name="search_items",
        file_path="app/search.py",
        framework="fastapi",
        validation_evidence=(),
    )
    pair = MatchedEndpointPair(
        spec_path="/search",
        spec_method="GET",
        source_path="/search",
        source_method="GET",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/search",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    spec_f = Finding(
        rule_id="API-INPUT-001",
        rule_version="1.0.0",
        title="Missing constraint on 'query'",
        severity=Severity.MEDIUM,
        confidence=0.75,
        rationale="Search query missing maxLength",
        remediation="Add maxLength",
        evidence=(Evidence(kind="spec_param", message="/search query"),),
    )
    findings = InputConstraintsCorrelationRule().correlate(AnalysisContext(), [pair], [spec_f], [])
    assert len(findings) == 1
    assert findings[0].correlation_state == CorrelationState.SUPPORTED
    assert "Corroborated Missing Input Constraints" in findings[0].title


def test_corr_input_001_inconclusive_unrelated() -> None:
    # Validation evidence exists in handler, but for an unrelated variable
    # -> INCONCLUSIVE (0 findings)
    op = NormalizedOperation(method="get", path="/data")
    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/data",
        raw_path="/data",
        handler_name="get_data",
        file_path="app/data.py",
        framework="fastapi",
        validation_evidence=(
            SourceSecurityEvidence(
                category=EvidenceCategory.INPUT_VALIDATION,
                strength=EvidenceStrength.MEDIUM,
                message="if internal_flag is True: pass",
                symbol="internal_flag",
            ),
        ),
    )
    pair = MatchedEndpointPair(
        spec_path="/data",
        spec_method="GET",
        source_path="/data",
        source_method="GET",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/data",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    spec_f = Finding(
        rule_id="API-INPUT-001",
        rule_version="1.0.0",
        title="Missing constraint on 'page_size'",
        severity=Severity.MEDIUM,
        confidence=0.75,
        rationale="Missing maximum",
        remediation="Add max",
        evidence=(Evidence(kind="spec_param", message="/data page_size"),),
    )
    findings = InputConstraintsCorrelationRule().correlate(AnalysisContext(), [pair], [spec_f], [])
    assert len(findings) == 0


# --- CORR-SURF-001 TESTS ---


def test_corr_surf_001_zombie_and_shadow() -> None:
    # 1. Zombie endpoint: in spec, missing in source
    zombie_op = NormalizedOperation(
        method="delete",
        path="/v1/legacy/purge",
        location=SourceLocation(file="spec.yaml", line=88, column=3),
    )
    zombie_pair = MatchedEndpointPair(
        spec_path="/v1/legacy/purge",
        spec_method="DELETE",
        source_path=None,
        source_method=None,
        match_state=EndpointMatchState.NO_MATCH,
        canonical_matching_path="/v1/legacy/purge",
        spec_operation=zombie_op,
        source_endpoint=None,
    )

    # 2. Shadow endpoint: in source, missing in spec
    shadow_ep = NormalizedSourceEndpoint(
        method="post",
        path="/v1/internal/admin-reset",
        raw_path="/v1/internal/admin-reset",
        handler_name="admin_reset",
        file_path="app/internal.py",
        framework="fastapi",
        location=SourceLocation(file="app/internal.py", line=12, column=1),
    )
    context = AnalysisContext(
        specification=NormalizedOpenAPI(
            endpoints=(NormalizedEndpoint(path="/v1/legacy/purge", operations=(zombie_op,)),)
        ),
        source=NormalizedSourceTree(endpoints=(shadow_ep,)),
    )

    findings = SurfaceDivergenceCorrelationRule().correlate(context, [zombie_pair], [], [])
    assert len(findings) == 2

    zombie_f = next(f for f in findings if "Zombie" in f.title)
    shadow_f = next(f for f in findings if "Shadow" in f.title)

    assert "Potential Zombie Endpoint" in zombie_f.title
    assert "Potential Shadow Endpoint" in shadow_f.title
    assert zombie_f.severity == Severity.LOW
    assert shadow_f.severity == Severity.MEDIUM


def test_corr_surf_001_negative_perfect_parity() -> None:
    # Negative Case: All endpoints matched, no shadows or zombies
    op = NormalizedOperation(method="get", path="/healthy")
    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/healthy",
        raw_path="/healthy",
        handler_name="health_check",
        file_path="app/health.py",
        framework="fastapi",
    )
    pair = MatchedEndpointPair(
        spec_path="/healthy",
        spec_method="GET",
        source_path="/healthy",
        source_method="GET",
        match_state=EndpointMatchState.EXACT_MATCH,
        canonical_matching_path="/healthy",
        spec_operation=op,
        source_endpoint=s_ep,
    )
    context = AnalysisContext(
        specification=NormalizedOpenAPI(
            endpoints=(NormalizedEndpoint(path="/healthy", operations=(op,)),)
        ),
        source=NormalizedSourceTree(endpoints=(s_ep,)),
    )
    findings = SurfaceDivergenceCorrelationRule().correlate(context, [pair], [], [])
    assert len(findings) == 0
