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
from app.analysis.correlation.engine import CorrelationEngine
from app.analysis.findings import Evidence, Finding, Severity


def test_correlation_reproducibility_10_runs() -> None:
    # Build a complex multi-endpoint context
    op1 = NormalizedOperation(
        method="delete",
        path="/documents/{doc_id}",
        parameters=(NormalizedParameter(name="doc_id", param_in="path", required=True),),
        effective_security=({"bearerAuth": []},),
        location=SourceLocation(file="spec.yaml", line=10, column=5),
    )
    op2 = NormalizedOperation(
        method="get",
        path="/users/{userId}/profile",
        parameters=(NormalizedParameter(name="userId", param_in="path", required=True),),
        effective_security=(),
        location=SourceLocation(file="spec.yaml", line=25, column=5),
    )
    zombie_op = NormalizedOperation(
        method="post",
        path="/deprecated/flush",
        effective_security=(),
        location=SourceLocation(file="spec.yaml", line=40, column=5),
    )

    spec = NormalizedOpenAPI(
        endpoints=(
            NormalizedEndpoint(path="/documents/{doc_id}", operations=(op1,)),
            NormalizedEndpoint(path="/users/{userId}/profile", operations=(op2,)),
            NormalizedEndpoint(path="/deprecated/flush", operations=(zombie_op,)),
        )
    )

    s_ep1 = NormalizedSourceEndpoint(
        method="delete",
        path="/documents/{doc_id}",
        raw_path="/documents/{doc_id}",
        handler_name="delete_doc",
        file_path="app/routes.py",
        framework="fastapi",
        auth_state=AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE,
        object_access_evidence=(
            SourceSecurityEvidence(
                category=EvidenceCategory.OBJECT_ACCESS,
                strength=EvidenceStrength.STRONG,
                message="db.query(Doc).get(doc_id)",
                symbol="doc_id",
            ),
        ),
        location=SourceLocation(file="app/routes.py", line=30, column=1),
    )
    s_ep2 = NormalizedSourceEndpoint(
        method="get",
        path="/users/{user_id}/profile",
        raw_path="/users/{user_id}/profile",
        handler_name="get_profile",
        file_path="app/routes.py",
        framework="fastapi",
        auth_state=AuthState.AUTH_PRESENT,
        location=SourceLocation(file="app/routes.py", line=50, column=1),
    )
    shadow_ep = NormalizedSourceEndpoint(
        method="post",
        path="/internal/debug-reset",
        raw_path="/internal/debug-reset",
        handler_name="debug_reset",
        file_path="app/internal.py",
        framework="fastapi",
        auth_state=AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE,
        location=SourceLocation(file="app/internal.py", line=15, column=1),
    )

    source = NormalizedSourceTree(endpoints=(s_ep1, s_ep2, shadow_ep))
    context = AnalysisContext(specification=spec, source=source)

    spec_findings = (
        Finding(
            rule_id="API-AUTH-001",
            rule_version="1.0.0",
            title="Missing Auth on /users/{userId}/profile",
            severity=Severity.MEDIUM,
            confidence=0.70,
            rationale="Spec test",
            remediation="Add security",
            evidence=(Evidence(kind="spec_auth", message="GET /users/{userId}/profile"),),
        ),
    )
    source_findings = (
        Finding(
            rule_id="API-SOURCE-AUTH-001",
            rule_version="1.0.0",
            title="Missing Auth on delete_doc",
            severity=Severity.HIGH,
            confidence=0.75,
            rationale="Source test",
            remediation="Add decorator",
            evidence=(Evidence(kind="source_auth", message="DELETE /documents/{doc_id}"),),
        ),
    )

    engine = CorrelationEngine()

    baseline_result = engine.correlate(context, spec_findings, source_findings)
    baseline_finding_keys = [
        (f.rule_id, f.title, f.severity, f.confidence, f.correlation_state)
        for f in baseline_result.correlated_findings
    ]

    assert len(baseline_result.correlated_findings) >= 3

    # Execute 10 consecutive runs and assert bitwise equality
    for i in range(10):
        run_result = engine.correlate(context, spec_findings, source_findings)
        run_keys = [
            (f.rule_id, f.title, f.severity, f.confidence, f.correlation_state)
            for f in run_result.correlated_findings
        ]
        assert run_keys == baseline_finding_keys, f"Determinism mismatch on run {i + 1}"
        assert run_result.metrics_summary == baseline_result.metrics_summary
        assert len(run_result.matched_endpoints) == len(baseline_result.matched_endpoints)
