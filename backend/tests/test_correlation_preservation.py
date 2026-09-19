from app.analysis.context import (
    AnalysisContext,
    AuthState,
    NormalizedEndpoint,
    NormalizedOpenAPI,
    NormalizedOperation,
    NormalizedSourceEndpoint,
    NormalizedSourceTree,
)
from app.analysis.correlation.engine import CorrelationEngine
from app.analysis.findings import Evidence, Finding, Severity


def test_preservation_of_three_independent_result_sets() -> None:
    # 1. Spec setup
    op = NormalizedOperation(
        method="delete",
        path="/items/{item_id}",
        effective_security=({"bearerAuth": []},),
    )
    spec = NormalizedOpenAPI(
        endpoints=(NormalizedEndpoint(path="/items/{item_id}", operations=(op,)),)
    )

    # 2. Source setup
    s_ep = NormalizedSourceEndpoint(
        method="delete",
        path="/items/{item_id}",
        raw_path="/items/{item_id}",
        handler_name="delete_item",
        file_path="app/routes.py",
        framework="fastapi",
        auth_state=AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE,
    )
    source = NormalizedSourceTree(endpoints=(s_ep,))
    context = AnalysisContext(specification=spec, source=source)

    # 3. Independent Phase 2 finding (SPEC_ONLY)
    spec_finding = Finding(
        rule_id="API-AUTH-001",
        rule_version="1.0.0",
        title="Potential Missing Authentication Requirement",
        severity=Severity.HIGH,
        confidence=0.85,
        rationale="Spec test rationale",
        remediation="Add security schemes",
        evidence=(Evidence(kind="spec_auth", message="DELETE /items/{item_id}"),),
    )

    # 4. Independent Phase 3 finding (SOURCE_ONLY)
    source_finding = Finding(
        rule_id="API-SOURCE-AUTH-001",
        rule_version="1.0.0",
        title="Potential Missing Recognizable Authentication Evidence",
        severity=Severity.HIGH,
        confidence=0.75,
        rationale="Source test rationale",
        remediation="Add decorator",
        evidence=(Evidence(kind="source_auth", message="DELETE /items/{item_id}"),),
    )

    spec_findings = (spec_finding,)
    source_findings = (source_finding,)

    # 5. Run Correlation Engine
    engine = CorrelationEngine()
    result = engine.correlate(
        context=context,
        spec_findings=spec_findings,
        source_findings=source_findings,
    )

    # 6. Verify result sets: SPEC_ONLY and SOURCE_ONLY MUST remain completely unchanged
    assert result.spec_only_findings == spec_findings
    assert result.source_only_findings == source_findings
    assert result.spec_only_findings[0] is spec_finding
    assert result.source_only_findings[0] is source_finding

    # 7. Verify CORRELATED findings synthesize multi-layer facts with lineage
    assert len(result.correlated_findings) > 0
    corr = result.correlated_findings[0]
    assert corr.rule_id == "CORR-AUTH-001"
    assert corr.matched_endpoint is not None
    assert corr.matched_endpoint.spec_path == "/items/{item_id}"
    assert corr.matched_endpoint.source_path == "/items/{item_id}"
    assert len(corr.spec_findings) == 1
    assert corr.spec_findings[0] is spec_finding
    assert len(corr.source_findings) == 1
    assert corr.source_findings[0] is source_finding
