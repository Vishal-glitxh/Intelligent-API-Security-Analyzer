from app.analysis.context import AuthState, EvidenceCategory
from app.analysis.correlation.models import (
    CorrelatedEvidencePair,
    CorrelationState,
    MatchedEndpointPair,
)
from app.analysis.findings import Evidence, Finding


def align_authentication_evidence(
    pair: MatchedEndpointPair,
    spec_findings: list[Finding],
    source_findings: list[Finding],
) -> tuple[CorrelationState, tuple[CorrelatedEvidencePair, ...], str]:
    """Aligns authentication evidence between OpenAPI operation and source endpoint handler.

    State definitions:
    - SUPPORTED: Cross-layer evidence is mutually consistent with the evaluated proposition:
      * Both layers require/enforce authentication, OR
      * Both layers document/exhibit lack of authentication.
    - CONTRADICTED:
      * Spec requires security, but source has AUTH_ABSENT_IN_ANALYZABLE_SCOPE.
      * Spec documents public (security: []), but source enforces authentication.
    - INCONCLUSIVE:
      * Source auth_state is AUTH_UNKNOWN or endpoint is unmatched.
    """
    evidence_pairs: list[CorrelatedEvidencePair] = []

    if not pair.spec_operation or not pair.source_endpoint:
        return (CorrelationState.INCONCLUSIVE, (), "Unmatched endpoint cannot be aligned.")

    spec_op = pair.spec_operation
    source_ep = pair.source_endpoint

    spec_has_security = len(spec_op.effective_security) > 0
    source_auth_state = source_ep.auth_state

    # Collect relevant spec evidence
    spec_auth_ev: Evidence | None = None
    for f in spec_findings:
        if f.rule_id in ("API-AUTH-001", "API-AUTH-002") and f.evidence:
            for ev in f.evidence:
                if (ev.message and spec_op.path in ev.message) or (
                    ev.provenance and spec_op.path in ev.provenance
                ):
                    spec_auth_ev = ev
                    break

    # Collect relevant source evidence
    source_auth_ev = source_ep.auth_evidence[0] if source_ep.auth_evidence else None

    # Evaluate correlation state
    if source_auth_state == AuthState.AUTH_UNKNOWN:
        rationale = "Source authentication state is unknown due to dynamic routing or dispatch."
        corr_state = CorrelationState.INCONCLUSIVE

    elif spec_has_security and source_auth_state == AuthState.AUTH_PRESENT:
        corr_state = CorrelationState.SUPPORTED
        rationale = (
            "Cross-layer authentication consistent: specification requires security and "
            f"source handler '{source_ep.handler_name}' implements authentication."
        )

    elif not spec_has_security and source_auth_state == AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE:
        corr_state = CorrelationState.SUPPORTED
        rationale = (
            "Cross-layer authentication consistent: specification specifies no security schemes "
            f"and source handler '{source_ep.handler_name}' contains no authentication evidence."
        )

    elif spec_has_security and source_auth_state == AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE:
        corr_state = CorrelationState.CONTRADICTED
        rationale = (
            f"Authentication divergence: specification requires security schemes "
            f"{spec_op.effective_security}, but source handler '{source_ep.handler_name}' "
            "contains no recognizable authentication dependency or decorator in analyzable scope."
        )

    elif not spec_has_security and source_auth_state == AuthState.AUTH_PRESENT:
        corr_state = CorrelationState.CONTRADICTED
        rationale = (
            "Documentation drift: specification defines operation as public "
            "(no security requirements), but source handler "
            f"'{source_ep.handler_name}' enforces authentication dependencies."
        )

    else:
        corr_state = CorrelationState.INCONCLUSIVE
        rationale = "Authentication evidence cannot be definitively correlated."

    evidence_pairs.append(
        CorrelatedEvidencePair(
            category=EvidenceCategory.AUTHENTICATION,
            correlation_state=corr_state,
            spec_evidence=spec_auth_ev,
            source_evidence=source_auth_ev,
            rationale=rationale,
        )
    )

    return (corr_state, tuple(evidence_pairs), rationale)


def align_authorization_evidence(
    pair: MatchedEndpointPair,
    spec_findings: list[Finding],
    source_findings: list[Finding],
) -> tuple[CorrelationState, tuple[CorrelatedEvidencePair, ...], str]:
    """Aligns object authorization / BOLA evidence across specification and source code.

    Evaluates explicit evidence chain:
      endpoint parameter -> identifier usage -> object lookup -> authorization / tenant evidence

    State definitions:
    - SUPPORTED: Spec exposes ID parameter, source queries object AND enforces
                 authorization/ownership/tenant boundaries.
    - COMPLEMENTARY: Spec exposes ID parameter, source queries object, but source LACKS
                     authorization check, synthesizing a potential BOLA condition.
    - INCONCLUSIVE: No object query detected or endpoint unmatched.
    """
    evidence_pairs: list[CorrelatedEvidencePair] = []

    if not pair.spec_operation or not pair.source_endpoint:
        return (CorrelationState.INCONCLUSIVE, (), "Unmatched endpoint cannot be aligned.")

    spec_op = pair.spec_operation
    source_ep = pair.source_endpoint

    # 1. Check if specification exposes direct object identifier parameter
    path_params = [p for p in spec_op.parameters if p.param_in == "path"]
    has_object_id_param = any(
        any(k in p.name.lower() for k in ("id", "uuid", "key", "slug", "code")) for p in path_params
    )

    has_object_lookup = len(source_ep.object_access_evidence) > 0
    has_authz_evidence = (len(source_ep.authz_evidence) + len(source_ep.tenant_evidence)) > 0

    # Collect evidence items
    spec_ev: Evidence | None = None
    for f in spec_findings:
        if f.rule_id == "API-AUTHZ-001" and f.evidence:
            for ev in f.evidence:
                if (ev.message and spec_op.path in ev.message) or (
                    ev.provenance and spec_op.path in ev.provenance
                ):
                    spec_ev = ev
                    break

    source_obj_ev = (
        source_ep.object_access_evidence[0] if source_ep.object_access_evidence else None
    )

    if has_object_id_param and has_object_lookup and has_authz_evidence:
        corr_state = CorrelationState.SUPPORTED
        rationale = (
            "Cross-layer authorization consistent: specification exposes object identifier "
            f"in path, and source handler '{source_ep.handler_name}' verifies caller "
            "authorization/ownership or tenant boundary before completing access."
        )
    elif has_object_id_param and has_object_lookup and not has_authz_evidence:
        corr_state = CorrelationState.COMPLEMENTARY
        rationale = (
            "Cross-layer facts synthesize potential BOLA: specification exposes object "
            f"identifier in path, source handler '{source_ep.handler_name}' directly queries "
            "data store using the identifier, and no recognizable authorization/ownership/tenant "
            "check exists in scope."
        )
    else:
        corr_state = CorrelationState.INCONCLUSIVE
        rationale = (
            "Authorization alignment inconclusive: no combined path identifier and database lookup "
            "detected."
        )

    evidence_pairs.append(
        CorrelatedEvidencePair(
            category=EvidenceCategory.AUTHORIZATION,
            correlation_state=corr_state,
            spec_evidence=spec_ev,
            source_evidence=source_obj_ev,
            rationale=rationale,
        )
    )

    return (corr_state, tuple(evidence_pairs), rationale)


def align_input_validation_evidence(
    pair: MatchedEndpointPair,
    spec_findings: list[Finding],
    source_findings: list[Finding],
) -> tuple[CorrelationState, tuple[CorrelatedEvidencePair, ...], str]:
    """Aligns parameter input validation evidence between OpenAPI schema and source code checks.

    Must establish a specific relationship between:
      endpoint -> parameter/field -> constraint -> source validation evidence
    If relationship cannot be established statically, returns INCONCLUSIVE.
    """
    evidence_pairs: list[CorrelatedEvidencePair] = []

    if not pair.spec_operation or not pair.source_endpoint:
        return (CorrelationState.INCONCLUSIVE, (), "Unmatched endpoint cannot be aligned.")

    spec_op = pair.spec_operation
    source_ep = pair.source_endpoint

    # Find spec input findings matching this path
    spec_input_findings = [
        f
        for f in spec_findings
        if f.rule_id == "API-INPUT-001"
        and f.evidence
        and any(ev.message and spec_op.path in ev.message for ev in f.evidence)
    ]

    has_spec_constraint_defect = len(spec_input_findings) > 0
    has_source_validation = len(source_ep.validation_evidence) > 0

    if not has_spec_constraint_defect and not has_source_validation:
        return (
            CorrelationState.INCONCLUSIVE,
            (),
            "No specific parameter constraint evidence present on either layer.",
        )

    # Correlate specific parameter validation
    matched_param_evidence = False
    for val_ev in source_ep.validation_evidence:
        if val_ev.symbol and any(
            val_ev.symbol.lower() in f.title.lower() for f in spec_input_findings
        ):
            matched_param_evidence = True
            break

    if has_spec_constraint_defect and matched_param_evidence:
        corr_state = CorrelationState.CONTRADICTED
        rationale = (
            "Specification omits validation constraint (e.g. maximum/pattern), but source handler "
            f"'{source_ep.handler_name}' implements manual conditional validation in code."
        )
    elif has_spec_constraint_defect and not has_source_validation:
        corr_state = CorrelationState.SUPPORTED
        rationale = (
            "Specification lacks validation constraint and source code contains no recognizable "
            f"manual validation logic in handler '{source_ep.handler_name}'."
        )
    else:
        corr_state = CorrelationState.INCONCLUSIVE
        rationale = (
            "Validation evidence between specification and source cannot be mapped to specific "
            "parameters."
        )

    spec_ev = spec_input_findings[0].evidence[0] if spec_input_findings else None
    source_ev = source_ep.validation_evidence[0] if source_ep.validation_evidence else None

    evidence_pairs.append(
        CorrelatedEvidencePair(
            category=EvidenceCategory.INPUT_VALIDATION,
            correlation_state=corr_state,
            spec_evidence=spec_ev,
            source_evidence=source_ev,
            rationale=rationale,
        )
    )

    return (corr_state, tuple(evidence_pairs), rationale)
