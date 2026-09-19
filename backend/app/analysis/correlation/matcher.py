import re

from app.analysis.context import (
    NormalizedOpenAPI,
    NormalizedOperation,
    NormalizedSourceEndpoint,
    NormalizedSourceTree,
)
from app.analysis.correlation.models import EndpointMatchState, MatchedEndpointPair

_PARAM_REGEX = re.compile(r"\{[a-zA-Z0-9_]+\}")


def normalize_to_canonical_template(path: str) -> str:
    """Normalizes path parameters to a generic '{param}' placeholder for matching only.

    Example: '/api/v1/users/{user_id}/items/{itemId}' -> '/api/v1/users/{param}/items/{param}'
    Does not modify original semantic parameter representations in evidence.
    """
    clean_path = "/" + path.strip("/") if path.strip("/") else "/"
    segments = [seg for seg in clean_path.split("/") if seg]
    normalized_segs = [
        "{param}" if (seg.startswith("{") and seg.endswith("}")) else seg for seg in segments
    ]
    return "/" + "/".join(normalized_segs)


def match_endpoints(
    specification: NormalizedOpenAPI | None,
    source_tree: NormalizedSourceTree | None,
) -> tuple[
    tuple[MatchedEndpointPair, ...],
    tuple[NormalizedOperation, ...],
    tuple[NormalizedSourceEndpoint, ...],
]:
    """Deterministically matches OpenAPI operations with source code endpoint handlers.

    Uses a 4-tier hierarchy:
    1. Exact (method, raw_path) match -> EXACT_MATCH
    2. Canonical parameter-normalized template match -> PARAMETER_NORMALIZED_MATCH
    3. OperationId to handler_name disambiguation -> PARAMETER_NORMALIZED_MATCH
    4. Multiple candidates unresolved -> AMBIGUOUS_MATCH
    5. Unmatched -> NO_MATCH

    Returns:
        (matched_pairs, unmatched_spec_operations, unmatched_source_endpoints)
    """
    if not specification or not specification.endpoints:
        unmatched_source = tuple(source_tree.endpoints) if source_tree else ()
        return (), (), unmatched_source

    if not source_tree or not source_tree.endpoints:
        all_spec_ops: list[NormalizedOperation] = []
        for ep in specification.endpoints:
            all_spec_ops.extend(ep.operations)
        return (), tuple(all_spec_ops), ()

    # Collect and sort all specification operations deterministically
    spec_ops: list[NormalizedOperation] = []
    for ep in specification.endpoints:
        for op in ep.operations:
            spec_ops.append(op)
    spec_ops.sort(key=lambda op: (op.path, op.method.lower()))

    # Collect and sort source endpoints deterministically
    source_eps: list[NormalizedSourceEndpoint] = sorted(
        source_tree.endpoints,
        key=lambda s: (s.path, s.method.lower(), s.file_path, s.handler_name),
    )

    matched_pairs: list[MatchedEndpointPair] = []
    matched_source_indices: set[int] = set()
    unmatched_spec_ops: list[NormalizedOperation] = []

    # Map source endpoints for fast deterministic lookup
    # 1. (method.lower(), raw_path.strip('/')) -> list of (index, source_ep)
    exact_source_map: dict[tuple[str, str], list[tuple[int, NormalizedSourceEndpoint]]] = {}
    # 2. (method.lower(), canonical_template) -> list of (index, source_ep)
    canonical_source_map: dict[tuple[str, str], list[tuple[int, NormalizedSourceEndpoint]]] = {}

    for idx, s_ep in enumerate(source_eps):
        m = s_ep.method.lower()
        raw_key = (m, s_ep.path.strip("/"))
        exact_source_map.setdefault(raw_key, []).append((idx, s_ep))

        canon_path = normalize_to_canonical_template(s_ep.path)
        canon_key = (m, canon_path)
        canonical_source_map.setdefault(canon_key, []).append((idx, s_ep))

    for op in spec_ops:
        m = op.method.lower()
        op_path = op.path
        raw_key = (m, op_path.strip("/"))
        canon_path = normalize_to_canonical_template(op_path)
        canon_key = (m, canon_path)

        # 1. Tier 1: Exact Match on raw path
        if raw_key in exact_source_map:
            candidates = exact_source_map[raw_key]
            # Take first available unmatched candidate or the exact candidate
            available = [c for c in candidates if c[0] not in matched_source_indices]
            target = available[0] if available else candidates[0]
            matched_source_indices.add(target[0])
            s_ep = target[1]
            matched_pairs.append(
                MatchedEndpointPair(
                    spec_path=op.path,
                    spec_method=op.method.upper(),
                    source_path=s_ep.path,
                    source_method=s_ep.method.upper(),
                    match_state=EndpointMatchState.EXACT_MATCH,
                    canonical_matching_path=canon_path,
                    spec_operation=op,
                    source_endpoint=s_ep,
                    spec_operation_id=op.operation_id,
                    source_handler_name=s_ep.handler_name,
                    match_rationale="Exact match on HTTP method and raw path string.",
                    spec_location=op.location,
                    source_location=s_ep.location,
                )
            )
            continue

        # 2. Tier 2: Canonical parameter-normalized template match
        if canon_key in canonical_source_map:
            candidates = canonical_source_map[canon_key]
            available = [c for c in candidates if c[0] not in matched_source_indices]
            active_pool = available if available else candidates

            if len(active_pool) == 1:
                target = active_pool[0]
                matched_source_indices.add(target[0])
                s_ep = target[1]
                matched_pairs.append(
                    MatchedEndpointPair(
                        spec_path=op.path,
                        spec_method=op.method.upper(),
                        source_path=s_ep.path,
                        source_method=s_ep.method.upper(),
                        match_state=EndpointMatchState.PARAMETER_NORMALIZED_MATCH,
                        canonical_matching_path=canon_path,
                        spec_operation=op,
                        source_endpoint=s_ep,
                        spec_operation_id=op.operation_id,
                        source_handler_name=s_ep.handler_name,
                        match_rationale=(
                            f"Matched via canonical path parameter normalization ('{canon_path}')."
                        ),
                        spec_location=op.location,
                        source_location=s_ep.location,
                    )
                )
                continue

            # 3. Tier 3: Multiple candidates -> Disambiguate using operation_id vs handler_name
            disambiguated = False
            if op.operation_id:
                clean_op_id = op.operation_id.lower().replace("_", "").replace("-", "")
                for c in active_pool:
                    clean_handler = c[1].handler_name.lower().replace("_", "").replace("-", "")
                    if clean_op_id == clean_handler:
                        matched_source_indices.add(c[0])
                        s_ep = c[1]
                        matched_pairs.append(
                            MatchedEndpointPair(
                                spec_path=op.path,
                                spec_method=op.method.upper(),
                                source_path=s_ep.path,
                                source_method=s_ep.method.upper(),
                                match_state=EndpointMatchState.PARAMETER_NORMALIZED_MATCH,
                                canonical_matching_path=canon_path,
                                spec_operation=op,
                                source_endpoint=s_ep,
                                spec_operation_id=op.operation_id,
                                source_handler_name=s_ep.handler_name,
                                match_rationale=(
                                    f"Resolved ambiguous template '{canon_path}' via matching "
                                    f"operationId '{op.operation_id}' and handler "
                                    f"'{s_ep.handler_name}'."
                                ),
                                spec_location=op.location,
                                source_location=s_ep.location,
                            )
                        )
                        disambiguated = True
                        break

            if disambiguated:
                continue

            # 4. Tier 4: Still Ambiguous
            candidate_names = [f"{c[1].file_path}:{c[1].handler_name}" for c in active_pool]
            matched_pairs.append(
                MatchedEndpointPair(
                    spec_path=op.path,
                    spec_method=op.method.upper(),
                    source_path=None,
                    source_method=None,
                    match_state=EndpointMatchState.AMBIGUOUS_MATCH,
                    canonical_matching_path=canon_path,
                    spec_operation=op,
                    source_endpoint=None,
                    spec_operation_id=op.operation_id,
                    source_handler_name=None,
                    match_rationale=(
                        f"Ambiguous match: multiple source handlers match template '{canon_path}': "
                        f"{', '.join(candidate_names)}"
                    ),
                    spec_location=op.location,
                    source_location=None,
                )
            )
            continue

        # 5. Tier 5: No Match (Zombie Spec Endpoint)
        unmatched_spec_ops.append(op)
        matched_pairs.append(
            MatchedEndpointPair(
                spec_path=op.path,
                spec_method=op.method.upper(),
                source_path=None,
                source_method=None,
                match_state=EndpointMatchState.NO_MATCH,
                canonical_matching_path=canon_path,
                spec_operation=op,
                source_endpoint=None,
                spec_operation_id=op.operation_id,
                source_handler_name=None,
                match_rationale="No source code handler matches this specification endpoint.",
                spec_location=op.location,
                source_location=None,
            )
        )

    # Collect unmatched source endpoints (Shadow Endpoints)
    unmatched_source_eps: list[NormalizedSourceEndpoint] = [
        s_ep for idx, s_ep in enumerate(source_eps) if idx not in matched_source_indices
    ]

    # Deterministic sorting of matched pairs
    matched_pairs.sort(
        key=lambda p: (
            p.spec_path,
            p.spec_method,
            p.source_path or "",
            p.source_method or "",
            p.match_state,
        )
    )

    return (
        tuple(matched_pairs),
        tuple(unmatched_spec_ops),
        tuple(unmatched_source_eps),
    )
