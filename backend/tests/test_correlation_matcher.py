from app.analysis.context import (
    NormalizedEndpoint,
    NormalizedOpenAPI,
    NormalizedOperation,
    NormalizedSourceEndpoint,
    NormalizedSourceParameter,
    NormalizedSourceTree,
    SourceLocation,
)
from app.analysis.correlation.matcher import match_endpoints, normalize_to_canonical_template
from app.analysis.correlation.models import EndpointMatchState


def test_normalize_to_canonical_template() -> None:
    assert normalize_to_canonical_template("/users/{user_id}") == "/users/{param}"
    assert normalize_to_canonical_template("/users/{userId}/items/{itemId}") == (
        "/users/{param}/items/{param}"
    )
    assert normalize_to_canonical_template("/health") == "/health"
    assert normalize_to_canonical_template("/") == "/"


def test_exact_match() -> None:
    op = NormalizedOperation(
        method="get",
        path="/api/v1/users",
        operation_id="list_users",
        location=SourceLocation(file="spec.yaml", line=10, column=5),
    )
    spec = NormalizedOpenAPI(
        endpoints=(NormalizedEndpoint(path="/api/v1/users", operations=(op,)),)
    )

    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/api/v1/users",
        raw_path="/api/v1/users",
        handler_name="list_users",
        file_path="app/routes.py",
        framework="fastapi",
        location=SourceLocation(file="app/routes.py", line=20, column=1),
    )
    source = NormalizedSourceTree(endpoints=(s_ep,))

    matched, unmatched_spec, unmatched_source = match_endpoints(spec, source)

    assert len(matched) == 1
    assert matched[0].match_state == EndpointMatchState.EXACT_MATCH
    assert matched[0].spec_path == "/api/v1/users"
    assert matched[0].source_path == "/api/v1/users"
    assert matched[0].spec_operation_id == "list_users"
    assert matched[0].source_handler_name == "list_users"
    assert len(unmatched_spec) == 0
    assert len(unmatched_source) == 0


def test_parameter_normalized_match() -> None:
    # Spec uses camelCase {userId}, source uses snake_case {user_id}
    op = NormalizedOperation(
        method="get",
        path="/api/v1/users/{userId}",
        operation_id="get_user",
        location=SourceLocation(file="spec.yaml", line=15, column=5),
    )
    spec = NormalizedOpenAPI(
        endpoints=(NormalizedEndpoint(path="/api/v1/users/{userId}", operations=(op,)),)
    )

    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/api/v1/users/{user_id}",
        raw_path="/api/v1/users/{user_id}",
        handler_name="get_user_handler",
        file_path="app/routes.py",
        framework="fastapi",
        parameters=(NormalizedSourceParameter(name="user_id", is_path_param=True),),
        location=SourceLocation(file="app/routes.py", line=30, column=1),
    )
    source = NormalizedSourceTree(endpoints=(s_ep,))

    matched, unmatched_spec, unmatched_source = match_endpoints(spec, source)

    assert len(matched) == 1
    assert matched[0].match_state == EndpointMatchState.PARAMETER_NORMALIZED_MATCH
    assert matched[0].spec_path == "/api/v1/users/{userId}"
    assert matched[0].source_path == "/api/v1/users/{user_id}"
    assert matched[0].canonical_matching_path == "/api/v1/users/{param}"
    assert len(unmatched_spec) == 0
    assert len(unmatched_source) == 0


def test_ambiguous_match_and_disambiguation() -> None:
    # Spec has two operations sharing a template, but with distinct operationId
    op1 = NormalizedOperation(
        method="get",
        path="/items/{item_id}",
        operation_id="get_item_detail",
    )
    spec = NormalizedOpenAPI(
        endpoints=(NormalizedEndpoint(path="/items/{item_id}", operations=(op1,)),)
    )

    s_ep1 = NormalizedSourceEndpoint(
        method="get",
        path="/items/{itemId}",
        raw_path="/items/{itemId}",
        handler_name="get_item_detail",
        file_path="app/items.py",
        framework="fastapi",
    )
    s_ep2 = NormalizedSourceEndpoint(
        method="get",
        path="/items/{id}",
        raw_path="/items/{id}",
        handler_name="other_item_handler",
        file_path="app/legacy.py",
        framework="fastapi",
    )
    source = NormalizedSourceTree(endpoints=(s_ep1, s_ep2))

    # Should disambiguate to s_ep1 because operation_id matches handler_name
    matched, unmatched_spec, unmatched_source = match_endpoints(spec, source)
    assert len(matched) == 1
    assert matched[0].match_state == EndpointMatchState.PARAMETER_NORMALIZED_MATCH
    assert matched[0].source_handler_name == "get_item_detail"
    assert len(unmatched_source) == 1  # s_ep2 is unmatched (shadow)


def test_shadow_and_zombie_endpoints() -> None:
    # Spec has /spec-only, Source has /source-only
    op = NormalizedOperation(
        method="delete",
        path="/spec-only",
        operation_id="zombie_op",
    )
    spec = NormalizedOpenAPI(endpoints=(NormalizedEndpoint(path="/spec-only", operations=(op,)),))

    s_ep = NormalizedSourceEndpoint(
        method="post",
        path="/source-only",
        raw_path="/source-only",
        handler_name="shadow_handler",
        file_path="app/shadow.py",
        framework="flask",
    )
    source = NormalizedSourceTree(endpoints=(s_ep,))

    matched, unmatched_spec, unmatched_source = match_endpoints(spec, source)

    assert len(matched) == 1
    assert matched[0].match_state == EndpointMatchState.NO_MATCH
    assert matched[0].spec_path == "/spec-only"
    assert len(unmatched_spec) == 1
    assert unmatched_spec[0].path == "/spec-only"
    assert len(unmatched_source) == 1
    assert unmatched_source[0].path == "/source-only"


def test_flask_parameter_conversion_match() -> None:
    # Flask route originally declared as @app.route('/users/<int:user_id>')
    # normalized to /users/{user_id} by Phase 3 extractor
    op = NormalizedOperation(
        method="get",
        path="/users/{user_id}",
        operation_id="get_user",
    )
    spec = NormalizedOpenAPI(
        endpoints=(NormalizedEndpoint(path="/users/{user_id}", operations=(op,)),)
    )

    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/users/{user_id}",
        raw_path="/users/<int:user_id>",
        handler_name="get_user_by_id",
        file_path="app/views.py",
        framework="flask",
        parameters=(NormalizedSourceParameter(name="user_id", is_path_param=True),),
    )
    source = NormalizedSourceTree(endpoints=(s_ep,))

    matched, unmatched_spec, unmatched_source = match_endpoints(spec, source)
    assert len(matched) == 1
    assert matched[0].match_state == EndpointMatchState.EXACT_MATCH
    assert matched[0].spec_path == "/users/{user_id}"
    assert matched[0].source_path == "/users/{user_id}"
    assert len(unmatched_spec) == 0
    assert len(unmatched_source) == 0


def test_fastapi_router_prefix_match() -> None:
    # FastAPI APIRouter(prefix='/api/v2') + @router.get('/products/{id}')
    op = NormalizedOperation(
        method="get",
        path="/api/v2/products/{productId}",
        operation_id="get_product",
    )
    spec = NormalizedOpenAPI(
        endpoints=(NormalizedEndpoint(path="/api/v2/products/{productId}", operations=(op,)),)
    )

    s_ep = NormalizedSourceEndpoint(
        method="get",
        path="/api/v2/products/{product_id}",
        raw_path="/products/{product_id}",
        handler_name="read_product",
        file_path="app/routers/products.py",
        framework="fastapi",
        parameters=(NormalizedSourceParameter(name="product_id", is_path_param=True),),
    )
    source = NormalizedSourceTree(endpoints=(s_ep,))

    matched, unmatched_spec, unmatched_source = match_endpoints(spec, source)
    assert len(matched) == 1
    assert matched[0].match_state == EndpointMatchState.PARAMETER_NORMALIZED_MATCH
    assert matched[0].canonical_matching_path == "/api/v2/products/{param}"
    assert matched[0].spec_path == "/api/v2/products/{productId}"
    assert matched[0].source_path == "/api/v2/products/{product_id}"


def test_unresolvable_ambiguous_match() -> None:
    # Multiple candidates in source, neither matches operation_id
    op = NormalizedOperation(
        method="get",
        path="/data/{id}",
        operation_id="unrelated_op_id",
    )
    spec = NormalizedOpenAPI(endpoints=(NormalizedEndpoint(path="/data/{id}", operations=(op,)),))

    s_ep1 = NormalizedSourceEndpoint(
        method="get",
        path="/data/{dataId}",
        raw_path="/data/{dataId}",
        handler_name="handler_one",
        file_path="app/v1.py",
        framework="fastapi",
    )
    s_ep2 = NormalizedSourceEndpoint(
        method="get",
        path="/data/{recordId}",
        raw_path="/data/{recordId}",
        handler_name="handler_two",
        file_path="app/v2.py",
        framework="fastapi",
    )
    source = NormalizedSourceTree(endpoints=(s_ep1, s_ep2))

    matched, unmatched_spec, unmatched_source = match_endpoints(spec, source)
    assert len(matched) == 1
    assert matched[0].match_state == EndpointMatchState.AMBIGUOUS_MATCH
    assert matched[0].spec_path == "/data/{id}"
    assert matched[0].source_path is None
    assert "Ambiguous match" in matched[0].match_rationale
