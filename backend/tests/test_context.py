from dataclasses import FrozenInstanceError

import pytest
from app.analysis.context import (
    AnalysisContext,
    NormalizedEndpoint,
    NormalizedOpenAPI,
    NormalizedOperation,
    NormalizedParameter,
    NormalizedProperty,
    NormalizedSchema,
    NormalizedSourceFile,
    NormalizedSourceTree,
    ScanMetadata,
    SourceLocation,
)


def test_analysis_context_empty_defaults() -> None:
    ctx = AnalysisContext()
    assert ctx.specification is None
    assert ctx.source is None
    assert ctx.metadata is None


def test_analysis_context_normalized_construction() -> None:
    loc = SourceLocation(file="openapi.yaml", line=10, column=5)
    param = NormalizedParameter(
        name="user_id",
        param_in="path",
        required=True,
        schema_type="string",
        location=loc,
    )
    prop = NormalizedProperty(name="email", property_type="string", required=True)
    schema = NormalizedSchema(
        name="UserDTO",
        schema_type="object",
        properties=(prop,),
        required_properties=("email",),
    )
    operation = NormalizedOperation(
        method="get",
        path="/users/{user_id}",
        operation_id="getUserById",
        parameters=(param,),
        security_requirements=({"BearerAuth": []},),
        response_schemas={"200": schema},
        location=loc,
    )
    endpoint = NormalizedEndpoint(path="/users/{user_id}", operations=(operation,), location=loc)
    spec = NormalizedOpenAPI(
        title="Test API",
        version="3.1.0",
        endpoints=(endpoint,),
        spec_hash="sha256:spec123",
        provenance="spec_upload_01",
    )

    src_file = NormalizedSourceFile(
        path="src/users.py",
        content_hash="sha256:src456",
        detected_routes=("/users/{user_id}",),
        provenance="repo_zip_01",
    )
    src_tree = NormalizedSourceTree(files=(src_file,), source_hash="sha256:tree789")

    metadata = ScanMetadata(
        engine_version="0.1.0",
        rule_set_version="0.1.0",
        config_version="1.0.0",
        spec_hash="sha256:spec123",
        source_hash="sha256:tree789",
    )

    ctx = AnalysisContext(specification=spec, source=src_tree, metadata=metadata)

    assert ctx.specification is not None
    assert ctx.specification.title == "Test API"
    assert len(ctx.specification.endpoints) == 1
    assert ctx.specification.endpoints[0].operations[0].method == "get"
    assert ctx.source is not None
    assert len(ctx.source.files) == 1
    assert ctx.metadata is not None
    assert ctx.metadata.engine_version == "0.1.0"


def test_analysis_context_immutability() -> None:
    ctx = AnalysisContext()
    with pytest.raises(FrozenInstanceError):
        ctx.specification = None  # type: ignore[misc]
