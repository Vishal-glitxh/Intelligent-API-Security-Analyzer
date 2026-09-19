from pathlib import Path

from app.analysis.openapi.loader import load_openapi_spec
from app.analysis.openapi.normalizer import normalize_openapi_spec
from app.analysis.openapi.resolver import RefStatus, resolve_internal_ref

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "openapi"


def test_normalizer_extracts_endpoints_and_security() -> None:
    yaml_path = FIXTURES_DIR / "valid_v30.yaml"
    content = yaml_path.read_text(encoding="utf-8")
    loaded = load_openapi_spec(content, file_path=str(yaml_path))
    norm = normalize_openapi_spec(loaded)

    assert norm.title == "Sample Valid 3.0 API"
    assert norm.version == "1.0.0"
    assert norm.openapi_version == "3.0.3"
    assert norm.servers == ("https://api.example.com/v1",)
    assert len(norm.security_schemes) == 1
    assert norm.security_schemes[0].name == "BearerAuth"
    assert norm.security_schemes[0].scheme_type == "http"
    assert norm.security_schemes[0].scheme == "bearer"
    assert norm.security_schemes[0].bearer_format == "JWT"

    assert len(norm.global_security) == 1
    assert "BearerAuth" in norm.global_security[0]

    # Check endpoints
    assert len(norm.endpoints) == 2
    paths = {e.path: e for e in norm.endpoints}
    assert "/ping" in paths
    assert "/items" in paths

    # Check /ping operation has explicit empty security override
    ping_op = paths["ping" if "ping" in paths else "/ping"].operations[0]
    assert ping_op.method == "get"
    assert ping_op.has_explicit_security_override is True
    assert ping_op.effective_security == ()

    # Check /items operation inherits global security
    items_op = paths["/items"].operations[0]
    assert items_op.has_explicit_security_override is False
    assert len(items_op.effective_security) == 1
    assert "BearerAuth" in items_op.effective_security[0]

    # Check parameter constraints on limit
    limit_param = items_op.parameters[0]
    assert limit_param.name == "limit"
    assert limit_param.schema_type == "integer"
    assert limit_param.constraints.get("minimum") == 1
    assert limit_param.constraints.get("maximum") == 100


def test_normalizer_resolves_refs_and_handles_circular() -> None:
    ref_path = FIXTURES_DIR / "ref_resolution.yaml"
    content = ref_path.read_text(encoding="utf-8")
    loaded = load_openapi_spec(content, file_path=str(ref_path))
    norm = normalize_openapi_spec(loaded)

    # Check that circular ref is detected safely without infinite recursion
    raw_spec = loaded.raw_data
    circ_res = resolve_internal_ref(raw_spec, "#/components/schemas/CircularNode")
    assert circ_res.status == RefStatus.RESOLVED_INTERNAL

    # Chained ref resolution
    chained_res = resolve_internal_ref(raw_spec, "#/components/schemas/ChainedModel")
    assert chained_res.status == RefStatus.RESOLVED_INTERNAL
    assert chained_res.resolved_data is not None
    assert "properties" in chained_res.resolved_data

    # Check unsupported external ref
    ext_res = resolve_internal_ref(raw_spec, "https://example.com/schemas/external.yaml#/External")
    assert ext_res.status == RefStatus.UNSUPPORTED_EXTERNAL

    # Check missing internal ref
    missing_res = resolve_internal_ref(raw_spec, "#/components/schemas/NonExistentModel")
    assert missing_res.status == RefStatus.UNRESOLVED_INTERNAL

    # Verify normalization captured the reference on the endpoint response
    endpoint = norm.endpoints[0]
    op = endpoint.operations[0]
    resp_200 = op.response_schemas.get("200")
    assert resp_200 is not None
    assert resp_200.name == "ChainedModel"
    assert len(resp_200.properties) == 1
    assert resp_200.properties[0].name == "id"


def test_normalizer_security_schemes_and_request_bodies() -> None:
    spec_yaml = """
openapi: 3.0.3
info:
  title: Multi Scheme API
  version: 1.0.0
servers:
  - url: https://api.example.com
components:
  securitySchemes:
    ApiKeyHeader:
      type: apiKey
      name: X-API-KEY
      in: header
    ApiKeyQuery:
      type: apiKey
      name: api_key
      in: query
    ApiKeyCookie:
      type: apiKey
      name: session_id
      in: cookie
    OAuthFlow:
      type: oauth2
      description: OAuth2 flows
      flows:
        implicit:
          authorizationUrl: https://auth.example.com/oauth/authorize
          scopes:
            read: Read access
    OidcScheme:
      type: openIdConnect
      openIdConnectUrl: https://auth.example.com/.well-known/openid-configuration
paths:
  /users:
    post:
      summary: Create user
      requestBody:
        description: User payload
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - email
              properties:
                email:
                  type: string
                  format: email
                  minLength: 5
                  maxLength: 254
                  pattern: "^[^@]+@[^@]+$"
                role:
                  type: string
                  enum: [admin, user, guest]
      responses:
        '201':
          description: Created
"""
    loaded = load_openapi_spec(spec_yaml)
    norm = normalize_openapi_spec(loaded)

    scheme_names = {s.name for s in norm.security_schemes}
    assert "ApiKeyHeader" in scheme_names
    assert "ApiKeyQuery" in scheme_names
    assert "ApiKeyCookie" in scheme_names
    assert "OAuthFlow" in scheme_names
    assert "OidcScheme" in scheme_names

    apiKey_cookie = next(s for s in norm.security_schemes if s.name == "ApiKeyCookie")
    assert apiKey_cookie.param_in == "cookie"
    assert apiKey_cookie.param_name == "session_id"

    op = norm.endpoints[0].operations[0]
    assert op.request_body_schema is not None
    assert len(op.request_body_schema.properties) == 2

    props = {p.name: p for p in op.request_body_schema.properties}
    assert props["email"].required is True
    assert props["email"].format == "email"
    assert props["role"].required is False
