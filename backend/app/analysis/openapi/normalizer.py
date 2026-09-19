from typing import Any

from app.analysis.context import (
    NormalizedEndpoint,
    NormalizedOpenAPI,
    NormalizedOperation,
    NormalizedParameter,
    NormalizedProperty,
    NormalizedSchema,
    NormalizedSecurityScheme,
    SourceLocation,
)
from app.analysis.openapi.loader import LoadedSpec, _encode_json_pointer_token
from app.analysis.openapi.resolver import RefStatus, resolve_internal_ref

_HTTP_METHODS = ("get", "post", "put", "delete", "patch", "options", "head", "trace")
_SCHEMA_CONSTRAINT_KEYS = (
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "pattern",
    "enum",
    "minItems",
    "maxItems",
    "uniqueItems",
    "multipleOf",
    "format",
)


def _get_location(location_map: dict[str, SourceLocation], pointer: str) -> SourceLocation | None:
    return location_map.get(pointer)


def _normalize_security_list(raw_sec: Any) -> tuple[dict[str, list[str]], ...]:
    if not isinstance(raw_sec, list):
        return ()
    result: list[dict[str, list[str]]] = []
    for item in raw_sec:
        if isinstance(item, dict):
            sec_dict: dict[str, list[str]] = {}
            for k, v in item.items():
                sec_dict[str(k)] = [str(x) for x in v] if isinstance(v, list) else []
            result.append(sec_dict)
    return tuple(result)


def normalize_openapi_spec(
    loaded_spec: LoadedSpec,
    provenance: str | None = None,
) -> NormalizedOpenAPI:
    """Normalize a validated OpenAPI LoadedSpec into immutable NormalizedOpenAPI models."""
    raw = loaded_spec.raw_data
    loc_map = loaded_spec.location_map
    spec_hash = loaded_spec.spec_hash
    file_path = loaded_spec.file_path

    unresolved_refs: set[str] = set()
    unsupported_external_refs: set[str] = set()
    circular_refs: set[str] = set()

    def record_ref_status(ref: str, status: RefStatus) -> None:
        if status == RefStatus.UNRESOLVED_INTERNAL:
            unresolved_refs.add(ref)
        elif status == RefStatus.UNSUPPORTED_EXTERNAL:
            unsupported_external_refs.add(ref)
        elif status == RefStatus.CIRCULAR:
            circular_refs.add(ref)

    # 1. API Metadata
    info = raw.get("info", {}) if isinstance(raw.get("info"), dict) else {}
    title = str(info.get("title", ""))
    version = str(info.get("version", "1.0.0"))
    openapi_version = str(raw.get("openapi", "3.0.0")).strip()

    servers: list[str] = []
    if isinstance(raw.get("servers"), list):
        for s in raw["servers"]:
            if isinstance(s, dict) and "url" in s:
                servers.append(str(s["url"]))

    # 2. Security Schemes
    security_schemes: list[NormalizedSecurityScheme] = []
    components = raw.get("components", {}) if isinstance(raw.get("components"), dict) else {}
    raw_schemes = (
        components.get("securitySchemes", {})
        if isinstance(components.get("securitySchemes"), dict)
        else {}
    )

    for scheme_name, scheme_data in raw_schemes.items():
        if not isinstance(scheme_data, dict):
            continue
        pointer = f"/components/securitySchemes/{_encode_json_pointer_token(scheme_name)}"

        # Resolve scheme $ref if present
        if "$ref" in scheme_data and isinstance(scheme_data["$ref"], str):
            res = resolve_internal_ref(raw, scheme_data["$ref"])
            record_ref_status(scheme_data["$ref"], res.status)
            if res.resolved_data:
                scheme_data = res.resolved_data

        norm_scheme = NormalizedSecurityScheme(
            name=str(scheme_name),
            scheme_type=str(scheme_data.get("type", "unknown")),
            scheme=str(scheme_data["scheme"]) if "scheme" in scheme_data else None,
            bearer_format=(
                str(scheme_data["bearerFormat"]) if "bearerFormat" in scheme_data else None
            ),
            param_in=str(scheme_data["in"]) if "in" in scheme_data else None,
            param_name=str(scheme_data["name"]) if "name" in scheme_data else None,
            description=str(scheme_data["description"]) if "description" in scheme_data else None,
            flows=dict(scheme_data.get("flows", {}))
            if isinstance(scheme_data.get("flows"), dict)
            else {},
            location=_get_location(loc_map, pointer),
        )
        security_schemes.append(norm_scheme)

    # 3. Global Security
    global_security = _normalize_security_list(raw.get("security"))

    # Helper to normalize schema
    def normalize_schema(
        raw_schema: Any,
        schema_pointer: str,
        visited_refs: frozenset[str] = frozenset(),
    ) -> NormalizedSchema | None:
        if not isinstance(raw_schema, dict):
            return None

        schema_name: str | None = None
        ref_status: str | None = None
        target_schema = raw_schema
        active_pointer = schema_pointer

        if "$ref" in raw_schema and isinstance(raw_schema["$ref"], str):
            ref_str = raw_schema["$ref"]
            res = resolve_internal_ref(raw, ref_str, visited_refs)
            record_ref_status(ref_str, res.status)
            ref_status = str(res.status)
            if res.status == RefStatus.RESOLVED_INTERNAL and res.resolved_data:
                schema_name = ref_str.split("/")[-1]
                target_schema = res.resolved_data
                visited_refs = visited_refs | {ref_str}
                if ref_str.startswith("#/"):
                    active_pointer = ref_str[1:]
            elif res.status == RefStatus.CIRCULAR:
                return NormalizedSchema(
                    name=ref_str.split("/")[-1],
                    schema_type="circular",
                    ref_status=str(RefStatus.CIRCULAR),
                    location=_get_location(loc_map, schema_pointer),
                )
            else:
                return NormalizedSchema(
                    name=ref_str.split("/")[-1],
                    schema_type="unresolved",
                    ref_status=ref_status,
                    location=_get_location(loc_map, schema_pointer),
                )

        schema_type = str(target_schema.get("type", "object"))
        required_props = (
            tuple(str(x) for x in target_schema["required"])
            if isinstance(target_schema.get("required"), list)
            else ()
        )

        properties: list[NormalizedProperty] = []
        raw_props = (
            target_schema.get("properties", {})
            if isinstance(target_schema.get("properties"), dict)
            else {}
        )

        for prop_name, prop_data in raw_props.items():
            if not isinstance(prop_data, dict):
                continue
            prop_ptr = f"{active_pointer}/properties/{_encode_json_pointer_token(prop_name)}"
            prop_loc = _get_location(loc_map, prop_ptr) or _get_location(loc_map, schema_pointer)

            # Resolve property $ref if present
            if "$ref" in prop_data and isinstance(prop_data["$ref"], str):
                prop_ref = prop_data["$ref"]
                prop_res = resolve_internal_ref(raw, prop_ref, visited_refs)
                record_ref_status(prop_ref, prop_res.status)
                if prop_res.resolved_data:
                    prop_data = prop_res.resolved_data

            properties.append(
                NormalizedProperty(
                    name=str(prop_name),
                    property_type=str(prop_data.get("type")) if "type" in prop_data else None,
                    format=str(prop_data.get("format")) if "format" in prop_data else None,
                    required=str(prop_name) in required_props,
                    description=(
                        str(prop_data.get("description")) if "description" in prop_data else None
                    ),
                    location=prop_loc,
                )
            )

        items_schema: NormalizedSchema | None = None
        if "items" in target_schema and isinstance(target_schema["items"], dict):
            items_ptr = f"{schema_pointer}/items"
            items_schema = normalize_schema(target_schema["items"], items_ptr, visited_refs)

        return NormalizedSchema(
            name=schema_name,
            schema_type=schema_type,
            properties=tuple(properties),
            required_properties=required_props,
            items_schema=items_schema,
            location=_get_location(loc_map, schema_pointer),
            ref_status=ref_status,
        )

    # 4. Endpoints & Operations
    endpoints: list[NormalizedEndpoint] = []
    raw_paths = raw.get("paths", {}) if isinstance(raw.get("paths"), dict) else {}

    for path_str, path_item in raw_paths.items():
        if not isinstance(path_item, dict):
            continue
        path_ptr = f"/paths/{_encode_json_pointer_token(path_str)}"
        path_loc = _get_location(loc_map, path_ptr)

        # Path-level parameters
        raw_path_params = (
            path_item.get("parameters", []) if isinstance(path_item.get("parameters"), list) else []
        )

        operations: list[NormalizedOperation] = []

        for method in _HTTP_METHODS:
            if method not in path_item or not isinstance(path_item[method], dict):
                continue
            op_data = path_item[method]
            op_ptr = f"{path_ptr}/{method}"
            op_loc = _get_location(loc_map, op_ptr)

            op_id = str(op_data["operationId"]) if "operationId" in op_data else None
            summary = str(op_data["summary"]) if "summary" in op_data else None
            description = str(op_data["description"]) if "description" in op_data else None
            tags = (
                tuple(str(t) for t in op_data["tags"])
                if isinstance(op_data.get("tags"), list)
                else ()
            )
            deprecated = bool(op_data.get("deprecated", False))

            # Merged parameters (operation-level overrides path-level)
            op_params_raw = (
                op_data.get("parameters", []) if isinstance(op_data.get("parameters"), list) else []
            )
            merged_param_map: dict[tuple[str, str], dict[str, Any]] = {}

            # Add path-level parameters
            for p in raw_path_params:
                if isinstance(p, dict):
                    if "$ref" in p and isinstance(p["$ref"], str):
                        res = resolve_internal_ref(raw, p["$ref"])
                        record_ref_status(p["$ref"], res.status)
                        if res.resolved_data:
                            p = res.resolved_data
                    if "name" in p and "in" in p:
                        merged_param_map[(str(p["name"]), str(p["in"]))] = p

            # Override with operation-level parameters
            for idx, p in enumerate(op_params_raw):
                if isinstance(p, dict):
                    param_ptr = f"{op_ptr}/parameters/{idx}"
                    if "$ref" in p and isinstance(p["$ref"], str):
                        res = resolve_internal_ref(raw, p["$ref"])
                        record_ref_status(p["$ref"], res.status)
                        if res.resolved_data:
                            p = res.resolved_data
                    if "name" in p and "in" in p:
                        merged_param_map[(str(p["name"]), str(p["in"]))] = (p, param_ptr)  # type: ignore[assignment]

            norm_parameters: list[NormalizedParameter] = []
            for (p_name, p_in), p_val in merged_param_map.items():
                param_dict: dict[str, Any]
                p_ptr: str
                if isinstance(p_val, tuple):
                    param_dict, p_ptr = p_val
                else:
                    param_dict = p_val
                    p_ptr = f"{path_ptr}/parameters"

                # Extract schema and constraints
                schema_dict = (
                    param_dict.get("schema", {})
                    if isinstance(param_dict.get("schema"), dict)
                    else {}
                )
                if "$ref" in schema_dict and isinstance(schema_dict["$ref"], str):
                    s_res = resolve_internal_ref(raw, schema_dict["$ref"])
                    record_ref_status(schema_dict["$ref"], s_res.status)
                    if s_res.resolved_data:
                        schema_dict = s_res.resolved_data

                constraints: dict[str, Any] = {}
                for ck in _SCHEMA_CONSTRAINT_KEYS:
                    if ck in schema_dict:
                        constraints[ck] = schema_dict[ck]
                    elif ck in param_dict:
                        constraints[ck] = param_dict[ck]

                schema_type = (
                    str(schema_dict.get("type"))
                    if "type" in schema_dict
                    else (str(param_dict.get("type")) if "type" in param_dict else None)
                )

                norm_parameters.append(
                    NormalizedParameter(
                        name=p_name,
                        param_in=p_in,
                        required=bool(param_dict.get("required", p_in == "path")),
                        schema_type=schema_type,
                        description=(
                            str(param_dict.get("description"))
                            if "description" in param_dict
                            else None
                        ),
                        constraints=constraints,
                        location=_get_location(loc_map, p_ptr),
                    )
                )

            # Security Requirements & Effective Security
            has_explicit_security_override = "security" in op_data
            if has_explicit_security_override:
                op_sec = _normalize_security_list(op_data.get("security"))
                security_requirements = op_sec
                effective_security = op_sec
            else:
                security_requirements = ()
                effective_security = global_security

            # Request Body Schema
            req_body_schema: NormalizedSchema | None = None
            if "requestBody" in op_data and isinstance(op_data["requestBody"], dict):
                rb_data = op_data["requestBody"]
                rb_ptr = f"{op_ptr}/requestBody"
                if "$ref" in rb_data and isinstance(rb_data["$ref"], str):
                    rb_res = resolve_internal_ref(raw, rb_data["$ref"])
                    record_ref_status(rb_data["$ref"], rb_res.status)
                    if rb_res.resolved_data:
                        rb_data = rb_res.resolved_data

                rb_content = (
                    rb_data.get("content", {}) if isinstance(rb_data.get("content"), dict) else {}
                )
                for media_type, media_obj in rb_content.items():
                    if isinstance(media_obj, dict) and "schema" in media_obj:
                        media_ptr = (
                            f"{rb_ptr}/content/{_encode_json_pointer_token(media_type)}/schema"
                        )
                        req_body_schema = normalize_schema(media_obj["schema"], media_ptr)
                        break

            # Response Schemas
            resp_schemas: dict[str, NormalizedSchema] = {}
            if "responses" in op_data and isinstance(op_data["responses"], dict):
                for status_code, resp_obj in op_data["responses"].items():
                    if not isinstance(resp_obj, dict):
                        continue
                    resp_ptr = f"{op_ptr}/responses/{status_code}"
                    if "$ref" in resp_obj and isinstance(resp_obj["$ref"], str):
                        resp_res = resolve_internal_ref(raw, resp_obj["$ref"])
                        record_ref_status(resp_obj["$ref"], resp_res.status)
                        if resp_res.resolved_data:
                            resp_obj = resp_res.resolved_data

                    resp_content = (
                        resp_obj.get("content", {})
                        if isinstance(resp_obj.get("content"), dict)
                        else {}
                    )
                    for media_type, media_obj in resp_content.items():
                        if isinstance(media_obj, dict) and "schema" in media_obj:
                            enc_media = _encode_json_pointer_token(media_type)
                            m_ptr = f"{resp_ptr}/content/{enc_media}/schema"
                            norm_resp_schema = normalize_schema(media_obj["schema"], m_ptr)
                            if norm_resp_schema:
                                resp_schemas[str(status_code)] = norm_resp_schema
                            break

            operations.append(
                NormalizedOperation(
                    method=method,
                    path=path_str,
                    operation_id=op_id,
                    summary=summary,
                    description=description,
                    tags=tags,
                    deprecated=deprecated,
                    parameters=tuple(norm_parameters),
                    security_requirements=security_requirements,
                    effective_security=effective_security,
                    has_explicit_security_override=has_explicit_security_override,
                    request_body_schema=req_body_schema,
                    response_schemas=resp_schemas,
                    location=op_loc,
                )
            )

        if operations:
            endpoints.append(
                NormalizedEndpoint(
                    path=path_str,
                    operations=tuple(operations),
                    location=path_loc,
                )
            )

    return NormalizedOpenAPI(
        title=title,
        version=version,
        openapi_version=openapi_version,
        servers=tuple(servers),
        endpoints=tuple(endpoints),
        security_schemes=tuple(security_schemes),
        global_security=global_security,
        spec_hash=spec_hash,
        provenance=provenance or f"file:{file_path}",
        unresolved_refs=tuple(sorted(unresolved_refs)),
        unsupported_external_refs=tuple(sorted(unsupported_external_refs)),
        circular_refs=tuple(sorted(circular_refs)),
    )
