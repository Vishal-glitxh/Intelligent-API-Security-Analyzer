from app.analysis.source.extractor import extract_function_security_evidence
from app.analysis.source.fastapi import extract_fastapi_endpoints
from app.analysis.source.flask import extract_flask_endpoints
from app.analysis.source.framework import FrameworkType, detect_framework
from app.analysis.source.loader import (
    LoadedSourceFile,
    LoadedSourceTree,
    load_source_from_disk,
    load_source_from_memory,
)
from app.analysis.source.models import (
    AuthState,
    EvidenceCategory,
    EvidenceStrength,
    NormalizedSourceEndpoint,
    NormalizedSourceFile,
    NormalizedSourceParameter,
    NormalizedSourceTree,
    SourceDiagnostic,
    SourceLocation,
    SourceSecurityEvidence,
)
from app.analysis.source.parser import ParsedModule, parse_source_file
from app.analysis.source.secrets import extract_secrets


def normalize_source_tree(loaded: LoadedSourceTree) -> NormalizedSourceTree:
    """Processes loaded source files into a unified, normalized, immutable NormalizedSourceTree."""
    normalized_files: list[NormalizedSourceFile] = []
    all_endpoints: list[NormalizedSourceEndpoint] = []
    all_evidence: list[SourceSecurityEvidence] = []
    all_diagnostics: list[SourceDiagnostic] = list(loaded.diagnostics)

    for loaded_file in loaded.files:
        # 1. Parse Python source into AST
        parsed = parse_source_file(
            content=loaded_file.content,
            file_path=loaded_file.relative_path,
            content_hash=loaded_file.content_hash,
        )
        all_diagnostics.extend(parsed.diagnostics)

        # 2. Detect framework
        framework = detect_framework(parsed)

        # 3. Extract endpoints
        endpoints: list[NormalizedSourceEndpoint] = []
        if framework == FrameworkType.FASTAPI:
            endpoints = extract_fastapi_endpoints(parsed)
        elif framework == FrameworkType.FLASK:
            endpoints = extract_flask_endpoints(parsed)

        # 4. For each endpoint, enrich with function-level security evidence
        enriched_endpoints: list[NormalizedSourceEndpoint] = []
        fn_lookup = {f.name: f for f in parsed.functions}

        for ep in endpoints:
            fn = fn_lookup.get(ep.handler_name)
            if not fn:
                enriched_endpoints.append(ep)
                continue

            path_params = tuple(p.name for p in ep.parameters if p.is_path_param)

            authz, obj_acc, tenant, val, db = extract_function_security_evidence(
                fn=fn,
                file_path=loaded_file.relative_path,
                path_parameters=path_params,
            )

            # Combine authz evidence with tenant evidence
            # (since tenant isolation contributes to authorization)
            combined_authz = list(ep.authz_evidence) + authz + tenant

            # Construct enriched endpoint
            enriched = NormalizedSourceEndpoint(
                method=ep.method,
                path=ep.path,
                raw_path=ep.raw_path,
                handler_name=ep.handler_name,
                file_path=ep.file_path,
                framework=ep.framework,
                location=ep.location,
                parameters=ep.parameters,
                auth_state=ep.auth_state,
                auth_evidence=ep.auth_evidence,
                authz_evidence=tuple(combined_authz),
                object_access_evidence=tuple(obj_acc),
                tenant_evidence=tuple(tenant),
                validation_evidence=tuple(val),
                router_prefix=ep.router_prefix,
            )
            enriched_endpoints.append(enriched)

            # Add endpoint evidence to aggregate
            all_evidence.extend(ep.auth_evidence)
            all_evidence.extend(combined_authz)
            all_evidence.extend(obj_acc)
            all_evidence.extend(val)
            all_evidence.extend(db)

        # 5. Extract module-level secrets and configuration evidence
        secret_evidence = extract_secrets(parsed)
        all_evidence.extend(secret_evidence)

        # Build file-level evidence
        file_evidence = list(secret_evidence)
        for ep in enriched_endpoints:
            file_evidence.extend(ep.auth_evidence)
            file_evidence.extend(ep.authz_evidence)
            file_evidence.extend(ep.object_access_evidence)

        norm_file = NormalizedSourceFile(
            path=loaded_file.relative_path,
            content_hash=loaded_file.content_hash,
            language="python",
            framework=framework.value,
            detected_routes=tuple(f"{ep.method.upper()} {ep.path}" for ep in enriched_endpoints),
            endpoints=tuple(enriched_endpoints),
            evidence=tuple(file_evidence),
            diagnostics=tuple(parsed.diagnostics),
            ast_root=parsed.ast_root,
            provenance=f"file:{loaded_file.relative_path}",
        )
        normalized_files.append(norm_file)
        all_endpoints.extend(enriched_endpoints)

    # Deterministic sorting
    def _endpoint_sort_key(e: NormalizedSourceEndpoint) -> tuple[str, str, str]:
        return (e.path, e.method, e.file_path)

    def _evidence_sort_key(ev: SourceSecurityEvidence) -> tuple[str, str, int, str]:
        file_p = ev.location.file if ev.location else ""
        line_num = ev.location.line if (ev.location and ev.location.line is not None) else 0
        return (ev.category.value, file_p, line_num, ev.message)

    all_endpoints.sort(key=_endpoint_sort_key)
    all_evidence.sort(key=_evidence_sort_key)

    return NormalizedSourceTree(
        files=tuple(normalized_files),
        endpoints=tuple(all_endpoints),
        evidence=tuple(all_evidence),
        diagnostics=tuple(all_diagnostics),
        source_hash=loaded.tree_hash,
        provenance=f"tree:{loaded.root_path}",
    )


__all__ = [
    "AuthState",
    "EvidenceCategory",
    "EvidenceStrength",
    "LoadedSourceFile",
    "LoadedSourceTree",
    "NormalizedSourceEndpoint",
    "NormalizedSourceFile",
    "NormalizedSourceParameter",
    "NormalizedSourceTree",
    "ParsedModule",
    "SourceDiagnostic",
    "SourceLocation",
    "SourceSecurityEvidence",
    "load_source_from_disk",
    "load_source_from_memory",
    "normalize_source_tree",
]
