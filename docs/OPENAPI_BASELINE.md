# OpenAPI Specification Security Analysis Baseline (Phase 2)

## 1. Research Baseline Objective

The primary objective of Phase 2 is to establish a deterministic, evidence-backed OpenAPI specification analysis layer. This layer forms the **specification-only baseline** of the Intelligent API Security Analyzer.

In subsequent phases (Phase 3: Source Code Analysis, Phase 4: Correlation), this baseline will serve as the comparator to empirically answer the core research question:

> *Does correlating OpenAPI specification evidence with source-code implementation evidence improve precision, reduce false positives, and improve explainability compared to specification-only or source-only analysis?*

---

## 2. Ingestion Architecture

```
OpenAPI YAML / JSON
        │
        ▼
[1. Safe Loader] ────────► AST Node Mapping (Line/Col per JSON Pointer)
        │                  SHA-256 Hashing & Size Limit Enforcement
        ▼
[2. Schema Validator] ───► OpenAPI 3.0.x / 3.1.x Validation (openapi-spec-validator)
        │
        ▼
[3. $ref Resolver] ──────► Internal JSON Pointer Traversal & Cycle Detection
        │
        ▼
[4. Normalizer] ─────────► Immutable NormalizedOpenAPI (Engine & Rules Interface)
        │
        ▼
[5. Security Rules] ─────► 5 Deterministic Specification Rules
        │
        ▼
   Findings & Evidence
```

### Supported Versions
- **OpenAPI 3.0.x** (3.0.0 – 3.0.3)
- **OpenAPI 3.1.x** (3.1.0)
- Validated using standard JSON Schema definitions via `openapi-spec-validator`.

### Loader & Security Controls
- **Parser**: Safe YAML parser (`yaml.SafeLoader` with AST node interception) and standard `json`.
- **DoS Prevention**: Hard input document size ceiling (default 10 MB).
- **Integrity**: SHA-256 hash computed immediately on raw text before parsing.
- **Privacy & Storage**: Raw specification text is not unnecessarily persisted in application databases or logged; reproduction and traceability rely on content hashes and normalized evidence.

---

## 3. Reference (`$ref`) Resolution Semantics

Internal references (`$ref`) are resolved using RFC 6901 JSON pointer semantics. The resolver explicitly tracks and categorizes reference resolution outcomes into distinct states:

| Status | Meaning | Resolution Action |
|---|---|---|
| `resolved_internal` | Reference points to a valid internal component | Dereferenced to target dictionary or schema definition. |
| `unresolved_internal` | Reference points to non-existent internal path | Captured as resolution error; surfaced in `NormalizedOpenAPI.unresolved_refs`. |
| `unsupported_external` | Reference points to external URL or file | Logged safely; captured in `NormalizedOpenAPI.unsupported_external_refs`. |
| `circular` | Reference is part of a self-referential cycle | Terminated safely without infinite recursion; schema marked as `schema_type="circular"`. |

Failures are never silently discarded. Recursive schema structures (e.g. tree nodes, linked lists) are detected using a `visited` pointer set.

---

## 4. Normalization Layer (`NormalizedOpenAPI`)

To maintain architectural isolation, security rules never inspect raw YAML/JSON dictionaries directly. All analysis operates upon immutable frozen dataclasses in `app.analysis.context`:

- **`NormalizedOpenAPI`**: Root container containing endpoints, global security schemes, global security requirements, and resolution diagnostics.
- **`NormalizedEndpoint`**: Grouping of operations under a normalized path.
- **`NormalizedOperation`**: Single HTTP operation (`method`, `path`, `parameters`, `effective_security`, `has_explicit_security_override`, `request_body_schema`, `response_schemas`, `location`).
- **`NormalizedParameter`**: Explicit parameter attributes with parsed constraints (`minimum`, `maximum`, `minLength`, `maxLength`, `pattern`, `enum`).
- **`NormalizedSchema`**: Recursive schema tree with property names, types, constraints, and source locations.

### Effective Security Resolution
For every operation, the normalizer computes `effective_security`:
1. If the operation explicitly declares `security: []`, `effective_security` is empty and `has_explicit_security_override = True`.
2. If the operation declares its own security schemes, those schemes become `effective_security`.
3. If the operation omits `security`, it inherits the top-level `global_security`.

---

## 5. Deterministic Security Rules

Phase 2 implements five core specification rules adhering to mandatory architectural corrections:

### `API-AUTH-001`: Potential Missing Authentication Requirement
- **Rule ID**: `API-AUTH-001`
- **Purpose**: Detects operations that have no effective security requirement despite the specification defining security schemes.
- **Mandatory Correction**: Path name patterns (e.g. `/health`, `/login`, `/auth`, `/register`, `/docs`) are **not** authoritative exemptions. Explicit OpenAPI security semantics alone dictate finding generation.
- **Severity / Confidence**: `HIGH` / `0.85` for state-changing operations (`POST`, `PUT`, `DELETE`, `PATCH`); `MEDIUM` / `0.70` for read operations (`GET`, `HEAD`, `OPTIONS`).

### `API-AUTH-002`: Potential Inconsistent Authentication Coverage
- **Rule ID**: `API-AUTH-002`
- **Purpose**: Detects endpoints where authenticated operations and unauthenticated operations exist on the same path.
- **Mandatory Correction**: Sibling differences are reported only when sibling operations provide direct evidence of an intended security boundary. The finding title is strictly qualified: *"Potential Inconsistent Authentication Coverage"*.
- **Severity / Confidence**: `HIGH` / `0.80` for state-changing operations; `MEDIUM` / `0.70` for reads.

### `API-INPUT-001`: Potential Missing Input Constraints
- **Rule ID**: `API-INPUT-001`
- **Purpose**: Detects missing boundary constraints on high-risk, security-relevant parameters:
  1. *Pagination / Batch Limits* (`limit`, `page_size`, `count`): Flagged if missing `maximum`.
  2. *Redirect / Callback URLs* (`redirect_url`, `return_to`, `callback`): Flagged if missing `format: uri`, `pattern`, or `enum`.
  3. *Filesystem Paths* (`file_path`, `file_name`, `dest_dir`): Flagged if missing `pattern`, `maxLength`, or `enum`.
- **Mandatory Correction**: Never requires arbitrary constraints on generic strings; requires well-defined security relevance.
- **Severity / Confidence**: `MEDIUM` / `0.75`.

### `API-DATA-001`: Potential Sensitive-Data Exposure in Response Schema
- **Rule ID**: `API-DATA-001`
- **Purpose**: Inspects properties of 2xx success response schemas for sensitive fields.
- **Mandatory Correction**:
  - *Strong Indicators* (`password`, `secret`, `private_key`, `api_key`, `access_token`, `refresh_token`): Default `HIGH` / `0.85`.
  - *Moderate Indicators* (`credential`, `auth_token`, `ssn`): Default `MEDIUM` / `0.70`.
  - Qualified wording: *"Potential Sensitive-Data Exposure"*, noting that OpenAPI specifies data contracts, not runtime payloads.

### `API-AUTHZ-001`: Potential Broken Object Level Authorization (BOLA/IDOR) Architectural Indicator
- **Rule ID**: `API-AUTHZ-001`
- **Purpose**: Identifies endpoints accepting resource or object identifiers in the URL path (e.g. `/users/{id}`) paired with direct access methods (`GET`, `PUT`, `DELETE`, `PATCH`).
- **Mandatory Correction**: Emitted strictly as an architectural indicator. The presence of bearer authentication does not prove object authorization, nor does the absence of scopes prove exploitability.
- **Severity / Confidence**: `HIGH` / `0.65`.

---

## 6. Finding Provenance & Evidence Model

Every finding generated by the analyzer contains structured `Evidence` objects preserving the origin:

```python
@dataclass(frozen=True)
class Evidence:
    kind: str  # e.g., 'openapi_security', 'openapi_parameter_constraint'
    message: str  # Descriptive rationale with identified tokens
    file: str | None  # File path of specification
    line: int | None  # AST source line
    column: int | None  # AST source column
    source_hash: str | None
    provenance: str | None  # JSON Pointer, e.g. 'spec:/paths/~1users~1{id}/get'
```

This provenance guarantees reproducibility and enables Phase 4 correlation rules to match specification findings with corresponding backend AST routes and handler methods.

---

## 7. Static Specification Limitations & Phase 3 Motivation

Specification-only static analysis has known, fundamental limitations:

1. **Specification Drift**: OpenAPI contracts may not accurately reflect actual backend code behavior (e.g. omitted endpoints, unmodeled middleware filters).
2. **Runtime Context Blindness**: An OpenAPI document cannot prove whether an unauthenticated endpoint is intercepted by an API gateway, or whether object-level authorization is enforced in database queries.
3. **Over-Reporting Risk**: Coarse specification rules risk generating false positives for endpoints intentionally designed to be public or polymorphic.

These limitations demonstrate why Phase 3 (Source Code Ingestion & AST Extraction) and Phase 4 (Correlation Engine) are required to achieve defensible precision and false-positive reduction.
