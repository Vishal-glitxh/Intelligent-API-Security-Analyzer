# IASA Correlated Finding Serialization Audit

**Date:** 2026-11-15
**Scope:** Read-only source, API, persistence-model, frontend, report, and test inspection. No tests, database queries, scans, migrations, or evaluation runs were performed.

## Executive summary

`CorrelatedFinding` is a `Finding` with additional cross-layer lineage. Its rules populate their own severity, confidence, evidence, correlation state, endpoint, child findings, evidence pairs, and divergence details. The repository serializes only part of that model. The `scan_results.correlated_findings` JSON/JSONB column therefore stores no correlated-level severity, confidence, evidence, evidence pairs, or divergence details. There is no rehydration step that restores them.

This loss is user-visible and affects downstream behavior:

- Findings Explorer falls back to the first nested child severity and evidence when the correlated values are absent. That fallback can disagree with the synthesized correlation. The existing persistence test constructs a `CRITICAL` correlated finding with `HIGH` and `MEDIUM` children, but only asserts the correlated rule ID after retrieval.
- Correlated confidence is omitted and the frontend has no child fallback, so its confidence display is absent.
- The scan assistant receives persisted correlated dictionaries, but its document builder reads only top-level evidence; it does not traverse nested child findings. Missing top-level correlated evidence therefore removes that evidence from assistant retrieval.
- JSON report and Findings Explorer receive the same persisted correlated dictionary and both lack the omitted fields. HTML reports are a narrower summary that renders correlation title/state/endpoint/rationale and no evidence or severity/confidence.

The findings API uses `list[dict[str, Any]]`, so adding optional keys can extend the current response without a schema migration or an immediate Pydantic schema rewrite. Existing JSONB rows may still lack new fields, so any frontend and API contract must remain backward-compatible. Exposing `evidence_pairs` requires an explicit serialization policy: source evidence objects have additional fields, including `extracted_value`, which should not be blindly exposed.

## Current model and construction

`backend/app/analysis/findings.py:36-47` defines base `Finding` fields: rule ID/version, title, severity, confidence, rationale, remediation, and evidence. `backend/app/analysis/correlation/models.py:67-88` defines `CorrelatedEvidencePair` and `CorrelatedFinding`. The latter inherits all base fields and adds correlation state, layer, matched endpoint, nested spec/source findings, evidence pairs, and optional divergence details.

The correlation engine in `backend/app/analysis/correlation/engine.py:43-62` calls each deterministic correlation rule and collects the returned objects; it does not recompute or overwrite their severity/confidence. It preserves the original spec-only and source-only findings (`:75-95`). The correlation rule constructors set correlated-level severity/confidence explicitly:

- Authentication correlation uses mutation-sensitive severity and fixed or corroboration-adjusted confidence (`backend/app/analysis/rules/correlation/auth_correlation.py:96-145`, `:148-191`, `:194-240`).
- Object authorization uses `HIGH` and synthesized confidence `0.85` (`authz_correlation.py:98-144`).
- Surface divergence assigns fixed severity/confidence for zombie and shadow routes (`surface_divergence.py:54-84`, `:127-156`).
- Sensitive-data and input-constraint correlations also assign their own severity/confidence, sometimes derived from a spec finding (`sensitive_data.py:61-89`; `input_constraints.py:57-116`).

Thus severity/confidence are not merely child metadata. Some rules derive them from a child, but the resulting value is a deliberate property of the correlated finding. Other rules assign independent values. Correlated-level evidence is also constructed separately: authentication and authorization rules resolve it from aligned evidence, selected child evidence, or a synthesized fallback (`auth_correlation.py:16-43`; `authz_correlation.py:16-43`). That value need not equal the first child evidence. `evidence_pairs` retain category, correlation state, separate spec/source evidence, and the alignment rationale (`correlation/models.py:67-75`; aligners in `backend/app/analysis/correlation/aligner.py`).

`divergence_details` is sometimes set equal to the rationale, but it is a distinct model field. For surface divergence, it carries concise route mismatch detail (`surface_divergence.py:77-84`, `:149-155`); the model therefore cannot safely assume the field is always redundant.

## End-to-end field-preservation matrix

| Field | In-memory and populated? | Current repository serialization | DB reload / API / JSON report | HTML report | Frontend consumption |
|---|---|---|---|---|---|
| `severity` | Inherited `Finding` field; constructors set it per rule, sometimes based on method or child findings. | **Omitted** by `_serialize_correlated_finding`. | Not stored in this correlated JSON record; `GET /findings` and JSON report pass through the stored dict, so it remains absent. | Not rendered. | Findings Explorer uses `f.severity`, then first spec child, then first source child, then `MEDIUM` (`FindingsExplorerScreen.tsx:143-156`). This can display a child/default severity instead of the correlated rule's severity. |
| `confidence` | Inherited field; constructors set a correlation-specific value, including fixed baselines and confidence adjustments. | **Omitted.** | Not stored or restored; absent from findings API and JSON report. | Not rendered. | Mapper assigns `confidence: f.confidence`; no child fallback. Header only displays it when present (`FindingsExplorerScreen.tsx:45-48`). |
| `evidence` | Inherited field; populated from aligned evidence, child findings, or synthesized fallback depending on rule. | **Omitted** for the correlated object. | Not stored in its own correlated record. Nested children may retain overlapping evidence, but do not guarantee the same evidence or fallback. | Not rendered. | Mapper falls back to first spec child's evidence, then first source child's evidence (`:156`); may substitute a partial or semantically different evidence set. |
| `evidence_pairs` | Correlation-specific field; alignment rules populate pairs; surface divergence may use an empty tuple. | **Omitted.** | Alignment category/state, separate source/spec evidence, and pair rationale are not stored in the correlated record. Child findings and top-level rationale cannot reliably reconstruct the pair. | Not rendered. | No frontend type or view consumes it. |
| `divergence_details` | Correlation-specific optional field; constructors populate it, sometimes with a value distinct from rationale. | **Omitted.** | Not stored or exposed through findings/JSON report. | Not rendered. | No frontend type or view consumes it. |
| `rationale` | Inherited and populated by correlation rules. | Preserved. | Stored, reloaded as JSON, returned by `GET /findings`, included in JSON report. | Rendered in correlated cards. | Mapper preserves it; the previously approved Findings Explorer display fix uses it when `description` is absent. |
| `remediation` | Inherited and populated by correlation rules. | Preserved. | Stored, returned by API and JSON report. | Not rendered in current correlation cards. | Mapper preserves and Findings Explorer renders it. |
| Nested `spec_findings` / `source_findings` | Correlation rules attach relevant child tuples; unmatched-route correlations can intentionally have empty children. | Preserved using `_serialize_finding` recursively. | Stored/reloaded and passed through findings API and JSON report. | Not rendered as child details. | Used only as fallback sources for category/severity/evidence; not displayed as a lineage list. |

## Persistence and API flow

1. `AnalysisWorkerOutput.result` carries a `MultiLayerAnalysisResult` in memory (`backend/app/schemas/worker.py:16-23`). The worker returns it from `execute_analysis_worker`; `ScanService._execute_scan_job` passes successful output to the repository (`backend/app/services/scan_service.py:171-197`).
2. The database model stores `spec_only_findings`, `source_only_findings`, `correlated_findings`, matched endpoints, and metrics as generic JSON with PostgreSQL JSONB variants (`backend/app/db/models.py:63-86`). No relational columns or migration are required to add JSON keys.
3. `ScanRepository.save_worker_output` serializes each finding before creating `ScanResult` (`backend/app/repositories/scan.py:199-217`). `_serialize_finding` preserves ordinary finding severity/confidence/rationale/remediation/evidence (`:46-59`). `_serialize_correlated_finding` instead includes rule ID/version, title, correlation state, matched endpoint, child findings, rationale, and remediation only (`:78-92`).
4. `get_scan_with_result` returns the `ScanResult` ORM row and its decoded JSON values directly; there is no correlated-finding deserializer (`scan.py:148-158`). Data omitted by the writer cannot be restored at this stage.
5. `ScanFindingsResponse.correlated_findings` is `list[dict[str, Any]]` (`backend/app/schemas/scan.py:42-46`). `GET /{scan_id}/findings` returns the stored correlated dictionaries without transformation (`backend/app/api/v1/scans.py:346-375`). `GET /{scan_id}/results` returns only metrics and matched endpoints (`:315-343`).
6. The JSON report returns the stored finding arrays as-is (`backend/app/services/report.py:14-52`, served at `scans.py:442-466`). Thus a report does not recover omitted model fields.

No live database or existing row was inspected, consistent with the read-only preservation constraints. The JSONB structure and current writer were inspected from code and tests only; exact shapes of records written by older application versions remain unverified.

## API, reports, and other consumers

### Findings Explorer and endpoint screen

`FindingsExplorerScreen.tsx:143-157` maps correlated records into the common `Finding` type. It prefers top-level severity/evidence, but the current serializer never supplies them; it then falls back to a single child. The correlated type in `frontend/src/types/findings.ts:49-62` has optional severity and nested findings but does not declare confidence, evidence, evidence pairs, or divergence details. The generic `Finding` interface includes optional confidence/evidence (`:29-47`), which explains why the mapper can consume those keys without modeling their correlated contract explicitly.

The fallback can be misleading. The current API persistence test constructs correlated severity `CRITICAL` and confidence `0.95` while its spec and source children are `HIGH` and `MEDIUM` (`backend/tests/test_phase5_api.py:197-225`). Given the current serializer and UI mapper, that fixture would yield no correlated confidence and would display the first child's `HIGH`, rather than the correlated `CRITICAL`, if rendered in Findings Explorer. The test currently asserts only that the correlated rule ID survives (`:253-266`), so this mismatch is not caught.

`EndpointCorrelationScreen.tsx` consumes `GET /results` matched endpoint records and their match rationale, not correlated finding metadata; it is not a consumer of `evidence_pairs` or divergence details.

### JSON and HTML reports

JSON report and Findings Explorer share the same stored correlated dictionary: there is no divergent serialization logic between them. Both lack the fields omitted by the repository writer. HTML is not equivalent to either data view: `ReportService.generate_html_report` renders correlated rule ID/title/state, matched endpoint, and rationale (`backend/app/services/report.py:91-109`) but not correlated severity, confidence, evidence, remediation, pairs, or children. It is a summary rendering and should not be described as a full correlated-evidence export.

### Assistant retrieval

The scan assistant route passes persisted correlated finding dictionaries to `answer_scan_question` (`backend/app/api/v1/scans.py:399-407`). `rag_assistant._make_documents` builds evidence references from the finding's top-level `evidence` list (`backend/app/services/rag_assistant.py:238-283`); it does not read `spec_findings`, `source_findings`, or `evidence_pairs` when building each cross-layer document. Because correlated-level evidence is omitted by persistence, assistant retrieval receives the title/rationale/remediation and endpoint but no top-level correlated evidence passages. Nested child evidence remains available only in the dictionaries, not consumed by this builder.

## Confirmed defects and risks

### Confirmed

1. **Correlated severity, confidence, and evidence are dropped at persistence.** These fields exist on the in-memory model and are populated by rule constructors, but `_serialize_correlated_finding` omits them. The result is a stored/API/report representation that cannot faithfully reproduce the original correlation finding.
2. **Findings Explorer substitutes child severity/evidence.** The mapper explicitly falls back to the first child when top-level fields are absent. The existing API test fixture demonstrates a correlated severity distinct from child severities; the current serialized response cannot preserve that own value.
3. **Correlation alignment provenance is dropped.** `evidence_pairs` with per-side evidence/state/rationale and `divergence_details` are not serialized. The exact pair data cannot be recreated from a scalar rationale and nested child findings in all cases.
4. **JSON API/report and assistant do not receive correlated evidence.** API/report omission follows from the stored dictionary; the assistant specifically reads only top-level evidence.

### Potential risks / product decisions

- The model makes these fields available, but no explicit public API documentation or typed response schema found in the inspected path states which correlation-only internals are intentionally private. Product approval is needed before exposing all evidence-pair metadata.
- `SourceSecurityEvidence` includes `extracted_value`, symbol, endpoint, and rationale (`backend/app/analysis/context.py:142-156`). A future serializer must choose an explicit safe subset; generic dataclass serialization could reveal source literals or internal details that current finding evidence serialization does not include.
- Existing persisted rows may have only the older reduced dictionary. No database query was made, so their count and exact contents are unknown. Additive optional fields and frontend fallbacks are needed for compatibility.
- HTML's summary-only behavior is an existing output limitation rather than a persistence defect; whether to expand it is a separate product decision.

## Backward compatibility

- Extending each correlated-finding JSON object with additive keys is compatible with the current `list[dict[str, Any]]` response schema (`scan.py:42-46`) and JSON report's untyped dictionary payload. It does not require changing the relational schema or adding an Alembic migration because the column is JSON/JSONB.
- Existing stored records will not acquire the new keys retroactively. The frontend must continue to accept absent values and should prefer a correlated field only when supplied; child fallback may remain as a legacy fallback but should not override a present correlated value.
- A future explicit Pydantic response model would improve contract documentation and validation, but every newly added field should be optional/defaulted while legacy JSON rows exist. Whether to introduce that schema now is not required for a narrow additive serializer fix.
- JSON report will automatically carry additional persisted keys. HTML will remain unchanged unless separately approved and implemented.

## Missing test coverage and proposed round-trip tests

Existing evidence inspected:

- `backend/tests/test_correlation_preservation.py:79-90` checks in-memory correlated lineage and child identity, not serialization.
- `backend/tests/test_rules_correlation.py` checks rule-level state/severity/confidence construction, but not persistence/API round-trip.
- `backend/tests/test_phase5_api.py:185-290` persists a fake correlated finding and checks counts/rule IDs across findings and report endpoints. It does not assert correlated own severity/confidence/evidence, pairs, divergence details, or parity of complete object payloads.
- No frontend test currently covers rendering a correlated finding whose own severity/evidence differ from its nested children.

Recommended focused test, without running it as part of this audit:

1. Construct a correlated finding with own severity `CRITICAL`, confidence `0.95`, a top-level evidence item that differs from both children, one pair containing distinct spec and source evidence/state/rationale, and a divergence detail distinct from its rationale. Give nested child findings different severities/evidence.
2. Pass it through `ScanRepository.save_worker_output` using the verified disposable test database fixture; fetch it through `GET /findings` and JSON report. Assert every approved field survives with exact values and JSON-safe enum/location representations. Do not use the development database.
3. Assert the frontend mapper prefers correlated severity/evidence/confidence when present, and uses documented compatibility fallback only when fields are absent.
4. Add a legacy stored-dictionary case with no new keys to prove API/frontend compatibility.
5. If evidence pairs are public, test safe serialization of both `Evidence` and `SourceSecurityEvidence`, and explicitly assert that `extracted_value` is excluded or redacted unless the approved contract says otherwise.
6. Keep HTML expectations separate: test the current summary contract unless a distinct HTML completeness change is approved.

## Minimal implementation recommendation

1. Obtain product approval for the public subset. The low-risk correctness baseline is to preserve correlated `severity`, `confidence`, and top-level `evidence`, because they are required model fields and already affect UI/assistant behavior. Decide separately whether to expose `evidence_pairs` and `divergence_details`; if exposed, serialize them with an explicit allowlist and safe source-evidence representation.
2. Extend `_serialize_correlated_finding` in `backend/app/repositories/scan.py` with the approved fields, reusing `_serialize_evidence` only for base `Evidence`. Do not use generic object serialization for `SourceSecurityEvidence`.
3. Update `CorrelatedFinding` in `frontend/src/types/findings.ts` with optional fields matching the approved response shape. Keep legacy records valid.
4. Update `FindingsExplorerScreen.tsx` to consume correlation-level fields directly; only fall back to nested children when the top-level fields are absent, for old rows.
5. Add repository/API round-trip coverage in `backend/tests/test_phase5_api.py` or a focused repository test, plus frontend behavior coverage. No scanner-rule changes, frozen analyzer changes, relational migration, or benchmark updates are indicated.

## Exact files likely to change after approval

Minimal approved subset:

- `backend/app/repositories/scan.py` — correlated-finding serialization.
- `frontend/src/types/findings.ts` — optional correlated payload fields.
- `frontend/src/components/findings/FindingsExplorerScreen.tsx` — prefer own correlation metadata while retaining legacy fallback.
- `backend/tests/test_phase5_api.py` or a new focused repository test — persisted/API/JSON-report round-trip assertions.
- A frontend test file — correlated-field priority and legacy fallback.

Only if explicitly approved:

- `backend/app/schemas/scan.py` — typed Pydantic correlated response schema; not necessary for additive keys under the current dictionary response.
- `backend/app/services/report.py` and report tests — if HTML should display full correlated evidence/metadata.
- No database model or Alembic migration is currently required for additive JSONB keys.

## Decisions requiring product approval

1. Which correlated fields are public: only severity/confidence/evidence, or also evidence pairs and divergence details?
2. If evidence pairs are exposed, which `SourceSecurityEvidence` fields are safe for API/report output, especially `extracted_value`?
3. Should Findings Explorer continue a legacy child fallback when correlation-level fields are absent, or display an explicit unavailable state for old records?
4. Is HTML intentionally a summary, or must it become a complete evidence report?
5. Should a Pydantic response schema be introduced now, or should this remain a narrow additive dictionary contract until legacy rows can be migrated/versioned?

## Git and artifact preservation

Before the report was created, Git reported branch `main` tracking `origin/main`, with pre-existing dirty/untracked work. Among the inspected paths, `backend/app/schemas/scan.py`, `frontend/src/types/findings.ts`, `frontend/src/components/findings/FindingsExplorerScreen.tsx`, and `backend/tests/test_phase5_api.py` already had user changes; these changes were read and preserved. The correlation model/engine, repository, API routes, report service, database model, correlation/scan-detail components, and correlation preservation tests had no pre-existing tracked diff. The report path did not exist before this audit.

No application or test files were modified. No database, scans, Docker resources, or frozen artifacts were accessed for writes. This report is the sole file created by this audit; the existing dirty worktree and untracked files remain untouched. No tests were run.
