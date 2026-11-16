# IASA Analyzer Correctness and Evidence Consistency Audit

**Date:** 2026-11-13
**Scope:** Read-only inspection of current source, API contracts, frontend consumers, and existing tests. No scans, database operations, benchmarks, or tests were run for this audit.

## 1. Executive summary

The deterministic analysis path preserves OpenAPI, source, and correlation findings as separate result groups. The browser's empty **Vulnerability Description** for `API-AUTH-001` is a confirmed field-name mismatch: the backend emits the explanation as `rationale`, while Findings Explorer renders only `description`. The rule, serializer, and API response retain the explanation; the UI does not display it in that panel.

Zero correlated endpoints for an OpenAPI-only scan is expected behavior. The matcher has no source handlers to pair with the OpenAPI operations, so it returns no matched pairs and reports the operations as unmatched. A minimal existing fixture pair can test cross-layer matching without creating a scan.

The JSON report and findings API use the same persisted finding arrays. The HTML report intentionally presents category counts and correlated summaries, not full details for spec-only and source-only findings. Separately, correlated-finding serialization drops inherited severity, confidence, and top-level evidence as well as `evidence_pairs`; the current frontend reconstructs some display values from child findings, which may conceal that loss. The dashboard's “Total Vulnerabilities” label also sums all three category counts, including correlated syntheses, so whether it is a unique-vulnerability count is unclear.

No changes were found in the tracked frozen analyzer paths. Key groundedness artifacts and the RAG index matched their recorded hashes during this audit. Existing worktree modifications were present before this report was created and were preserved.

## 2. Finding data flow

1. `backend/app/analysis/rules/openapi/auth_missing.py:8-101` defines `MissingAuthRule` (`API-AUTH-001`). For each OpenAPI operation without effective security requirements, it creates a `Finding` with a “Potential Missing Authentication Requirement” title, severity, confidence, rationale, remediation, and OpenAPI evidence including a JSON-pointer provenance string.
2. `backend/app/analysis/findings.py:11-39` defines `Finding` with `rationale`; it has no `description` field.
3. The normal scan worker in `backend/app/services/analysis_worker.py:60-71` runs OpenAPI loading, validation, normalization, and deterministic rules. It then parses source and runs source rules (`:82-93`), and finally invokes correlation (`:103-119`). The uploaded source is parsed statically; this path does not execute it.
4. `backend/app/repositories/scan.py:46-59` serializes ordinary findings with `title`, `severity`, `confidence`, `rationale`, `remediation`, and `evidence`. It does not rename `rationale` to `description`.
5. `backend/app/schemas/scan.py:42-46` types the three findings collections as dictionaries, so it does not enforce or normalize a formal per-finding description contract. `GET /{scan_id}/findings` returns the stored collections in `backend/app/api/v1/scans.py:346-375`.
6. `frontend/src/types/findings.ts:29-47` allows both optional `rationale` and optional `description`. In `FindingsExplorerScreen.tsx:59-75`, spec/source findings are passed through and correlated findings are mapped with `rationale`, but no description is synthesized. The detail panel at `:469-477` renders only `activeFinding.description`.

## 3. API-AUTH-001 investigation

### Rule behavior

`MissingAuthRule` is a specification-level detector, not proof that a deployed endpoint is reachable without authentication. It skips operations with effective security requirements (`auth_missing.py:28-32`). When it emits a finding:

- State-changing methods (`POST`, `PUT`, `DELETE`, `PATCH`) receive `HIGH` severity and confidence `0.85`; other methods receive `MEDIUM` and `0.70` (`:34-69`).
- The title says **Potential** missing authentication (`:83-90`).
- The rationale explains whether the operation explicitly sets `security: []`, lacks operation coverage despite schemes, or has no declared security scheme/global requirement (`:36-64`).
- Evidence is `kind="openapi_security"`, includes the relevant message, and has `spec:<JSON pointer>` provenance (`:71-81`).
- Remediation tells the user to define and apply a security scheme (`:94-99`).

### Finding and diagnosis

**Confirmed UI defect:** the data has an explanation under `rationale`, but the Vulnerability Description panel reads only `description`. Thus the panel is blank even though title, evidence, and remediation render. The explanation was not lost in rule generation or ordinary finding serialization. This is not evidence that API-AUTH-001 failed to generate a description-like explanation; the model's canonical field is `rationale`.

**Smallest proposed fix:** in Findings Explorer, display `description ?? rationale` (or map rationale into the UI's description slot), and add a component-level regression case with an API-AUTH-001 response containing rationale but no description. Keep `rationale` as the API's analysis explanation and do not change the deterministic rule.

## 4. Endpoint correlation investigation

### Extraction and matching

- OpenAPI route operations are normalized in `backend/app/analysis/openapi/normalizer.py:51+`; supported HTTP methods are enumerated at `:16`.
- `normalize_source_tree` parses uploaded source files into ASTs, detects supported frameworks, extracts routes, and applies path prefixes in `backend/app/analysis/source/__init__.py:29-69`. FastAPI routes are extracted from route decorators (`backend/app/analysis/source/fastapi.py:114-153`); Flask routes and blueprint prefixes are extracted in `backend/app/analysis/source/flask.py:110-147`.
- `backend/app/analysis/correlation/matcher.py:14-25` canonicalizes path parameter names for matching while preserving original paths. `match_endpoints` returns no matches when specification or source routes are absent (`:48-56`). With both sides present it first matches normalized HTTP method plus raw path, then method plus canonical parameter template, then attempts operationId/handler-name disambiguation; ambiguous candidates remain ambiguous, and unmatched specification operations become `NO_MATCH` pairs (`:58+`).
- `backend/app/analysis/correlation/engine.py:42-55` obtains the matched/unmatched sets; `:57-82` applies deterministic correlation rules while preserving the original spec-only and source-only findings.

### Why the OpenAPI-only scan has zero correlated endpoints

At `matcher.py:52-56`, an absent or empty source tree returns an empty matched-pair tuple and all specification operations as unmatched. `metrics.py:85-98` counts exact and parameter-normalized pairs as matched, not unmatched or ambiguous routes. `EndpointCorrelationScreen.tsx:32-52` reads `matched_endpoints` from the results API and displays that list; an empty list therefore produces the empty-state UI. This is the expected meaning of “no source implementation was supplied,” not by itself a matcher failure.

### Smallest safe cross-layer fixture

`backend/tests/test_phase5_api.py:17-39` already defines a valid OpenAPI document with `GET /items` and a harmless FastAPI `@app.get("/items")` handler. The existing scan-flow test submits both at `:49-60`. A focused matcher test can use these exact two fixture contents and assert one `EXACT_MATCH`; the existing API integration test could additionally assert `matched_endpoints_count == 1` and the returned method/path pair. No new scan or database record was created during this audit.

Existing matcher coverage includes exact matching, parameter-name normalization, operationId disambiguation, ambiguous matching, and unmatched spec/source routes (`backend/tests/test_correlation_matcher.py:23-156`). The absent-source branch at `matcher.py:52-56` is not directly asserted by that module. The API scan-flow test retrieves results but currently checks only that the metrics and matched-endpoints fields exist (`test_phase5_api.py:81-87`); it does not assert the expected match.

## 5. Report and screen consistency

| View | Data source and observed behavior |
|---|---|
| Scan summary | `ScanDetailsScreen.tsx:271-277` sums spec-only, source-only, and correlated finding counts and labels the sum “Total Vulnerabilities.” |
| Findings Explorer | Calls `GET /findings`; ordinary stored findings retain rationale/severity/evidence/remediation. Correlated findings are separately mapped, with some values recovered from nested child findings. The description panel only reads `description`. |
| Endpoint Correlation | Calls `GET /results` and displays `matched_endpoints` (`EndpointCorrelationScreen.tsx:32-52`); it does not display unmatched routes from the endpoint list. |
| JSON report | `ReportService.generate_json_report` returns the same persisted metrics, matched endpoints, and three finding arrays (`backend/app/services/report.py:14-52`). The API findings route returns those same stored finding arrays (`scans.py:346-375`). |
| HTML report | Uses the same persisted lists for category counts, but renders detail cards only for correlated findings (`report.py:85-110`, `:115-121`). It does not show spec-only/source-only rationale, evidence, or remediation in the HTML body. |

### Confirmed consistency gaps

- Ordinary finding descriptions are absent from the API model and serializer by design; the UI's optional `description` field does not match the backend's `rationale` field. This is the API-AUTH-001 blank-panel cause.
- `_serialize_correlated_finding` (`backend/app/repositories/scan.py:78-92`) serializes rule/title/state/endpoint/nested findings/rationale/remediation but omits inherited `severity`, `confidence`, and top-level `evidence`, and omits `CorrelatedFinding.evidence_pairs` and `divergence_details` (`backend/app/analysis/correlation/models.py:78-88`). Those fields are therefore unavailable in persisted/API/JSON correlated records. The frontend mapper falls back to a child severity and child evidence (`FindingsExplorerScreen.tsx:61-75`), which is not necessarily equivalent to the correlation's own attributes. This is confirmed field loss; whether a specific screen currently needs every omitted field is a product-contract decision.
- HTML output is a summary for spec-only and source-only categories rather than a full-detail report. Counts are shown, but their underlying evidence and remediation are absent from HTML. Existing tests explicitly check category labels and correlated detail only (`test_phase5_api.py:282-289`), so this appears to be the tested current scope, not an accidental mismatch in the JSON endpoint.

### Potential count ambiguity

`metrics.py:96-98` counts each category independently. The dashboard sums those counts and labels the result “Total Vulnerabilities.” Since correlated findings are synthesized alongside preserved spec-only/source-only findings (`engine.py:48-55`), the sum counts finding records across layers and may count related observations more than once. No canonical deduplication rule was found in the inspected path. Treat “unique vulnerability count” as unproven; clarify the label/definition or add a deduplication contract before describing it as a unique count.

## 6. Confirmed defects

1. **Findings Explorer hides the API-AUTH-001 explanation.** Backend uses `rationale`; the UI reads only `description` in the description panel. See `auth_missing.py:83-99`, `scan.py:46-59`, and `FindingsExplorerScreen.tsx:469-477`.
2. **Correlated finding metadata is dropped during persistence serialization.** The serializer omits inherited severity/confidence/evidence and correlation evidence pairs/divergence details, despite those fields existing on the in-memory `CorrelatedFinding`. See `correlation/models.py:78-88` and `repositories/scan.py:78-92`. The immediate user-visible impact can vary because the UI falls back to child values.
3. **HTML report omits full spec-only/source-only finding details while displaying their counts.** This is a confirmed scope limitation. It is a defect only if HTML is intended to be a complete evidence report; current tests assert the summary-style output.

## 7. Suspected defects or product-contract ambiguities

- The “Total Vulnerabilities” total may be interpreted as unique vulnerabilities although it sums three layer-specific record counts. No verified unique-issue aggregation exists in the inspected UI path.
- The Findings Explorer's correlated severity/evidence fallbacks use the first child finding. If the synthesized correlation has its own severity/evidence or multiple relevant children, the screen may not represent the correlation itself. This follows from the mapping code, but no concrete scan payload was read in this read-only audit, so an observed incorrect display is unverified.
- Endpoint Correlation displays only matched pairs; unmatched and ambiguous operations are represented in metrics/findings but not in that screen's endpoint list. Confirm whether the screen is meant to be a match-only matrix or a full route reconciliation view.

## 8. Missing test coverage and exact proposed cases

No tests were run for this audit. Existing tests inspected include `backend/tests/test_rules_openapi.py`, `backend/tests/test_correlation_matcher.py`, and `backend/tests/test_phase5_api.py`; frontend tests currently cover research presentation, Vite config, auth/redaction, and upload validation, but no Findings Explorer component test was found.

Recommended focused tests:

1. **API-AUTH-001 contract:** analyze an unauthenticated OpenAPI GET and assert title, severity, confidence, rationale, remediation, and evidence provenance; persist/serialize it and assert those same fields reach `GET /findings` and JSON report.
2. **UI description fallback:** render Findings Explorer with a finding that has `rationale` and no `description`; assert rationale appears under Vulnerability Description. Include a separate case where explicit `description` exists and remains preferred.
3. **No-source correlation:** call `match_endpoints(spec_with_GET_items, empty_source_tree)` and assert no matched pairs, the operation is unmatched, and no fabricated source route appears.
4. **Cross-layer API matching:** use existing `SAMPLE_SPEC_YAML` and `SAMPLE_FASTAPI_SOURCE`; assert one exact `/items` GET pair after the scan flow and ensure results/report expose consistent endpoint data.
5. **Correlated metadata serialization:** construct a `CorrelatedFinding` whose own severity/confidence/evidence and evidence pairs differ from its nested child values; assert persistence and API/JSON report preserve the declared contract, or explicitly assert the intended omissions if these are intentionally not part of the public contract.
6. **Report parity and counts:** for a controlled result, compare category arrays/counts between findings API and JSON report; verify HTML either includes each category's detail or labels itself clearly as a summary. Add a test defining whether the dashboard total counts records or distinct vulnerabilities.

## 9. Recommended minimal fixes

1. Render `description ?? rationale` in Findings Explorer; add the UI regression test. No scanner rule change is needed.
2. Decide the public correlated-finding contract, then serialize the required own severity/confidence/evidence and any relevant evidence-pair/divergence metadata. Add a round-trip/API test. Avoid reconstructing correlation metadata from the first child if the in-memory correlation result is authoritative.
3. Add direct assertions for the existing `/items` fixture pair and for an empty source tree. Preserve current matcher behavior: OpenAPI-only scans should remain unmatched rather than be reported as correlated.
4. Decide whether HTML is a summary or a full report. If full, render spec/source detail cards with their evidence and remediation; otherwise label/describe the summary scope.
5. Clarify “Total Vulnerabilities” as a count of finding records, or define deterministic deduplication before claiming a unique vulnerability count.

## 10. Exact files a future fix/test would affect

No application files were modified in this audit. Candidate files, depending on approved scope:

- `frontend/src/components/findings/FindingsExplorerScreen.tsx` — display rationale when description is absent; potentially correct correlated mapping.
- `frontend/src/types/findings.ts` — align finding and correlated-finding types with the chosen API contract.
- `frontend/src/tests/FindingsExplorerScreen.test.tsx` (new) — UI rationale/description rendering coverage.
- `backend/app/repositories/scan.py` — preserve approved correlated metadata during serialization.
- `backend/app/schemas/scan.py` — replace generic dictionaries with explicit response types if the API contract is being formalized.
- `backend/tests/test_rules_openapi.py` — strengthen API-AUTH-001 content/provenance assertions.
- `backend/tests/test_correlation_matcher.py` — empty-source case (or new API integration assertions).
- `backend/tests/test_phase5_api.py` — `/items` endpoint-match assertions, correlated serialization/report parity.
- `backend/app/services/report.py` and possibly `backend/tests/test_phase5_api.py` — only if HTML completeness or clearer summary labeling is approved.
- `frontend/src/components/scan-details/ScanDetailsScreen.tsx` and a frontend test — only if the total count definition changes.

## 11. Git and frozen-artifact preservation

At audit start the branch was `main` tracking `origin/main`. The pre-existing worktree already contained these modified tracked files:

`.env.example`, `.github/workflows/ci.yml`, `.gitignore`, `README.md`, `THREAT_MODEL.md`, `backend/app/core/config.py`, `backend/app/schemas/scan.py`, `backend/app/services/local_ai.py`, `backend/app/services/rag_assistant.py`, `backend/tests/test_config.py`, `backend/tests/test_local_ai.py`, `backend/tests/test_phase5_api.py`, `backend/tests/test_rag_assistant.py`, `frontend/README.md`, `frontend/src/components/new-scan/NewScanScreen.tsx`, `frontend/src/types/findings.ts`, and `frontend/vite.config.ts`.

Pre-existing untracked paths included RAG evaluation/service/test work under `backend/app/evaluation/`, `backend/app/services/`, `backend/tests/`, and `evaluation/rag/`, plus `frontend/src/tests/viteConfig.test.ts`. They were not changed or removed. This report is the only file created by this audit.

`git diff --quiet -- backend/app/analysis evaluation/dataset evaluation/external_dataset evaluation/reports` returned success: no tracked diff in those frozen analyzer/data/report paths. The following recorded hashes were rechecked and matched:

| Artifact | SHA-256 |
|---|---|
| `evaluation/rag/groundedness-v1/cases-review-ready-v1.json` | `b8df7483d84cd9e0d8fa86fb4291ee50f1948ad4f1cc94f6b9efedcf6dedf18` |
| `evaluation/rag/groundedness-v1/candidate-runs/candidate-2026-10-28-targeted-fixes-r2/answers.json` | `655b706267a57e941c2e5f6258a53c971b13705ac6f1bfd75195ac4357f114f9` |
| `evaluation/rag/groundedness-v1/candidate-runs/candidate-2026-10-28-targeted-fixes-r2/REPORT.md` | `26c470b9838fa51753c031b0f0654cf8b7e1caebb13ae851c4bb5c4daa22ed20` |
| `evaluation/rag/groundedness-v1/review-template-r2-candidate-2026-10-28.json` | `e75782e693ac73659b9a97db3792a86e8448ca766dcb500fb26ff4657e39cc5b` |
| `scratch/rag-index-v1.json` | `acf1537324fad31a8452870762342dfb87656f3f0c9ec7c13ec5560ade2291df` |

No database was accessed, no scan or benchmark was run, and no pre-existing files or records were modified. Existing worktree changes remain user-owned and uncommitted.
