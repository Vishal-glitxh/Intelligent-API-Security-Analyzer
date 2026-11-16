# IASA Automated Testing & Engineering Assessment

**Assessment date:** 2026-11-13  
**Repository:** `/Users/vishalsuhas/Desktop/Intelligent API Security Analyzer`  
**Branch / HEAD:** `main` / `abd385b`  
**Scope:** Read-only review plus local checks that did not require a database or service mutation. No source, configuration, benchmark, or review artifacts were changed for this assessment. This report is the only new repository file.

## Executive summary

The repository contains a mature deterministic analysis pipeline, an authenticated FastAPI service, a React analyst workstation, and an optional local Ollama/RAG explanation layer. The frozen analyzer under `backend/app/analysis/` and historical scanner benchmark inputs/reports are unchanged in the working tree. Scanner findings are produced deterministically; the AI assistant is a separate explanatory layer and does not determine scan findings.

Checks that did not need PostgreSQL passed: Ruff, Ruff formatting, strict MyPy, Bandit medium/high severity, dependency audit (with the local-project caveat below), frontend tests/lint/build, Compose configuration parsing, and `git diff --check`. Frontend tests passed **14/14**. Current backend pytest and coverage results are **not available**: this environment had no verified disposable PostgreSQL test database, and the test guard correctly refuses to run without one. The healthy PostgreSQL container found during preflight belongs to the existing demo project and was not used. No current full-suite result should be inferred from older README records.

The principal security concern for a local demo is that Vite is configured with `host: true` while the Compose development API defaults to authentication bypass enabled. If the Vite development server is reachable from another machine on the network, its `/api` proxy can expose the development API path without the token flow expected by users. This was identified from configuration; no remote/LAN access attempt was made. Bind Vite to loopback by default or make network exposure an explicit, protected opt-in before distributing a demo.

**Assessment:** suitable for continued single-process local development and demonstration after the Vite binding concern is resolved or the server is otherwise strictly loopback-only. **Not approved for production or multi-worker/multi-replica deployment.** Groundedness evidence is small and versioned; it does not establish general RAG answer quality.

## 1. Repository and environment

### Working tree at assessment start

- Branch `main`, HEAD `abd385b`.
- 16 tracked files were modified before this assessment: `.env.example`, `.github/workflows/ci.yml`, `.gitignore`, `README.md`, `THREAT_MODEL.md`, backend config/schema/local-AI/RAG services and related tests, plus frontend README, New Scan screen, and findings types.
- 15 untracked path entries were present in `git status --short`; these contain the new RAG evaluation/index implementation, tests, evaluation artifacts, and review materials. They are pre-existing work and were preserved.
- The requested report path did not exist before this task.
- No database connection or mutation occurred. `DATABASE_URL` and `TEST_DATABASE_URL` were unset in the shell.

### Test-database safety

`backend/tests/conftest.py` is an untracked test guard. Its `pytest_configure` requires `TEST_DATABASE_URL`, parses it as PostgreSQL, requires a database name ending in `_test` or `_testing`, and sets the application database URL before test modules load. The guard is designed to fail closed before persistence tests can import application modules. No dedicated disposable PostgreSQL service/database was available. The existing demo PostgreSQL service was deliberately not used.

Environment observed: Python 3.14.6 in `.venv`; Docker context `desktop-linux`, Compose v5.6.1. At preflight, the old demo API container was exited and the demo PostgreSQL container was healthy and loopback-published. No API runtime test was attempted.

## 2. Architecture and implementation map

| Area | Main implementation locations | Assessment |
|---|---|---|
| API startup and routing | `backend/app/main.py`, `backend/app/api/router.py`, `backend/app/api/v1/scans.py`, `backend/app/api/v1/ai.py` | FastAPI app with liveness/readiness endpoints, auth dependencies, scans, reports, and optional assistant routes. |
| Configuration and security | `backend/app/core/config.py`, `backend/app/core/security.py` | Supported environment labels are fail-closed; production rejects development auth/secrets/database defaults. Token mapping, tenant access checks, and bounded rate-limit buckets are implemented. |
| Multipart and admission | `backend/app/middleware/upload_body_limit.py`, `backend/app/services/upload_admission.py`, `backend/app/api/v1/scans.py` | Cumulative request-body accounting and timeout precede Starlette multipart parsing; admission is process-local. Per-file reads are bounded after parsing. Starlette may spool multipart parts before application-level file-size checks, which remains a documented resource-bound limitation. |
| Scan lifecycle | `backend/app/services/scan_service.py`, `backend/app/services/analysis_worker.py`, `backend/app/jobs/runner.py`, `backend/app/services/archive.py` | Scan validation, workspace/archive handling, subprocess execution, worker timeout, and sanitized failure persistence are separated from HTTP route code. Startup recovery marks interrupted work; recovery is not coordinated across multiple API instances. |
| Persistence | `backend/app/db/models.py`, `backend/app/db/session.py`, `backend/app/repositories/scan.py`, `backend/alembic/versions/` | SQLAlchemy/PostgreSQL persistence and three migrations cover audit records, scans/results, and client identity. Migration checks were not run in this assessment because there was no disposable database. |
| OpenAPI pipeline | `backend/app/services/specification_guard.py`, `backend/app/analysis/openapi/{loader,validator,resolver,normalizer}.py` | Guard rejects external references and bounds YAML composition before frozen loader/validator execution; OpenAPI validation remains strict. |
| Source analysis | `backend/app/analysis/source/` | Static Python parsing and framework extractors; uploaded code is not imported or executed. The analysis package is a frozen research baseline and has no working-tree diff. |
| Rules and correlation | `backend/app/analysis/rules/`, `backend/app/analysis/engine.py`, `backend/app/analysis/correlation/` | Deterministic finding rules and separate endpoint/evidence correlation. Findings retain layer provenance; correlated observations do not replace the original spec/source findings. |
| Reports | `backend/app/services/report.py` | JSON and standalone HTML reports; escaping/CSP safeguards are documented. Frontend report previews are sandboxed. |
| Local AI and RAG | `backend/app/services/local_ai.py`, `backend/app/services/rag_index.py`, `backend/app/services/rag_assistant.py`, `backend/app/evaluation/rag_*.py` | Optional local Ollama embeddings/generation, versioned local index, hybrid retrieval, citation validation, safe fallback, and separately versioned research protocols. Local AI outage does not block deterministic scans. |
| Frontend | `frontend/src/App.tsx`, `frontend/src/services/api.ts`, `frontend/src/context/AuthContext.tsx`, `frontend/src/screens/`, `frontend/src/components/` | React/TypeScript workstation with dashboard, assessment, scan details, findings, correlation, reports, and research views. API token is entered through Connect API and held in session storage. |
| Deployment | `docker-compose.yml`, `Dockerfile`, `.env.example`, `.github/workflows/ci.yml` | Compose is documented as local-development-only. API and PostgreSQL published ports are loopback-bound in Compose. Production/multiple replicas remain out of scope. |

### Main scan request path

Authenticated `POST /api/v1/scans` → request body limit middleware → route auth/dependency → process-local admission reservation → explicit multipart parsing and bounded file reads → spec guard/validation and scan record/workspace → isolated worker process → deterministic analysis/correlation → persisted results → ownership-protected findings/report routes. The frontend calls the same API through Vite’s `/api` proxy during development.

## 3. Checks executed in this assessment

No backend test, migration, runtime scan, historical benchmark, Ollama generation, or Docker image build was run.

| Check | Command / method | Result |
|---|---|---|
| Ruff | `.venv/bin/ruff check .` | PASS — all checks passed. |
| Ruff formatting | `.venv/bin/ruff format --check .` with a temporary cache directory | PASS — 168 files already formatted. |
| Strict MyPy | `.venv/bin/mypy backend --cache-dir=<temporary path>` | PASS — no issues in 143 source files. |
| Bandit medium/high | `.venv/bin/bandit -r backend/app -ll -q` | PASS — no medium/high findings. |
| Bandit all severities | `.venv/bin/bandit -r backend/app -q` | ATTENTION — 10 Low, 0 Medium, 0 High. Details below. |
| Dependency audit | `.venv/bin/pip-audit` | PASS for audited distributions — no known vulnerabilities found. The local project package was not published on PyPI and therefore was not audited by this command. |
| Frontend tests | `npm test -- --reporter=verbose` in `frontend/` | PASS — 14 tests in 3 files. |
| Frontend lint | `npm run lint` in `frontend/` | PASS — project script uses Oxlint. ESLint is not configured as the active script. |
| Frontend production build | `npm run build -- --outDir <temporary-output>` in an isolated temporary copy | PASS — TypeScript build and Vite production build completed; 2,498 modules transformed. The first attempt passed unsupported Vite `--cacheDir` and failed at invocation; retry with an isolated config/cache succeeded. No repository build output/cache was overwritten. |
| Compose syntax | `docker compose config --quiet` | PASS — configuration parsed. This is not container startup evidence. |
| Diff whitespace | `git diff --check` | PASS. |
| Backend pytest/coverage | Not run | BLOCKED — no verified disposable PostgreSQL test target. No coverage percentage was produced. |
| Alembic upgrade/check | Not run | BLOCKED — no disposable DB; no development/demo DB access permitted. |
| Docker API runtime/E2E | Not run | NOT VERIFIED — current demo API container was exited; no service was started. |
| Historical benchmarks / live RAG | Not run | Intentionally excluded; no frozen outputs were regenerated. |

### Low-severity Bandit triage

The 10 low findings are static-pattern matches, not evidence of a confirmed exploitable vulnerability:

- `B105` on a `SECRET` classification enum in `backend/app/analysis/context.py` and a deliberately empty token-kind sentinel in `backend/app/analysis/source/secrets.py`.
- `B106` on `env_config` and `placeholder` classification labels in `backend/app/analysis/source/secrets.py`.
- `B105` on development-only sentinel values in `backend/app/core/config.py`; configuration validation rejects these in production.
- Three `B101` findings on assertions after input validation in the new groundedness v2 evaluator (`backend/app/evaluation/rag_groundedness_v2.py`). These are low-severity robustness/style findings; replacing assertions with explicit validation would make behavior independent of Python optimization flags.
- `B311` on seeded `random.Random` in `backend/app/evaluation/statistics.py`, used for reproducible bootstrap sampling rather than security-sensitive randomness.

No finding was suppressed or edited. Medium/high Bandit reported zero.

## 4. Test baseline and evidence boundaries

### Current versus historical results

- **Current backend result:** not run; no current test count or coverage is claimed.
- README records a 2026-10-29 working-tree run of 401 backend tests with 86% coverage using a disposable PostgreSQL 18 instance on tmpfs. It is historical and does not automatically cover all changes present on 2026-11-13.
- README also records frontend 14 tests, lint, and build; this assessment independently reran those frontend checks successfully.
- README’s 2026-10-28 isolated Compose smoke test verified migration, liveness/readiness, authenticated scan, findings/report retrieval, and cross-tenant denial. It used Ollama disabled and predates the latest RAG retrieval guard. It is historical runtime evidence, not proof of the current image or current API runtime.
- CI configuration provisions PostgreSQL and invokes quality gates, but CI was not run or inspected as a live job in this assessment.

### Test quality gaps

- `frontend/src/tests/uploadValidation.test.ts` tests a locally defined helper rather than importing the production upload/form implementation. It does not prove that browser component validation and actual submission agree.
- `frontend/src/tests/authAndRedaction.test.ts` similarly uses a local header helper instead of asserting the production API/auth path. Add component/API integration coverage before treating auth UI behavior as regression-proven.
- No current PostgreSQL-backed test results, migration consistency, scan lifecycle smoke test, or tenant-isolation smoke test were produced here.
- Existing historical scanner benchmarks must remain separate from RAG quality evaluation. Do not infer current groundedness from finding determinism, citation-ID validity, or retrieval scores.

## 5. Research and frozen-artifact integrity

The following tracked protected areas have no current diff: `backend/app/analysis/`, `evaluation/dataset/`, `evaluation/external_dataset/`, and `evaluation/reports/`. No historical benchmark was run, and none of those outputs were rewritten.

The separate Connexion contract-assisted protocol is not a replacement for the historical `SOURCE_ONLY` independence rule. The historical source-only limitations and Connexion fixture-conformance scope remain distinct.

Recorded local artifact hashes verified during this assessment:

| Artifact | SHA-256 |
|---|---|
| Groundedness v1 review-ready manifest | `b8df7483d84cd9e0d8fa86fb4291ee50f1948ad4f1cc94f6b9efedcf6dedf18` |
| Immutable r2 answers | `655b706267a57e941c2e5f6258a53c971b13705ac6f1bfd75195ac4357f114f9` |
| Immutable r2 report | `26c470b9838fa51753c031b0f0654cf8b7e1caebb13ae851c4bb5c4daa22ed20` |
| Groundedness v2 review template | `1e0f498c44507da64921058c6164e2bece914b8761ea38a6442cabd70aa9670e` |
| Groundedness v2 metrics | `ee213e4952f6a963fea37cdb0f9c70fb304e83163fb24725c9d95bd76cb0628e` |
| Current local RAG index | `acf1537324fad31a8452870762342dfb87656f3f0c9ec7c13ec5560ade2291df` |
| Precision v1 baseline output | `0dd1e14567caac1a637031b97842e6570c6c3a3c8e0059ca6aeb1764fd0d62e2` |
| Precision v1 candidate output | `7fce07047d5299b0ed28ee44d7015eee7cc37828c314cbf281ab3dec9ced803a` |
| Precision v1 ranking experiment | `c6448018469408a79512bdafcb7a64eae65e9adb9348e7f0dc9706a6e61103c0` |

The v2 review is a separate six-case answer-hash-bound human review; it reports manifest agreement 6/6 and reviewer agreement 5/6. The original v1 provenance checkpoint remains unavailable and is not replaced. The v1 process remains pending/unscoreable under its original Case 5 conflict. The six-case sample is descriptive, not a general quality estimate or release approval.

Recorded RAG precision experiment evidence on 17 queries reports Recall@5 0.941 and macro Precision@5 0.188 for the baseline; a provisional semantic threshold reduced returned false-positive sources but did not improve fixed-k macro Precision@5 and still missed a relevant source. These small, model/index-specific results are a quality warning, not broad performance evidence. No evaluation was rerun here.

## 6. Findings register

Severity describes the engineering concern. A verification gap is not automatically a confirmed runtime defect.

| ID / priority | Finding and evidence | Impact / status | Minimum next action |
|---|---|---|---|
| F-01 / P1 | Vite uses `server.host: true` in `frontend/vite.config.ts:11-22`; Compose defaults to `ENVIRONMENT=development` and `LOCAL_DEV_AUTH_BYPASS=true` in `docker-compose.yml:26-35`, and Vite proxies `/api` to the API. | Confirmed configuration combination; exposure requires Vite to be reachable from another machine. Could permit unauthenticated use of the development API from that network. No network exploitation was tested. | Bind Vite to `127.0.0.1` by default. If LAN access is a deliberate feature, require explicit opt-in plus token auth and verify no bypass. Add a host-binding check to the demo runbook. |
| F-02 / P1 (deployment blocker) | Rate limiting/admission are in-process (`backend/app/core/security.py`, `backend/app/services/upload_admission.py`); startup recovery runs per API process (`backend/app/main.py`); job workspaces/worker execution are local. README and threat model document single-process support only. | Multi-worker/multi-replica operation can have independent limits and competing recovery/ownership behavior. It is explicitly unsupported, not a defect in the documented single-process demo. | Keep production/multi-replica NO-GO. Before enabling it, design shared admission/rate-limit coordination, durable job leases/ownership, safe recovery, and multi-instance failure tests as one architecture change. |
| F-03 / P2 (verification blocker) | Backend tests require a disposable PostgreSQL target via `backend/tests/conftest.py`; no such target was available. | Current backend regressions, coverage, migration upgrade, and migration drift are unknown. Do not use the extant demo database. | Provision a new tmpfs PostgreSQL test container/database and test-only user using the README’s documented procedure; verify target name/port before running pytest and Alembic. |
| F-04 / P2 | Recorded 17-query RAG protocol has macro Precision@5 0.188 and includes false-positive retrievals; the threshold experiment still misses a relevant source. | Retrieval quality is limited on a small labeled sample. This does not establish generated-answer groundedness. | Expand independently reviewed query/source labels and negative controls; keep runs versioned and separate. Do not tune on the six groundedness cases alone. |
| F-05 / P2 | The immutable r2 answer review assesses the 2026-10-28 candidate, while current local AI/retrieval code has later uncommitted changes. | Current code’s live generated answers have not been evaluated; historical r2 review cannot be treated as current-code evidence. | Once the prompt/retrieval change set is frozen and approved, produce a new separately named candidate once and obtain answer-bound human review. Keep release decision pending until then. |
| F-06 / P2 | Frontend upload/auth tests duplicate helper logic rather than exercising production components/API integration. | Test pass does not demonstrate the actual browser upload/auth journey. | Refactor only test seams needed to exercise production validation/header code or add component tests; then cover one authenticated browser/API flow. |
| F-07 / P3 | Ten Bandit low-severity findings remain; medium/high check is clean. | Mostly labels/sentinels and reproducibility assertion/randomness patterns; low immediate risk. | Triage each finding; replace evaluator asserts with explicit errors where useful. Do not suppress without rationale. |
| F-08 / P3 | `docs/release/RC1_REPORT.md` describes a historical October 13 GO, while current README/threat model state that production and multi-replica deployment are unsupported. | A reader may mistake the old RC1 snapshot for current approval. It is dated and describes a different checkpoint. | Keep the historical report immutable; add a conspicuous current-status pointer in the main release index/README if the report is used for submission. |
| F-09 / P3 | README’s verification instructions are dated; they do not establish checks on today’s working tree, and there is no configured coverage threshold in `pyproject.toml`. | Coverage numbers may be mistaken for a permanent guarantee. | Keep run dates beside results and set a coverage target only after deciding what code/scope it applies to. |

**Priority counts:** P0: 0; P1: 2; P2: 4; P3: 3. P1 items include one conditional local-network security exposure and one explicit deployment restriction. No confirmed critical/high exploitable vulnerability was demonstrated by checks in this assessment.

## 7. Recommended roadmap

### P0 — Critical correctness/security

No new P0 defect was confirmed in this assessment. Preserve the frozen deterministic analyzer and require verified disposable persistence infrastructure for backend regression runs.

### P1 — Security and supported operating boundary

1. **Constrain local frontend exposure.** Objective: make the default developer workstation loopback-only. Location: `frontend/vite.config.ts`, `frontend/package.json`, `README.md`, possibly `.env.example`. Dependency: decide whether non-loopback Vite access is intended. Change: default host to `127.0.0.1`; if explicit LAN use is retained, document it and require API token auth. Acceptance: listener binds only loopback in default mode; development proxy does not expose bypassed API to a LAN client. Tests: config assertion plus a local-only smoke check and auth negative test. Risk: breaks workflows that intentionally open Vite to another device; keep that behavior opt-in.
2. **Maintain single-process/single-replica limitation.** Objective: avoid unsupported deployment assumptions. Location: `backend/app/main.py`, `backend/app/core/security.py`, `backend/app/services/upload_admission.py`, scan worker/recovery modules, `THREAT_MODEL.md`, deployment docs. Dependency: production architecture authorization. Change: no partial distributed job patch; design shared coordination and durable ownership together. Acceptance: defined lease/recovery semantics, cross-instance limits, worker isolation, and failure/concurrency tests before deployment claim. Risk: broad architecture; defer unless production deployment is explicitly selected.
3. **Restore current PostgreSQL-backed evidence.** Objective: establish current correctness and migrations. Location: `backend/tests/conftest.py`, test suites, Alembic. Dependency: disposable PostgreSQL with tmpfs and isolated credentials. Acceptance: full pytest+coverage, upgrade and consistency check pass without touching development/demo data. Tests: documented README sequence plus target verification before test imports.

### P2 — Analyzer evidence and assistant quality

1. **Evaluate RAG precision and groundedness separately.** Location: `backend/app/services/rag_assistant.py`, `backend/app/services/local_ai.py`, `backend/app/evaluation/rag_protocol_v2.py`, `backend/app/evaluation/rag_groundedness_v2.py`, `evaluation/rag/`. Dependency: freeze current candidate code and reviewer process. Acceptance: fresh versioned artifact, complete source/answer hashes, human claim-to-evidence review, negative controls, no unsupported answer accepted; historical runs remain byte-identical. Risks: six cases and 17 retrieval queries are too small for broad claims; never adapt scanner findings or labels to improve metrics.
2. **Strengthen frontend behavior tests.** Location: `frontend/src/tests/`, `frontend/src/components/new-scan/`, `frontend/src/services/api.ts`, `frontend/src/context/AuthContext.tsx`. Dependency: choose test utilities already in project. Acceptance: tests exercise actual production validators/request construction and demonstrate successful/failed selection/auth flows; no duplicated shadow implementation. Risk: browser automation and native chooser limitations; distinguish tool constraints from UI defects.
3. **Keep Connexion research modes separate.** Location: `backend/app/analysis/source/connexion.py`, evaluation runner/protocol and docs. Dependency: independent ground truth for contract-to-handler mapping. Acceptance: `SOURCE_ONLY` never receives contract route labels; contract-assisted results use a separate versioned protocol and fixtures. Risk: insufficient independent labels can create misleading metrics.

### P3 — Maintainability/documentation

1. Triage Bandit low findings and explicitly replace evaluator assertions if optimized Python could remove needed checks.
2. Clarify the active release status without rewriting historical RC1 reports.
3. Keep test/coverage claims dated; choose a meaningful coverage threshold before introducing one.

### P4 — Production operations

Before production: shared job queue/ownership, cross-replica admission and rate limits, hardened secret management, TLS/reverse proxy, resource quotas, durable backups, telemetry/audit retention, incident/recovery runbooks, and integration tests across supported deployment topology. Keep one API process and one replica until these gates pass. Ollama remains optional and should be network-restricted; local inference does not itself guarantee privacy if the Ollama service is exposed.

## 8. Minimum next verification sequence

1. Address or explicitly contain the Vite binding risk before sharing the demo on a network.
2. Start a newly created disposable PostgreSQL test container on tmpfs with a test-only user and a database ending `_test`; verify `TEST_DATABASE_URL` target before pytest starts.
3. Run `uv run alembic upgrade head`, `uv run pytest -v --cov=backend/app --cov-report=term-missing`, `uv run alembic check`, Ruff, formatting, strict MyPy, Bandit, and pip-audit. Do not use the development/demo DB.
4. Run frontend tests/lint/build from the final tree, then an isolated current-image scan/findings/report/auth smoke test if a current runtime claim is needed.
5. Keep historical scanner and RAG artifacts unchanged. If evaluating current RAG generation, write a separately versioned artifact and leave human judgments pending until independently recorded.

## 9. Remaining limitations

- No backend pytest suite, coverage, migration check, current API runtime, or end-to-end browser workflow was executed during this assessment.
- No Docker image build, local Ollama availability check, or live generation was performed.
- Dependency audit excludes the unpublished local project package.
- Bandit reports 10 low findings; medium/high checks are clean.
- Retrieval and groundedness results are limited, version-specific research samples and do not provide production assurance.
- Multi-worker/multi-replica deployment remains unsupported and unverified. Do not interpret this report as production release approval.
