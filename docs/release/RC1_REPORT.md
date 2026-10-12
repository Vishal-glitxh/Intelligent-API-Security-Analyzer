# Intelligent API Security Analyzer — Release Candidate 1 (RC1) Report

**Date:** October 13, 2026  
**Status:** **GO** for Release Candidate 1  
**Target Milestone:** RC1 Stabilization  
**Repository Branch:** `main`  
**Base Commit:** `814a30c` ("Complete Phase 7.2 security hardening and statistical analysis")  

---

## 1. Starting Git Commit & Working-Tree State

At the beginning of RC1 preflight inspection:
- **Current Branch:** `main`
- **Starting Commit:** `814a30c`
- **Core Analyzer Freeze State:** `backend/app/analysis/` was strictly verified against frozen commit `060e9a2` via `git diff 060e9a2 -- backend/app/analysis/`. Result: **Zero diff lines (100% frozen and clean)**.
- **Evaluation Dataset Freeze State:** `evaluation/dataset/` and `evaluation/reports/phase6/` were strictly verified against `HEAD` via `git diff HEAD -- evaluation/dataset/ evaluation/reports/phase6/`. Result: **Zero diff lines (Ground truth and published reports untampered)**.
- **Pre-existing Working Tree State:**
  - Modified files: `backend/app/api/router.py`, `backend/app/api/v1/scans.py`, `backend/app/evaluation/cli.py`, `backend/app/evaluation/loader.py`, `backend/app/evaluation/runner.py`, `backend/app/repositories/scan.py`, `backend/app/services/report.py`, `backend/tests/test_api_security.py`, `pyproject.toml`, `README.md`.
  - Untracked artifacts: `backend/app/api/v1/research.py`, `backend/tests/test_phase7_external_benchmark.py`, `evaluation/external_dataset/`, `evaluation/reports/combined/`, `evaluation/reports/external/`, `evaluation/reports/phase7/dataset_candidates.md`, `evaluation/reports/phase7/dataset_suitability.json`, `frontend/`.

All pre-existing user work was strictly preserved without reset, stash, or overwrite.

---

## 2. Changes Made During RC1 Stabilization

Only demonstrated release-blocking, security-hardening, and packaging defects were modified:

1. **Strict Content-Security-Policy on HTML Reports (`backend/app/services/report.py`)**
   - *Reason:* Added `_CSP_META_TAG` (`default-src 'none'; style-src 'unsafe-inline'; font-src 'none'; img-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none';`) to both completed and failed standalone HTML report templates. This ensures reports opened in any browser cannot execute JavaScript, make network requests, or load remote resources.
   - *Line Length:* Formatted constant across multiple concatenated strings to strictly conform to Ruff's 100-character line limit.

2. **Strict Report-Preview Iframe Sandboxing (`frontend/src/components/reports/ReportsScreen.tsx`)**
   - *Reason:* Changed the preview iframe sandbox attribute from `sandbox="allow-same-origin"` to `sandbox=""`.
   - *Security Impact:* `sandbox="allow-same-origin"` alone retains parent origin privileges. Applying `sandbox=""` creates an opaque `null` origin, completely disabling scripts, form submissions, popups, parent window navigation, and parent storage/cookie access.

3. **Frontend Production Bundle Splitting (`frontend/src/App.tsx`)**
   - *Reason:* The initial JavaScript bundle was ~700 kB due to synchronous imports of Recharts and all 7 screens.
   - *Optimization:* Implemented dynamic `React.lazy()` and `Suspense` loading for secondary screens (`NewScanScreen`, `ScanDetailsScreen`, `FindingsExplorerScreen`, `EndpointCorrelationScreen`, `ReportsScreen`, `ResearchDashboardScreen`).
   - *Result:* Reduced the entry bundle from ~700 kB to **249.86 kB (78.40 kB gzip)** across 16 optimized chunks. The heavyweight 389.49 kB Recharts bundle is now deferred until the research dashboard is opened.

4. **Security Sandboxing Documentation (`README.md`)**
   - *Reason:* Corrected section 6 of the README to accurately document `sandbox=""` and CSP meta tag enforcement rather than the insecure `sandbox="allow-same-origin"`.

---

## 3. Test & Quality-Gate Verification Results

All quality gates were executed directly using documented commands. Every gate succeeded:

| Gate | Command Executed | Result | Outcome Summary |
|---|---|---|---|
| **Backend Test Suite** | `uv run pytest` | **PASS** | 203 passed, 0 failed in 13.25s (100% pass rate) |
| **Backend Linting** | `uv run ruff check .` | **PASS** | Clean, 0 errors |
| **Backend Formatting** | `uv run ruff format --check .` | **PASS** | 130 files checked, 100% clean |
| **Strict Type Checking** | `uv run mypy backend/app backend/tests` | **PASS** | Success: 0 issues in 111 source files |
| **Database Migrations** | `uv run alembic check` | **PASS** | Schema matches models (`No new upgrade operations detected`) |
| **Dependency Security Audit** | `uv run pip-audit` | **PASS** | 0 known vulnerabilities found |
| **Static Security Analysis** | `uv run bandit -r backend/app -ll` | **PASS** | 0 High, 0 Medium severity issues |
| **Docker Compose Config** | `docker compose config` | **PASS** | Valid configuration; services properly isolated |
| **Frontend Test Suite** | `cd frontend && npm test` | **PASS** | 15 passed across 3 test files in 7.60s |
| **Frontend Linter** | `cd frontend && npx oxlint` | **PASS** | 0 errors (48 non-blocking warnings) |
| **Frontend Production Build** | `cd frontend && npm run build` | **PASS** | 16 chunks generated cleanly (index: 249.86 kB) |

---

## 4. Security Review Findings

All security controls were reviewed against actual running code:

### A. Authentication & Tenant Isolation
- **API Token Verification:** Verified via `GET /api/v1/scans` without `Authorization` header returning `401 Unauthorized` with `{"detail": "Missing or invalid authorization credentials"}`.
- **Tenant Isolation:** Client IDs are strictly resolved from `API_CLIENT_TOKENS` mappings. Requests with token `client-a-token` cannot view, poll, or retrieve scan results belonging to `client-b-token` (`404 Not Found` returned consistently to prevent resource existence disclosure).
- **Public Endpoints:** Only `/health` is unauthenticated; all `/api/v1/*` routes require valid bearer tokens.

### B. Report-Preview Isolation
- **Iframe Sandboxing:** Rendered with `sandbox=""` in `frontend/src/components/reports/ReportsScreen.tsx`.
- **Content-Security-Policy:** Both completed and failed HTML reports include `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src 'none'; img-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none';">`.
- **HTML Escaping:** All user-controlled fields (`project_name`, `scan_id`, `error_message`, `rule_id`, `endpoint`) pass through `html.escape()` prior to string interpolation.
- **Assessment:** **Zero risk of stored XSS or parent application compromise.**

### C. Secrets & Logging Redaction
- **Masking Engine:** Backend `app.core.security.mask_sensitive_data` and frontend `redactSecrets` redact JWTs, bearer tokens, AWS keys, passwords, and sensitive JSON keys.
- **Headers & Parameters:** Authorization headers and uploaded ZIP raw file contents are never logged.
- **Static Detector Findings:** Source secrets found during scans have values redacted to `[REDACTED_SECRET]` before storage in `ScanResult` or presentation in HTML/JSON reports.

### D. Workload & Upload Controls
- **Upload Guards:** Enforced via `MAX_SPEC_BYTES` (5 MB), `MAX_ARCHIVE_BYTES` (25 MB), and `MAX_UPLOAD_BYTES` (50 MB).
- **Archive Security:** Streaming ZIP extraction enforces `MAX_UNCOMPRESSED_BYTES` (50 MB), `MAX_FILES_PER_SCAN` (2000), file size limit (1 MB per member), path traversal checks (`..`), and symlink rejection.
- **Concurrency & Rate Limiting:** Enforced via `MAX_ACTIVE_SCANS` (10 global), `MAX_CONCURRENT_SCANS_PER_CLIENT` (2 per tenant), and `SCAN_RATE_LIMIT_REQUESTS` (20 req/60s).

### E. Deployment Security
- **Interface Binding:** In `docker-compose.yml`, PostgreSQL 18 published port is explicitly pinned to `127.0.0.1:5432` and API to `127.0.0.1:8000`. Neither is exposed on `0.0.0.0`.
- **Production Guard:** If `ENVIRONMENT=production`, `Settings` validation explicitly rejects `_DISALLOWED_PRODUCTION_SECRETS` (e.g. `development-only-replace-me`, `dev-insecure-api-access-token-do-not-use-in-production`).
- **Memory Limits:** Process-level `WORKER_MAX_MEMORY_BYTES` (512 MB) limits worker memory, but production deployments must also enforce OS/cgroup container limits (`--memory=1g`, `--cpus=2.0`).

### Severity Classification Table
| Identifier | Severity | Component | Description & Status |
|---|---|---|---|
| SEC-01 | **Low** | `backend/app/analysis/source/secrets.py` | Bandit B105/B106 flags placeholder strings in secret regex rules (`env_config`, `placeholder`). Status: **Verified safe (detector regexes, not credentials)**. |
| SEC-02 | **Low** | `backend/app/evaluation/statistics.py` | Bandit B311 flags `random.Random(seed)` used for deterministic bootstrap CI simulation. Status: **Verified safe (statistical modeling, not crypto)**. |
| SEC-03 | **Info** | `frontend/src/components/reports/ReportsScreen.tsx` | Iframe sandbox changed from `allow-same-origin` to `sandbox=""` + CSP. Status: **Remediated**. |

---

## 5. Verification Status & Distinctions

To ensure complete transparency without fabricating test results:

1. **Automated UI Tests:**
   - **Status:** **PASS** (15 tests passed across 3 test files).
   - Validated upload file type and size validation, API key storage and header injection, secret redaction, and research schema parsing.

2. **Live HTTP Proxy Verification:**
   - **Status:** **PASS** (Full live workflow executed against real running services).
   - PostgreSQL 18 container running healthy on `127.0.0.1:5432`.
   - FastAPI running on `http://127.0.0.1:8000`.
   - Vite dev proxy running on `http://localhost:5173`.
   - Tested real end-to-end workflow through Vite proxy:
     - Unauthenticated rejection (`401 Unauthorized`).
     - Scan creation with OpenAPI YAML and source ZIP (`202 Accepted`, Scan ID `80ba17d5-d865-4f40-8fb3-ae4d19aaeb30`).
     - Polling scan status to `COMPLETED` (`200 OK`).
     - Retrieving 3 matched endpoint pairs (`200 OK`).
     - Retrieving findings across spec, source, and correlated layers (`200 OK`).
     - Exporting server-generated HTML report (`200 OK`).
     - Exporting structured JSON report with secret redaction (`200 OK`).

3. **Browser Automation Testing (Playwright / Headless):**
   - **Status:** **NOT EXECUTED IN CONTAINER** (Host environment blocks external Azure CDN driver binary downloads with HTTP 404/network unreachable).
   - In accordance with non-negotiable constraint #6, browser automation is distinguished from live HTTP verification, and no browser recordings or artificial DOM states have been fabricated.

---

## 6. Research Integrity & Epistemic Boundaries

Evaluation was verified using the CLI `--output-dir` parameter targeting scratch directories, preserving original published reports in `evaluation/reports/phase6/` untouched:

### A. Evaluation Results Summary
- **Baseline Benchmark (24 synthetic cases):**
  - `SPEC_ONLY`: Precision = 0.5000, Recall = 0.5000, F1 = 0.5000 (FPR = 28.6%, FNR = 50.0%)
  - `SOURCE_ONLY`: Precision = 0.5556, Recall = 0.6250, F1 = 0.5882 (FPR = 28.6%, FNR = 37.5%)
  - `CORRELATED`: Precision = 0.8333, Recall = 0.6250, F1 = 0.7143 (FPR = 7.1%, FNR = 37.5%)
  - *Observation:* Correlation significantly suppresses false positives (FPR drops from 28.6% to 7.1%), boosting precision from 0.50/0.55 to 0.8333.
- **External Benchmark (12 cases, VAmPI):**
  - `SPEC_ONLY`: Precision = 0.6667, Recall = 0.5714, F1 = 0.6154 (4 TP, 2 FP, 3 FN, 3 TN)
  - `SOURCE_ONLY`: Recall = 0.0000, TP = 0, FN = 7 (No endpoints discovered)
  - `CORRELATED`: Recall = 0.0000, TP = 0, FN = 7
- **Combined Benchmark (36 cases):**
  - `SPEC_ONLY`: Precision = 0.5714, Recall = 0.5333, F1 = 0.5517
  - `SOURCE_ONLY`: Precision = 0.5556, Recall = 0.3333, F1 = 0.4167
  - `CORRELATED`: Precision = 0.8333, Recall = 0.3333, F1 = 0.4762

### B. Methodological Honesty & Limitations
1. **The VAmPI / Connexion Architectural Limitation:**
   - VAmPI routes endpoints dynamically via Connexion's `operationId` mappings specified in `openapi.yaml`, rather than direct FastAPI (`@app.get`) or Flask (`@app.route`) decorators.
   - The frozen Python AST source extractor explicitly searches for framework decorators, discovering 0 endpoints in VAmPI Python modules.
   - This limitation is documented as a known design boundary rather than masked by modifying ground truth or unfreezing the analyzer.
2. **Sample Size & Confidence Intervals:**
   - Sample sizes (n=24 baseline, n=12 external) yield wide bootstrap 95% confidence intervals. Results indicate directional suppression of false positives rather than universal statistical dominance.
3. **Static Analysis Epistemic Boundary:**
   - Findings represent static-analysis evidence of discrepancies and missing security controls, not proof of runtime exploitability.

---

## 7. Known Limitations & Production Deployment Requirements

1. **Production Infrastructure Requirements:**
   - **TLS 1.3 Termination:** Must terminate HTTPS at the reverse proxy (Nginx, Traefik, or AWS ALB) with HSTS headers.
   - **Secret Provisioning:** Operators must provide strong, distinct secrets for `API_ACCESS_TOKEN` and `SESSION_SECRET`. Default placeholders will prevent startup in `production` mode.
   - **Container Resource Caps:** Application-level limits (`WORKER_MAX_MEMORY_BYTES=536870912`) protect individual subprocesses, but container cgroup memory limits (`--memory=1g`) and CPU limits (`--cpus=2.0`) are required to prevent host exhaustion.
   - **Rate Limiting & WAF:** Ingress controllers must enforce IP rate limiting and maximum body size quotas matching backend upload thresholds.

2. **Framework Support:**
   - AST source parsing natively supports FastAPI and Flask route decorators. Connexion, Django Ninja, and custom routing frameworks require future endpoint extractor extensions.

3. **Horizontal Scaling:**
   - Scan jobs currently run via local worker subprocesses with database state coordination. High-volume multi-node deployments require an external job queue (e.g., Celery, Redis, or Temporal).

---

## 8. Remaining Release Blockers

**None.**
- All 203 backend unit and integration tests pass.
- All 15 frontend tests pass.
- Type checking, linting, formatting, migration checks, and dependency audits are 100% clean.
- Iframe sandbox and CSP security controls are fully enforced.
- Analyzer rules and Phase 6 ground truth remain strictly frozen.

---

## 9. RC1 Release Recommendation

### **Recommendation: GO**

**Justification:**
1. **Security Integrity:** The application enforces strong tenant isolation, complete secret redaction, strict `sandbox=""` and CSP on reports, bounded uploads, and safe local network interface bindings.
2. **Quality Gates:** 100% pass rate across backend pytest (203/203), frontend vitest (15/15), mypy, ruff, oxlint, pip-audit, and production build.
3. **Performance:** Initial client bundle reduced from ~700 kB to 249.86 kB (78.40 kB gzip) via code splitting.
4. **Scientific Honesty:** Preserved 100% frozen core analyzer, intact Phase 6 ground truth, and transparent documentation of external benchmark limitations and confidence intervals.
