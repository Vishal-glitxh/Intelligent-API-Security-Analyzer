# Intelligent API Security Analyzer — Release Notes (v1.0.0-rc.1)

**Release Version:** `v1.0.0-rc.1`  
**Target Milestone:** Release Candidate 1 (RC1)  
**Release Date:** October 13, 2026  
**Status:** **Release Candidate 1**  

---

## 1. Overview & Capabilities

The Intelligent API Security Analyzer is an evidence-based, multi-layer static security analysis platform for REST APIs. Rather than relying on speculative heuristics, the system performs deterministic, rule-based extraction across both OpenAPI specifications and Python backend source code, correlating findings to identify security posture drift, undocumented endpoints, and authentication contradictions.

### Core Capabilities
- **Dual-Layer Analysis Engine:**
  - **OpenAPI Layer:** Validates OpenAPI 3.0/3.1 specs, normalizes schema references, and detects missing authentication schemes, weak security requirements, unconstrained parameters, and sensitive response field definitions.
  - **Source Code Layer:** Uses AST-based static extraction for FastAPI and Flask route trees, detecting unauthenticated route handlers, missing object-level access controls, unconstrained request inputs, and hardcoded credentials.
- **Cross-Layer Evidence Correlation:**
  - Deterministic 4-tier endpoint matching algorithm: Exact URI match, Parameter-normalized match, Subpath match, and Ambiguous match.
  - Correlates specification claims against implementation reality across four distinct states:
    - **SUPPORTED:** Both layers agree that security controls are present.
    - **CONTRADICTED:** Specification asserts security controls, but source code lacks implementation (or vice versa).
    - **COMPLEMENTARY:** One layer identifies risks invisible to the other.
    - **INCONCLUSIVE:** Insufficient evidence or conflicting ambiguous routing.
- **Analyst-Facing Web UI:**
  - Modern React 19 interface providing interactive dashboards, real-time scan progress polling, endpoint correlation matrices, itemized findings explorers, research evaluation metrics, and standalone report exports.
- **Empirical Research Framework:**
  - Built-in evaluation framework comparing `SPEC_ONLY`, `SOURCE_ONLY`, and `CORRELATED` analysis modes across the Phase 6 canonical baseline (24 cases) and external VAmPI benchmark (12 cases).

---

## 2. Architecture & Technology Stack

- **Backend:** Python 3.14, FastAPI, SQLAlchemy 2.0, PostgreSQL 18 (with async/sync drivers), Alembic migrations, Uvicorn, Tree-Sitter & Python `ast`.
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS, Recharts, Lucide Icons.
- **Infrastructure:** Docker & Docker Compose with isolated internal networking; PostgreSQL bound strictly to `127.0.0.1:5432`.

---

## 3. Authentication & Scan Workflow

1. **Client Authentication:**
   - Every API request requires a Bearer token (`Authorization: Bearer <token>`).
   - Tenant isolation is strictly enforced; client tokens are mapped to isolated client IDs. Cross-tenant access to scans, findings, or reports returns `404 Not Found` without disclosing resource existence.
2. **Scan Lifecycle:**
   - Client uploads OpenAPI specification (`.yaml` / `.json`) and source code archive (`.zip`) via `POST /api/v1/scans`.
   - Backend validates payload sizes against strict guards:
     - Specification limit: 5 MB (`MAX_SPEC_BYTES`)
     - Archive limit: 25 MB (`MAX_ARCHIVE_BYTES`)
     - Total upload limit: 50 MB (`MAX_UPLOAD_BYTES`)
   - Job is queued and dispatched to an isolated subprocess worker.
   - Status transitions from `QUEUED` -> `RUNNING` -> `COMPLETED` (or `FAILED` with sanitized error details).
3. **Artifact Generation:**
   - Persisted to PostgreSQL tables: `scans`, `scan_results`, and `audit_events`.
   - Results exportable as canonical structured JSON (`GET /api/v1/scans/{id}/report?format=json`) or standalone styled HTML (`GET /api/v1/scans/{id}/report?format=html`).

---

## 4. Security Findings, Correlation & Report Isolation

### Security Hardening in RC1
- **Strict HTML Report Isolation:**
  - Server-generated HTML reports include `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src 'none'; img-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none';">`.
  - The UI report preview iframe enforces `sandbox=""`, which strips same-origin privileges and disables script execution, DOM traversal, and parent window navigation.
- **Sensitive Data & Secret Redaction:**
  - Backend logs, error messages, and frontend visualizations redact sensitive tokens, JWTs, AWS credentials, and password values using regular-expression masking engines.
- **Archive Ingestion Defense:**
  - ZIP archives are safely unpacked with streaming decompression quotas (50 MB max uncompressed, 2000 files maximum, 1 MB max individual member size).
  - Traversal attempts (`../`) and symbolic links are detected and immediately rejected.

---

## 5. Empirical Benchmark Summary

Evaluations were executed across frozen partitions using the documented CLI (`python -m app.evaluation.cli`):

### A. Baseline Benchmark (24 synthetic ground-truth cases)
| Metric | SPEC_ONLY | SOURCE_ONLY | CORRELATED | Impact of Correlation |
|---|---|---|---|---|
| **Precision** | 0.5000 | 0.5556 | **0.8333** | **+66.7% vs Spec, +50.0% vs Source** |
| **Recall** | 0.5000 | 0.6250 | **0.6250** | Matches best single-layer recall |
| **F1 Score** | 0.5000 | 0.5882 | **0.7143** | **Superior overall balance** |
| **False Positive Rate** | 0.2857 | 0.2857 | **0.0714** | **Suppresses FPR from 28.6% to 7.1%** |

### B. External Benchmark (12 cases, VAmPI)
- **`SPEC_ONLY` Mode:** Precision = 0.6667, Recall = 0.5714, F1 = 0.6154 (4 TP, 2 FP, 3 FN, 3 TN).
- **`SOURCE_ONLY` Mode:** Recall = 0.0000 (0 TP, 7 FN).
- **`CORRELATED` Mode:** Precision = N/A, Recall = 0.0000, F1 = N/A.

---

## 6. Known Limitations & Research Honesty

1. **VAmPI / Connexion Source-Routing Limitation:**
   - VAmPI defines API routing dynamically in `openapi.yaml` via Connexion's `operationId` mappings rather than standard route decorators.
   - The frozen Python AST extractor targets FastAPI and Flask decorators (`@app.get`, `@app.route`), discovering 0 endpoints in VAmPI Python modules. This expected architectural boundary is retained honestly without altering benchmark ground truth.
2. **Sample Size & Statistical Significance:**
   - Benchmarks (n=24 baseline, n=12 external) produce wide bootstrap 95% confidence intervals. Correlated mode demonstrates strong directional suppression of false positives, but cannot be claimed as universally superior across all API architectures.
3. **Epistemic Boundary:**
   - Static analysis evidence indicates potential vulnerabilities and policy contradictions; it does not constitute proof of dynamic runtime exploitability.
4. **Browser Automation Status:**
   - Automated testing in the development environment consists of 203 backend Pytest tests, 15 frontend Vitest tests, and real end-to-end HTTP proxy validation. Headless browser automation (Playwright) was not executed in the container due to environment sandbox restrictions on downloading external browser driver binaries.

---

## 7. Installation & Quick Start

### Prerequisites
- Python 3.14 with `uv`
- Node.js 22+ with `npm`
- Docker and Docker Compose (PostgreSQL 18)

### Quick Start
```bash
# 1. Start PostgreSQL
docker compose up -d postgres

# 2. Apply database migrations
uv run alembic upgrade head

# 3. Start backend API
uv run uvicorn app.main:app --app-dir backend --port 8000

# 4. Start frontend (in a separate terminal)
cd frontend
npm install
npm run dev
```

### Reproducible Demonstration via cURL
```bash
# Submit an analysis job
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer dev-insecure-api-access-token-do-not-use-in-production" \
  -F "project_name=Demo API" \
  -F "spec_file=@evaluation/dataset/cases/AUTH-001/openapi.yaml" \
  -F "source_file=@evaluation/dataset/cases/AUTH-001/source.zip"

# Poll status (replace SCAN_ID with returned ID)
curl http://localhost:8000/api/v1/scans/<SCAN_ID> \
  -H "Authorization: Bearer dev-insecure-api-access-token-do-not-use-in-production"

# Fetch HTML report
curl http://localhost:8000/api/v1/scans/<SCAN_ID>/report?format=html \
  -H "Authorization: Bearer dev-insecure-api-access-token-do-not-use-in-production"
```

---

## 8. Production Deployment Prerequisites

Before deploying in a production environment:
1. **Terminate TLS 1.3:** Terminate HTTPS at the reverse proxy (Nginx/Traefik/ALB) and configure HSTS headers.
2. **Secret Rotation:** Supply unique, high-entropy secrets for `API_ACCESS_TOKEN` and `SESSION_SECRET`. Default values cause startup abortion when `ENVIRONMENT=production`.
3. **OS / Container Resource Limits:** Enforce container cgroup quotas (`--memory=1g`, `--cpus=2.0`) in addition to process-level caps (`WORKER_MAX_MEMORY_BYTES`).
4. **Reverse Proxy Quotas:** Mirror upload limits at the gateway layer to reject oversized payloads before buffering in application memory.
