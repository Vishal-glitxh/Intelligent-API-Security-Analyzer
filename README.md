# Intelligent API Security Analyzer

A defensive, evidence-based REST API security analyzer combining OpenAPI specification analysis, source-code AST static analysis, cross-layer deterministic correlation, and research evaluation benchmarking with an analyst-facing React workstation.

---

## Architecture Overview

```
                                      ┌────────────────────────────────────────┐
                                      │   Analyst Web Workstation (Phase 8)    │
                                      │   React 19 + TypeScript + Vite + CSS   │
                                      │   Port: 5173 (Dev Proxy)               │
                                      └───────────────────┬────────────────────┘
                                                          │ HTTP (API Key / Bearer)
                                                          ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ FastAPI Application Server (Port 8000)                                                               │
│                                                                                                      │
│  ┌───────────────────────┐  ┌─────────────────────────┐  ┌────────────────────────────────────────┐  │
│  │ Spec Analyzer         │  │ Source AST Analyzer     │  │ Cross-Layer Correlation Engine         │  │
│  │ (OpenAPI Rules)       │  │ (FastAPI / Flask AST)   │  │ (Tier 1-3 Matching & Synthesis)        │  │
│  └───────────┬───────────┘  └────────────┬────────────┘  └───────────────────┬────────────────────┘  │
│              └───────────────────────────┼───────────────────────────────────┘                       │
│                                          ▼                                                           │
│                         MultiLayerAnalysisResult                                                     │
│                                          │                                                           │
│                        ┌─────────────────┴─────────────────┐                                         │
│                        ▼                                   ▼                                         │
│             PostgreSQL (Port 5432)              Audit Reports (HTML / JSON)                          │
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start & Local Setup

### Requirements
- **Python**: `>=3.14,<3.15`
- **Node.js**: `>=20`
- **uv**: Modern Python package manager
- **Docker**: For local containerized PostgreSQL

---

### 1. Environment & Backend Setup

```bash
# 1. Install Python dependencies and package in editable mode
uv sync

# 2. Configure environment defaults
cp .env.example .env

# 3. Start PostgreSQL container (isolated to 127.0.0.1:5432)
docker compose up -d postgres

# 4. Apply database schema migrations
uv run alembic upgrade head

# 5. Start FastAPI application server
uv run uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

The backend health check is available at: `http://localhost:8000/health`.

---

### 2. Frontend Analyst Workstation Setup

```bash
# 1. Navigate to frontend directory
cd frontend

# 2. Install Node dependencies
npm install

# 3. Start Vite development server (proxies /api and /health to :8000)
npm run dev
```

The analyst workstation will be available at: `http://localhost:5173`.

---

## Verification & Quality Gates

Run the automated verification suite across both backend and frontend:

```bash
# Backend test suite (203 unit, integration, and security tests)
uv run pytest

# Backend static analysis and formatting
uv run ruff check .
uv run ruff format --check .
uv run mypy backend
uv run alembic check

# Security audits
uv run pip-audit
uv run bandit -r backend/app -lll -q
docker compose config

# Frontend test suite (15 unit and integration tests)
cd frontend
npm test

# Frontend linting
npm run lint

# Frontend production compilation and bundle chunk verification
npm run build
```

---

## Analyst Web UI Features (Phase 8)

The frontend workstation provides seven specialized screens:

1. **Dashboard**: Live scan telemetry, total/completed/failed scan counts, finding distribution, and recent audit activity.
2. **New Scan**: Drag-and-drop OpenAPI specification (`.json`, `.yaml`, `.yml`) and source archive (`.zip`) upload with client-side limit validation.
3. **Scan Details**: Scan status lifecycle (`QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`), polling with cleanup, execution metrics, and redacted failure messages.
4. **Findings Explorer**: Two-pane workstation for filtering by severity, category, and detection layer (`SPEC`, `SOURCE`, `CORRELATED`) with automatic secret redaction.
5. **Endpoint Correlation**: Cross-layer endpoint matching (`Tier 1: Exact`, `Tier 2: Parameterized`, `Tier 3: Normalized`) with separated contract and AST evidence.
6. **Research Dashboard**: Empirical benchmark visualizations using Recharts comparing `SPEC_ONLY`, `SOURCE_ONLY`, and `CORRELATED` across 24 baseline cases and 12 external VAmPI cases with 95% confidence intervals and explicit Connexion limitation notices.
7. **Reports & Export**: In-memory download of structured JSON and executive HTML reports with sandboxed iframe preview.

---

## Research Evaluation Infrastructure

The repository includes a self-contained, reproducible evaluation harness under `backend/app/evaluation/`.

### Benchmark Partitions
- **Baseline Benchmark (Phase 6)**: 24 test cases (10 authentic vulnerabilities, 14 negative controls) across 5 core security categories.
- **External VAmPI Benchmark (Phase 7.3)**: 12 external benchmark test cases derived from the OWASP Benchmark candidate VAmPI (`f16052dce83f05847133ec98f01c5193a41de7d8`).
- **Combined Benchmark**: 36 total cases evaluating generalized cross-dataset multi-layer correlation.

### Executing the Evaluation CLI

```bash
# Execute baseline benchmark (24 cases)
uv run evaluate --benchmark baseline

# Execute external VAmPI benchmark (12 cases)
uv run evaluate --benchmark external

# Execute combined benchmark (36 cases)
uv run evaluate --benchmark combined

# Dynamic evaluation run with fresh UUIDs and timestamps
uv run evaluate --dynamic --output-dir evaluation/runs
```

### Published Baseline Metrics (Phase 6)

| Metric | `SPEC_ONLY` | `SOURCE_ONLY` | `CORRELATED` (Multi-Layer) |
|:---|:---|:---|:---|
| **Precision** | `0.5000` | `0.5556` | **`0.8333`** |
| **Recall** | `0.5000` | `0.6250` | `0.6250` |
| **F1 Score** | `0.5000` | `0.5882` | **`0.7143`** |
| **False Positive Rate (FPR)** | `0.2857` | `0.2857` | **`0.0714`** |
| **False Negative Rate (FNR)** | `0.5000` | `0.3750` | `0.3750` |
| **TP / FP / FN / TN** | `4 / 4 / 4 / 10` | `5 / 4 / 3 / 10` | `5 / 1 / 3 / 13` |

---

## Production Deployment Checklist

Before deploying this application to a production or staging environment, ensure the following hardening controls are implemented:

1. **Private Networking & Database Isolation**:
   - PostgreSQL must never be published to public network interfaces (`0.0.0.0`). Bind exclusively to private container networks or VPC subnets.
   - The backend API should sit behind a hardened reverse proxy (e.g., NGINX, Cloudflare, or AWS ALB) with restricted public ingress.

2. **Container Resource Limits**:
   - Set explicit memory and CPU limits on the API and database containers to prevent denial-of-service via resource exhaustion:
     ```yaml
     deploy:
       resources:
         limits:
           cpus: '2.0'
           memory: 2048M
     ```

3. **Secrets Management**:
   - Replace development placeholder tokens (`dev-insecure-api-access-token-do-not-use-in-production`, `analyzer:analyzer`) with high-entropy cryptographic secrets managed via AWS Secrets Manager, GCP Secret Manager, or HashiCorp Vault.
   - Enforce rotation of `API_ACCESS_TOKEN` and `SESSION_SECRET`.

4. **HTTPS / TLS Termination**:
   - Terminate TLS 1.3 at the reverse proxy or ingress gateway.
   - Enable HSTS (`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`).

5. **Upload & Gateway Quotas**:
   - Enforce gateway-level payload limits aligned with backend settings (`MAX_SPEC_BYTES=5242880`, `MAX_ARCHIVE_BYTES=26214400`, `MAX_UPLOAD_BYTES=52428800`).
   - Rate limit scan creation endpoints (`POST /api/v1/scans`) to mitigate disk and compute exhaustion attacks.

6. **Static File Sandboxing**:
   - Generated HTML reports rendered via the UI are isolated inside sandboxed `<iframe>` tags with `sandbox=""` (disabling scripts, parent DOM traversal, forms, and same-origin access) plus server-generated strict `Content-Security-Policy` headers/meta tags to prevent cross-site scripting (XSS).

