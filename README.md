# Intelligent API Security Analyzer

A defensive, evidence-based REST API security analyzer combining OpenAPI specification analysis, source-code AST static analysis, cross-layer deterministic correlation, optional private local RAG/LLM assistance, and research evaluation benchmarking with an analyst-facing React workstation.

---

## Architecture Overview

```
                                      ┌────────────────────────────────────────┐
                                      │   Analyst Web Workstation (Phase 8)    │
                                      │   React 19 + TypeScript + Vite + CSS   │
                                      │   Port: 5173 (Dev Proxy)               │
                                      └───────────────────┬────────────────────┘
                                                          │ HTTP (local development or API token)
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

The repository's `docker-compose.yml` is for local development only. It includes development credentials and a development authentication setting; do not use it as a production deployment. Production must explicitly use `ENVIRONMENT=production` and secure credentials.

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

The backend exposes separate process liveness and dependency readiness checks:
`http://localhost:8000/health/live` (also available at the compatibility path `/health`)
reports that the API process is running. `http://localhost:8000/health/ready` returns success
only after startup scan recovery succeeds and the database answers `SELECT 1`; Docker Compose
uses this readiness endpoint for the API health check. If startup recovery fails, the process
remains live for diagnosis but stays unready until restarted after the underlying problem is fixed.

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

The counts below are from the dated verification runs recorded here; test counts change as coverage evolves. Older release notes and reports retain the counts from their historical runs.

Run the automated verification suite across both backend and frontend:

```bash
# Backend test suite (345 tests in the 2026-10-27 verification run)
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

# Frontend test suite (14 tests in the 2026-10-27 verification run)
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
2. **New Scan**: Drag-and-drop OpenAPI specification (`.json`, `.yaml`, `.yml`) with an optional source archive (`.zip`) for implementation analysis.
3. **Scan Details**: Scan status lifecycle (`QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`), polling with cleanup, execution metrics, and redacted failure messages.
4. **Findings Explorer**: Workstation for filtering by severity, category, and detection layer (`SPEC`, `SOURCE`, `CORRELATED`), with secret redaction and a keyless evidence assistant.
5. **Endpoint Correlation**: Cross-layer endpoint matching (`Tier 1: Exact`, `Tier 2: Parameterized`, `Tier 3: Normalized`) with separated contract and AST evidence.
6. **Research Dashboard**: Empirical benchmark visualizations using Recharts comparing `SPEC_ONLY`, `SOURCE_ONLY`, and `CORRELATED` across 24 baseline cases and 12 external VAmPI cases with 95% confidence intervals and explicit Connexion limitation notices.
7. **Reports & Export**: In-memory download of structured JSON and executive HTML reports with sandboxed iframe preview.

---

## Keyless local AI and hybrid RAG

Deterministic OpenAPI rules, source AST analysis, and correlation work without an AI service or cloud API key. The Findings Explorer includes a hybrid retrieval assistant that searches scan findings, endpoint mappings, and bundled API security guidance. It returns citations and keeps scan evidence distinct from general guidance.

When Ollama and a configured model are available, the assistant can add a structured, evidence-cited explanation and suggested next steps. Ollama is optional and contacted only at the local endpoint configured by `OLLAMA_BASE_URL` (loopback on the host, or `host.docker.internal` when Compose connects to Ollama on the host); status uses `GET /api/tags`, embeddings use `POST /api/embed`, and explanations use `POST /api/generate`. Embedding requests contain the question and up to 128 candidate document texts capped at 1,200 characters each after secret-pattern redaction; generation receives only the selected retrieved sources within the configured context budget. Uploaded source archives are not sent. HTTP redirects are rejected so a configured local Ollama endpoint cannot forward these request bodies to a redirect target. Models are never downloaded automatically.

Without a local embedding model, retrieval uses lexical ranking and a deterministic hashed-vector fallback. Without a local generation model, scan and retrieval still work and report that AI was not used. Locally generated embeddings are computed per request and not persisted; there is no durable vector index or index-administration interface yet. Internet is needed only to install dependencies or explicitly pull a chosen local model; live public-reference retrieval is not enabled. Ollama can be configured to listen beyond loopback by its operator; keep it bound to localhost unless intentional network access is protected by deployment controls.

The bundled security guidance is a small, project-maintained paraphrase set adapted from the [OWASP API Security Top 10 2023](https://api-security.owasp.org/), which is licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). Each returned OWASP source includes its official page URL and license label. The snippets are reference guidance, not authoritative scan evidence.

| Capability | Hosted API key required | Ollama required |
|---|---|---|
| Deterministic scanning and rule-based remediation | No | No |
| Lexical and hashed-vector fallback retrieval | No | No |
| Model-based semantic retrieval | No | Yes, with a configured local embedding model |
| Local AI explanations | No | Yes, with a configured local chat model |

Install Ollama separately and choose models explicitly:

```bash
ollama pull qwen2.5:3b
ollama pull nomic-embed-text
```

Set `.env` values to enable local generation and embeddings:

```dotenv
LOCAL_AI_ENABLED=true
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5:3b
OLLAMA_EMBEDDING_MODEL=nomic-embed-text
```

The authenticated status endpoint is `GET /api/v1/ai/status`; scan-specific questions use `POST /api/v1/scans/{scan_id}/assistant`. In Docker Compose, use `OLLAMA_BASE_URL=http://host.docker.internal:11434` when Ollama runs on the host.

### Retrieval evaluation

The separate `hybrid-rag-retrieval-v1` fixture set measures retrieval Recall@5 and Precision@5, retrieved source-ID validity, deterministic answer-template support, abstention, and the lexical/hashed-vector fallback. It does not score generated answers or alter scanner benchmark metrics. The eight-query protocol run recorded on 2026-10-27 achieved Recall@5 1.000, Precision@5 0.257, source-ID validity 1.000 (20/20), template-support rate 1.000 (8/8), and abstention 1.000 (1/1). The labeled expected source IDs are a small, manually reviewed conformance set; this is not a broad RAG quality or LLM groundedness claim. Latency and resource use were not measured.

Run the evaluation into a temporary file:

```bash
uv run python -m app.evaluation.rag_protocol_v1 --output /tmp/hybrid-rag-v1-results.json
```

### Local authentication

The example local configuration enables `LOCAL_DEV_AUTH_BYPASS=true`, allowing loopback development without entering an API token. The bypass applies only when `ENVIRONMENT=development`; production configuration rejects it. Production must explicitly set `ENVIRONMENT=production`, `LOCAL_DEV_AUTH_BYPASS=false`, a strong `SESSION_SECRET`, a strong `API_ACCESS_TOKEN`, and a non-development `DATABASE_URL`. The supported environment labels are `development`, `testing`, and `production`; unknown labels are rejected. Keep development services bound to `127.0.0.1` as shown above. A cloud AI API key is never used.

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

The included Docker Compose setup is for local development only. It uses development configuration and is not a production deployment template. Production deployments must set `ENVIRONMENT=production` and secure credentials explicitly; configuration validation rejects development bypasses, built-in tokens, fallback secrets, and the default database URL. This project currently supports one API process and one deployment replica: upload admission and startup recovery use process-local coordination, so multi-worker and multi-replica deployments are not supported or verified.

Before deploying this application to a production or staging environment, ensure the following hardening controls are implemented:

1. **Supported deployment topology**: Run one API process on one replica. Do not enable multiple server workers or replicas until upload admission and startup recovery use shared coordination and have been verified for that topology.

2. **Private Networking & Database Isolation**:
   - PostgreSQL must never be published to public network interfaces (`0.0.0.0`). Bind exclusively to private container networks or VPC subnets.
   - The backend API should sit behind a hardened reverse proxy (e.g., NGINX, Cloudflare, or AWS ALB) with restricted public ingress.

3. **Container Resource Limits**:
   - Set explicit memory and CPU limits on the API and database containers to prevent denial-of-service via resource exhaustion:
     ```yaml
     deploy:
       resources:
         limits:
           cpus: '2.0'
           memory: 2048M
     ```

4. **Secrets Management**:
   - Set high-entropy `API_ACCESS_TOKEN` and `SESSION_SECRET` values in the deployment secret manager.
   - Set `LOCAL_DEV_AUTH_BYPASS=false` and use separate client credentials where tenant isolation is required.
   - Enforce rotation of `API_ACCESS_TOKEN` and `SESSION_SECRET`.

5. **HTTPS / TLS Termination**:
   - Terminate TLS 1.3 at the reverse proxy or ingress gateway.
   - Enable HSTS (`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`).

6. **Upload & Gateway Quotas**:
   - Enforce gateway-level payload limits aligned with backend settings (`MAX_SPEC_BYTES=5242880`, `MAX_ARCHIVE_BYTES=26214400`, `MAX_UPLOAD_BYTES=52428800`).
   - Rate limit scan creation endpoints (`POST /api/v1/scans`) to mitigate disk and compute exhaustion attacks.

7. **Static File Sandboxing**:
   - Generated HTML reports rendered via the UI are isolated inside sandboxed `<iframe>` tags with `sandbox=""` (disabling scripts, parent DOM traversal, forms, and same-origin access) plus server-generated strict `Content-Security-Policy` headers/meta tags to prevent cross-site scripting (XSS).

