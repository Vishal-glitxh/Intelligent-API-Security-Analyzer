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
only when PostgreSQL is reachable and the expected Alembic revision is installed; Docker Compose
uses this readiness endpoint for the API health check. Queued and leased jobs recover through
database-backed worker claims rather than being failed during API startup.

---

### 2. Frontend Analyst Workstation Setup

```bash
# 1. Navigate to frontend directory
cd frontend

# 2. Install Node dependencies
npm install

# 3. Start Vite development server (loopback-only; proxies /api and /health to :8000)
npm run dev
```

The analyst workstation will be available at: `http://127.0.0.1:5173`. Vite binds to loopback by
default. LAN access to the development server is not supported; do not override the host binding
while `LOCAL_DEV_AUTH_BYPASS=true`. For access from another device, use a deliberate token-authenticated
deployment instead of exposing the development proxy.

### Demo: run and review a scan

The application has no user-account or sign-up flow; access uses API tokens. With the example
development configuration, the header reports **Local access** when the API is bound to loopback
and `LOCAL_DEV_AUTH_BYPASS=true`. For a token-authenticated local demo, set `API_ACCESS_TOKEN` to a
local test token and `LOCAL_DEV_AUTH_BYPASS=false` in `.env` before starting the API. Then choose
**Connect API** in the workstation header and enter that token. The browser keeps it in session
storage for the current session. `API_CLIENT_TOKENS` can instead map client IDs to tokens as JSON,
for example `{"analyst-a":"<local-test-token>"}`. Never use development credentials or the bypass
in production.

1. In the workstation, choose **New assessment**, optionally enter a project name, select a valid
   `.json`, `.yaml`, or `.yml` OpenAPI document, and optionally add a `.zip` source archive. Uploaded
   source is parsed statically; the analyzer does not execute it.
2. Choose **Start assessment** and wait for the scan summary to show `COMPLETED`. A `FAILED` scan
   remains visibly distinct and does not contain completed findings.
3. Open **Findings Explorer** to inspect specification, source, and correlated evidence. Choose
   **Reports & Export** to preview or download the JSON and HTML reports.

The corresponding API workflow is `POST /api/v1/scans`, then `GET /api/v1/scans/{scan_id}/findings`
and `GET /api/v1/scans/{scan_id}/report?format=json` (use `format=html` for HTML). Each scan is
restricted to its owning client token.

---

## Verification & Quality Gates

The counts below are from the dated verification runs recorded here; test counts change as coverage evolves. Older release notes and reports retain the counts from their historical runs.

Run the automated verification suite across both backend and frontend:

```bash
set -e
# Start a disposable PostgreSQL test instance. Do not point tests at the local
# development Compose database or any database containing user data.
docker run --rm -d --name iasa-test-postgres \
  --publish 127.0.0.1:55432:5432 \
  --tmpfs /var/lib/postgresql:rw,size=1g \
  --env POSTGRES_DB=iasa_test \
  --env POSTGRES_USER=iasa_test \
  --env POSTGRES_PASSWORD=replace-with-test-only-password \
  postgres:18
trap 'docker stop iasa-test-postgres >/dev/null 2>&1 || true' EXIT
until docker exec iasa-test-postgres pg_isready -U iasa_test -d iasa_test; do sleep 1; done

# The test suite rejects anything except PostgreSQL databases named *_test or *_testing.
export TEST_DATABASE_URL='postgresql+psycopg://iasa_test:replace-with-test-only-password@127.0.0.1:55432/iasa_test'
export DATABASE_URL="$TEST_DATABASE_URL"
export ENVIRONMENT=testing
uv run alembic upgrade head
uv run pytest -v --cov=backend/app --cov-report=term-missing

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

### Recorded verification evidence

The full backend run recorded on 2026-10-28 passed **386 tests** with **87% coverage** and two
dependency deprecation warnings. It used a newly created disposable PostgreSQL 18 test database
on tmpfs; `uv run alembic upgrade head` succeeded, and an isolated migration-consistency check
reported no pending model changes. Ruff, formatting, strict MyPy, and `git diff --check` passed in
that verification sequence. The frontend run recorded on 2026-10-27 passed 14 tests, lint, and the
production build. The dependency audit reported no known vulnerabilities in audited distributions;
it skipped the local project package because it was not available from PyPI.

An isolated Docker Compose smoke run recorded on 2026-10-28 built an image, applied migrations,
returned HTTP 200 from liveness and readiness, completed an authenticated scan, returned HTTP 200
for findings and report retrieval, and returned HTTP 403 for cross-tenant retrieval. That smoke run
used Ollama disabled and preceded the final RAG retrieval guard change; it does not verify a Docker
image built from the final RAG code or local-model behavior. No live RAG generation was part of the
final backend regression run.

Current working-tree checks on 2026-10-29 passed **401 backend tests** with **86% coverage** and two
dependency warnings, using a newly created PostgreSQL 18 database on tmpfs. Alembic upgrade and
consistency checks passed. Ruff, Ruff formatting, strict MyPy, high-severity Bandit, `pip-audit`, and
`git diff --check` passed; `pip-audit` could not audit the local project package because it is not
published on PyPI. Frontend verification passed 14 tests, lint, and production build in a temporary
copy so the existing `frontend/dist` and TypeScript cache were not overwritten.

The current API image was built and exercised in isolated production configuration with a disposable
PostgreSQL database. Migrations reached head; `/health/live` and `/health/ready` returned HTTP 200; an
authenticated scan completed; findings and JSON report returned HTTP 200; and another tenant received
HTTP 403 for both. The local Ollama status endpoint reported `llama3.2:latest` and
`nomic-embed-text:latest` available, with the unchanged seven-document/seven-chunk index ready. One
non-benchmark assistant request used the local model successfully. This verifies a single API process
only. Shared coordination, durable job recovery, multi-worker behavior, and multi-replica deployment
remain unsupported and unverified.

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

Without a compatible local embedding index, retrieval uses lexical ranking and a deterministic hashed-vector fallback. Without a local generation model, scan and retrieval still work and report that AI was not used. Embedding indexes are local, versioned JSON files built only by an explicit command; the application never downloads models, fetches source URLs, or rebuilds an index at startup. Internet is needed only to install dependencies or explicitly pull a chosen local model. Ollama can be configured to listen beyond loopback by its operator; keep it bound to localhost unless intentional network access is protected by deployment controls.

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

### Local retrieval index

The index is optional: deterministic scans and lexical retrieval continue when it is absent or stale. Build it explicitly from the bundled guidance with the configured local embedding model, or choose lexical-only mode:

```bash
cd backend
uv run python -m app.services.rag_index_cli rebuild
uv run python -m app.services.rag_index_cli inspect
uv run python -m app.services.rag_index_cli rebuild --lexical-only
```

An optional bounded JSON manifest can add reviewed documents. Each document must provide `document_id`, `title`, `source_type`, and `content`; `source_location`, `source_url`, and `license` are optional provenance fields. Use `--manifest sources.json --only-manifest` to build only those documents. IDs must be stable and unique; duplicate identical entries are deduplicated, while conflicting IDs reject the rebuild. Inputs are size bounded, normalized for common secrets, split into stable chunks, and validated before an atomic replacement. The index stores the Ollama model name and installed-model digest, vector dimensions, and chunking metadata, uses restrictive local file permissions, and is marked stale when the embedding model version or chunking configuration changes. Failed builds preserve the previous index.

### Local document ingestion (separately versioned candidate)

The explicit `ingest` command extracts PDF, DOCX, TXT, Markdown, and HTML files from a local directory. It does not fetch URLs, access the network, or run during API startup. The default category is public security documentation; `--category internal_iasa_knowledge` explicitly labels internal reference material. It skips hidden and sensitive configuration/credential paths, rejects symbolic links and non-regular files, enforces per-file, total-byte, document-count, page, and corpus-text bounds, and deduplicates identical source files by SHA-256. PDF text extraction uses the pinned `pypdf` dependency; DOCX reads only the main document XML without extracting archive paths. Text and HTML parsing do not execute scripts or embedded content.

Every ingested chunk carries the relative source identity, original filename, raw-file SHA-256, normalized-document SHA-256, chunk SHA-256, character offsets, and page/section where available. The v2 index stores the normalized source text needed to verify that chunk offsets and hashes are consistent. The command requires a **new explicit output path** and refuses the active index path or any existing output, so the historical `rag-index-v1.json` is not replaced. Build an unembedded candidate with:

```bash
uv run python -m app.services.rag_index_cli ingest \
  --directory ./approved-reference-documents \
  --output ./scratch/rag-index-v2-candidate.json \
  --lexical-only
```

Omit `--lexical-only` to request embeddings from the configured local Ollama embedding model. Ollama handles device selection; the application does not download or initialize BAAI models. If Ollama is unavailable, deterministic CPU hashed vectors and BM25 remain the retrieval fallback; these are lexical-support fallbacks, not equivalent semantic embeddings. To activate the candidate, configure `RAG_INDEX_PATH` explicitly to that file. Ingested public and internal documents are **not eligible for model generation by default**. A trusted operator must review the content and configure the exact normalized-document SHA-256 values in `RAG_APPROVED_DOCUMENT_HASHES`; the assistant then permits only exact retrieved excerpts from those approved hashes. The editable index alone cannot approve material. Do not approve documents containing untrusted instructions or content that should not be sent to the local model.

The existing locally bundled OWASP guidance remains application-controlled and model-eligible as before. Scan findings and endpoint/source evidence remain separate dynamic sources and are never merged into external-document trust. Uploading references is an operator CLI action; no new public API ingestion endpoint or persistent user-document store is introduced.

`hybrid-rag-retrieval-v2` is a separate 17-query protocol with manually reviewed query-specific relevant source IDs, per-query outcomes, false-positive lists, and category metrics. The recorded lexical/hash fallback result was Recall@5 0.941 and macro Precision@5 0.188; the live semantic RRF baseline reproduced those aggregate values, with 17/17 queries returning at least one out-of-label source. A separate `hybrid-rag-precision-experiment-v1` compared component and hybrid rankings without changing the query labels. Its provisional live-semantic candidate applies a 0.50 cosine floor only when the installed embedding model and persistent index are compatible: on this set it retained Recall@5 0.941, returned 61 rather than 85 sources, reduced false-positive IDs from 69 to 45, and abstained on three of four zero-relevance controls. Fixed-k macro Precision@5 remained 0.188 because its denominator stays five; precision among returned IDs increased from 0.188 to 0.262. The adversarial control still retrieved five sources, and the single missed relevant source remains. This small, model/index-specific result is a limited noise reduction, not a broad quality claim. Full per-query ranks, component scores, configurations, and hashes are in `evaluation/rag/experiments/precision-v1/RESULTS.md`; historical scanner benchmarks remain separate and unchanged.

Retrieval relevance, citation validity, and answer groundedness are distinct. The v2 protocol reports retrieved source-ID validity; groundedness remains unmeasured unless a reviewer supplies an answer-hash-bound human review. Citation presence alone is not proof of support.

The separate `hybrid-rag-groundedness-v1` cases at `evaluation/rag/groundedness-v1/cases.json` are a draft pending human review. The six-case review copy is `evaluation/rag/groundedness-v1/cases-review-ready-v1.json`; its manifest labels remain unchanged. The immutable r2 candidate is `evaluation/rag/groundedness-v1/candidate-runs/candidate-2026-10-28-targeted-fixes-r2/answers.json`, with its report beside it. The answers hash is `655b706267a57e941c2e5f6258a53c971b13705ac6f1bfd75195ac4357f114f9`; the report hash is `26c470b9838fa51753c031b0f0654cf8b7e1caebb13ae851c4bb5c4daa22ed20`. Use `review-template-r2-candidate-2026-10-28.json`, whose records bind to those exact answer hashes. Four cases have raw model responses and two abstained before generation; the four raw responses were rejected and the final application responses used deterministic fallbacks. The earlier temporary provenance checkpoint `/tmp/iasa-groundedness-v1-candidate-draft.json` is unavailable and has not been recreated or substituted. Review the raw and final responses, retrieved excerpts, citations, and abstention decisions using `evaluation/rag/groundedness-v1/REVIEW_GUIDE.md`. Under the original v1 process, Case 5 remains pending and the review set is not scoreable; the separately versioned v2 human review is described below.

### Separate human-groundedness review v2

To preserve the historical v1 protocol, the six r2 answers were also reviewed under the separate
`hybrid-rag-groundedness-review-v2` process in `evaluation/rag/groundedness-v2/`. Its answer-bound
review and guide separate the immutable manifest's abstention expectation, actual answer behavior,
and reviewer judgment; Case 5's disagreement is retained rather than folded into the manifest
metric. The recorded report at `evaluation/rag/groundedness-v2/reports/r2-review-metrics-v2.json`
reports manifest agreement 6/6 and reviewer agreement 5/6, with separate raw/final claim and
citation metrics. This six-case human-reviewed sample is descriptive, not a broad quality estimate
or release approval. The v1 template remains unchanged and pending under its original process. The
original temporary provenance checkpoint remains unavailable. The v2 review SHA-256 is
`1e0f498c44507da64921058c6164e2bece914b8761ea38a6442cabd70aa9670e`; the metrics report SHA-256 is
`ee213e4952f6a963fea37cdb0f9c70fb304e83163fb24725c9d95bd76cb0628e`.

Run the new evaluation to a separate temporary file:

```bash
cd backend
uv run python -m app.evaluation.rag_protocol_v2 --output /tmp/hybrid-rag-v2-results.json
```

### Retrieval evaluation

The separate `hybrid-rag-retrieval-v1` fixture set measures retrieval Recall@5 and Precision@5, retrieved source-ID validity, deterministic answer-template support, abstention, and the lexical/hashed-vector fallback. It does not score generated answers or alter scanner benchmark metrics. The eight-query protocol run recorded on 2026-10-27 achieved Recall@5 1.000, Precision@5 0.257, source-ID validity 1.000 (20/20), template-support rate 1.000 (8/8), and abstention 1.000 (1/1). The labeled expected source IDs are a small, manually reviewed conformance set; this is not a broad RAG quality or LLM groundedness claim. Latency and resource use were not measured. This historical v1 result remains unchanged by the v2 protocol.

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

The included Docker Compose setup is for local development only. It uses development configuration and is not a production deployment template. Production deployments must set `ENVIRONMENT=production` and secure credentials explicitly; configuration validation rejects development bypasses, built-in tokens, fallback secrets, the default database URL, and local-only artifact storage. A provider-neutral multi-replica reference architecture is documented in [the deployment guide](docs/deployment/PROVIDER_NEUTRAL_MULTI_REPLICA.md); it requires PostgreSQL coordination, S3-compatible shared artifact storage, migrations before rollout, and the deployment controls described there. Production readiness still requires provider-specific deployment, security, load, failure-recovery, and operational verification.

Before deploying this application to a production or staging environment, ensure the following hardening controls are implemented:

1. **Supported deployment topology**: Use the provider-neutral architecture and deployment gates in `docs/deployment/PROVIDER_NEUTRAL_MULTI_REPLICA.md`. The reference describes the intended topology; it does not claim a deployment has been validated or approved for production.

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

