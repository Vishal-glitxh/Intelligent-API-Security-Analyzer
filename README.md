# Intelligent API Security Analyzer

A defensive, evidence-based REST API security analyzer with OpenAPI analysis, source-code static analysis, cross-layer evidence correlation, and research evaluation infrastructure.

---

## Quick Start & Local Setup

### Requirements
- Python `>=3.14,<3.15`
- `uv` package manager
- Docker (for PostgreSQL integration tests)

### Environment Initialization
```bash
# 1. Install project dependencies and editable package
uv sync

# 2. Configure environment defaults
cp .env.example .env

# 3. Start PostgreSQL container
docker compose up -d postgres

# 4. Run full test suite (167 tests)
uv run pytest

# 5. Run static quality gates
uv run ruff check .
uv run ruff format --check .
uv run mypy backend
uv run alembic check
```

---

## Research Evaluation Infrastructure (Phase 6 Baseline)

The repository includes a self-contained, reproducible evaluation harness under `backend/app/evaluation/` and `evaluation/dataset/`.

### Benchmark Composition
- **Total Cases**: 24 benchmark cases across 6 security categories (`authentication`, `authorization`, `input_validation`, `sensitive_data`, `secrets`, `cross_layer_correlation`, `endpoint_matching`).
- **Dimension-A Propositions**: 22 tracked security propositions (`PROP-AUTH-001..005`, `PROP-AUTHZ-001..005`, `PROP-INPUT-001..004`, `PROP-DATA-001..004`, `PROP-SECRET-001..004`).
- **Dimension B & C Benchmarks**: Cross-layer correlation benchmark (`CORR-001`) and multi-pair endpoint normalization benchmark (`MATCH-001`).

### Experimental Modes
1. **`SPEC_ONLY`**: Evaluates security finding detection using OpenAPI specifications alone.
2. **`SOURCE_ONLY`**: Evaluates security finding detection using FastAPI source code ASTs alone.
3. **`CORRELATED`**: Multi-layer analysis synthesizing OpenAPI spec rules, source AST rules, parameter normalization, and cross-layer correlation rules.

### Executing the Research Evaluation CLI

To reproduce the published baseline report artifacts:

```bash
# Execute evaluation CLI (deterministic baseline mode)
uv run evaluate

# Alternative direct module invocation
uv run python -m app.evaluation.cli
```

To run a dynamic evaluation pass (generating fresh runtime UUIDs and ISO execution timestamps):

```bash
# Save dynamic run artifacts to git-ignored evaluation/runs/ directory
uv run evaluate --dynamic --output-dir evaluation/runs
```

### Published Baseline Metrics (Phase 6)

| Metric | `SPEC_ONLY` | `SOURCE_ONLY` | `CORRELATED` (Multi-Layer) |
|:-------|:------------|:--------------|:---------------------------|
| **Precision** | `0.5000` | `0.5556` | **`0.8333`** |
| **Recall** | `0.5000` | `0.6250` | `0.6250` |
| **F1 Score** | `0.5000` | `0.5882` | **`0.7143`** |
| **False Positive Rate (FPR)** | `0.2857` | `0.2857` | **`0.0714`** |
| **False Negative Rate (FNR)** | `0.5000` | `0.3750` | `0.3750` |
| **TP / FP / FN / TN** | `4 / 4 / 4 / 10` | `5 / 4 / 3 / 10` | `5 / 1 / 3 / 13` |
| **Completeness Score** | `1.0000` | `1.0000` | `1.0000` |
| **Explainability Score** | `1.0000` | `0.9885` | `1.0000` |

* **Dimension B (Correlation Accuracy)**: `1.0000`
* **Dimension C (Endpoint Match Accuracy)**: `1.0000`

### Evaluation Artifacts & Directory Structure
- `evaluation/reports/`: Canonical, tracked JSON artifacts (`metrics.json`, `classifications.json`, `endpoint_matching.json`, `evidence_completeness.json`, `explainability.json`, `full_report.json`, `phase6_proposition_trace.json`, `phase6_proposition_trace.md`) and HTML report (`report.html`).
- `evaluation/runs/`: Ignored workspace directory for custom/dynamic experimental runs.

---

## Security & Development Credentials Policy

* `POSTGRES_USER=analyzer` and `POSTGRES_PASSWORD=analyzer` in `.env.example` and `docker-compose.yml` are development and testing credentials intended solely for local containerized execution.
* Synthetic API key strings (e.g. `sk_live_998877665544332211` and `AKIAIOSFODNN7NOTREAL`) in `backend/tests/fixtures/` and `evaluation/dataset/cases/SECRET-001/` are controlled non-production test inputs used exclusively to validate rule detectors.
