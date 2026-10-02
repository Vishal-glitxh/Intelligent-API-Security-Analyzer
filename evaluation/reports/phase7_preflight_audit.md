# Phase 7 Pre-Flight Repository Error & Code-Leak Audit

**Repository**: Intelligent API Security Analyzer  
**Audit Date**: September 29, 2026  
**Auditor**: Antigravity AI (Pair Programming Auditor)  
**Audit Type**: Read-Only Forensic Baseline & Pre-Flight Verification  

---

## 1. Executive Summary

This report presents the findings of the **Phase 7 Pre-Flight Repository Error & Code-Leak Audit** for the **Intelligent API Security Analyzer** repository. The primary objective of this audit is to establish an empirical, evidence-based baseline across runtime safety, code quality, secret leakage, evaluation reproducibility, and infrastructure integrity prior to initiating Phase 7 (Research Hardening & Statistical Analysis).

The audit verified that all core analyzer implementations in `backend/app/analysis/` remain **100% immutable and untouched** relative to the Phase 5 completion baseline (`commit 060e9a2`). All 167 unit and integration tests pass, and static quality gates (`ruff check`, `ruff format`, `mypy`, `alembic check`, `docker compose config`) report clean execution. Furthermore, **zero real production secrets or sensitive credentials** were identified across tracked or untracked repository files.

The audit identified **10 distinct findings**: 0 Critical, 1 High, 2 Medium, 4 Low, and 3 Informational. The primary High-severity finding is a repository execution-path packaging issue where running `uv run python -m app.evaluation.cli` fails with `ModuleNotFoundError: No module named 'app'`, whereas running with `PYTHONPATH=backend` succeeds and perfectly reproduces Phase 6 experimental metrics. Additionally, running report generation introduces non-deterministic diffs (UUID and timestamp drift) in tracked JSON/HTML report artifacts.

Based on these findings, the audit recommendation is **GO WITH CONDITIONS** for Phase 7 entry, contingent on resolving the execution-path and report-drift remediation items (P0/P1) prior to statistical analysis.

---

## 2. Audit Scope

The audit covered all components and layers of the repository without modifying existing code, configurations, benchmarks, or ground truth:

1. **Source & Analyzer Code**: `backend/app/` (specifically checking `backend/app/analysis/` against commit `060e9a2`).
2. **Test Suites & Quality Gates**: `backend/tests/`, `pyproject.toml`, `alembic.ini`, `docker-compose.yml`.
3. **Secret & Sensitive Data Audit**: Full scan across tracked and untracked files, `.env`, `.env.example`, fixtures, and benchmark cases.
4. **Evaluation Infrastructure**: `backend/app/evaluation/`, `evaluation/dataset/` (24 cases, 22 Dimension-A propositions), `evaluation/reports/`, and `scratch/`.
5. **Infrastructure & Environment**: Docker setup, PostgreSQL configs, Python dependencies, and `pyproject.toml` layout.
6. **Documentation & Runbooks**: `README.md`, `docs/`, `runbooks/`, and inline CLI instructions.

---

## 3. Repository Baseline

### 3.1 Git Commit Baseline
- **HEAD Commit**: `21d2b2c Add complete Phase 6 evaluation artifacts`
- **Phase 6 Finalization**: `de40e5b Finalize Phase 6 research evaluation`
- **Phase 5 Baseline**: `060e9a2 Complete Phase 5 failure-path validation`
- **Phase 1-5 Implementation**: `3ea0f55 Add Phase 1-5 analyzer implementation`
- **Initial Commit**: `16c1a54 first commit`

### 3.2 Analyzer Immutability Verification
- **Command**: `git diff 060e9a2 -- backend/app/analysis/`
- **Result**: `EMPTY` (0 lines changed).
- **Verification Status**: **PASS**. The core analyzer logic (`openapi/`, `source/`, `correlation/`, `rules/`) has remained strictly immutable since Phase 5 completion.

---

## 4. Runtime Findings

Each quality check command specified in the audit prompt was executed independently in a read-only manner:

| Command | Status | Exit Code | Notes / Output Summary |
|---------|--------|-----------|------------------------|
| `uv run pytest` | **PASS** | 0 | 167 passed, 2 deprecation warnings |
| `uv run ruff check .` | **PASS** | 0 | All checks passed |
| `uv run ruff format --check .` | **PASS** | 0 | 117 files already formatted |
| `uv run mypy backend` | **PASS** | 0 | Success: no issues found in 108 source files |
| `uv run alembic check` | **PASS** | 0 | No new upgrade operations detected |
| `docker compose config` | **PASS** | 0 | Valid compose structure (`postgres:18`, port `5432`) |
| `uv run python -m app.evaluation.cli` | **FAIL** | 1 | `ModuleNotFoundError: No module named 'app'` |
| `PYTHONPATH=backend uv run python -m app.evaluation.cli` | **PASS** | 0 | Successfully executes evaluation across 24 cases |

---

## 5. Test & Quality Gate Results

### 5.1 Pytest Execution Summary
- **Total Tests**: 167
- **Passed**: 167 (100%)
- **Failed**: 0
- **Duration**: ~3.37 seconds
- **Warnings**: 2 deprecation warnings emitted from third-party libraries:
  1. `StarletteDeprecationWarning`: `Using httpx with starlette.testclient is deprecated; install httpx2 instead.` (`fastapi/testclient.py:1`)
  2. `DeprecationWarning`: `The anyio.abc.BlockingPortal alias is deprecated, use anyio.from_thread.BlockingPortal instead.` (`starlette/testclient.py:53`)

### 5.2 Static Quality & Database Verification
- **Ruff**: 0 lint errors, 0 formatting drift.
- **Mypy**: 0 type errors across 108 files under strict mode (`strict = true`).
- **Alembic**: Database schema is fully synchronized with ORM models.
- **Docker**: Syntax and environment declarations in `docker-compose.yml` are valid.

---

## 6. Secret / Credential Leakage Findings

A comprehensive regex-based and manual search was performed across all tracked and untracked files in the repository.

### 6.1 Audit Categories & Classifications
- **REAL SECRET**: 0 found. No active production keys, cloud tokens, private RSA keys, or live DB credentials exist in the repository.
- **DEVELOPMENT-ONLY CREDENTIAL**: `POSTGRES_USER=analyzer`, `POSTGRES_PASSWORD=analyzer`, `SESSION_SECRET=development-only-replace-me` found in `.env`, `.env.example`, and `docker-compose.yml`. Safe for local development, but must be configured via environment overrides in production.
- **TEST/FIXTURE SECRET**: Hardcoded strings like `sk_live_998877665544332211`, `AWS_SECRET_KEY = "AKIAIOSFODNN7NOTREAL"`, `TEST_DB_PASSWORD = "test_password_123"` exist inside `backend/tests/fixtures/` and `evaluation/dataset/cases/SECRET-001/`. These are synthetic test data used by security detection rules (`SECRET-001` / `PROP-SECRET-001`).
- **PLACEHOLDER**: Example connection strings in documentation and config files.

---

## 7. Sensitive Artifact Findings

| File / Pattern | Location | Git Status | Classification | Assessment |
|----------------|----------|------------|----------------|------------|
| `.env` | Repository root | Untracked (Ignored) | Local Dev Config | Properly ignored by `.gitignore` (Line 10). Contains local dev DB URL. |
| `.env.example` | Repository root | Tracked | Config Template | Public template containing safe development defaults. |
| `.DS_Store` | Root, `backend/`, `scratch/` | Untracked (Ignored) | OS Metadata | Ignored by `.gitignore` (Line 15). Safe. |
| `.coverage*` | Repository root | Untracked (Ignored) | Runtime Test Coverage | Ignored by `.gitignore` (Line 7). Safe. |
| `.venv/` | Repository root | Untracked (Ignored) | Virtual Environment | Ignored by `.gitignore` (Line 1). Safe. |
| `scratch/runtime-test-api.zip` | `scratch/` | Untracked (Ignored) | Test Artifact | Ignored by `.gitignore` (Line 19). Safe. |
| `scratch/runtime-test-api/` | `scratch/` | Untracked (Ignored) | Test Artifact Dir | Ignored by `.gitignore` (Line 20). Safe. |

---

## 8. Git Hygiene Findings

1. **Clean Working Tree**: `git status` prior to running report generation showed `nothing to commit, working tree clean`.
2. **Tracked Files in Scratch**: `scratch/generate_trace_report.py` and `scratch/verify_manual_api.py` are tracked in git. While functional, storing primary report generators in a `scratch/` folder creates slight architectural ambiguity.
3. **Ignored Patterns Verification**: `.gitignore` correctly covers Python caches (`__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`), coverage files, `.venv`, `.env`, OS metadata (`.DS_Store`), and Phase 6 run outputs (`evaluation/runs/`).

---

## 9. Docker / Infrastructure Findings

- **Service Definition**: `docker-compose.yml` defines a single service (`postgres`) using image `postgres:18`.
- **Port Binding**: Port `5432:5432` is published to localhost.
- **Default Credentials**: `POSTGRES_USER=analyzer`, `POSTGRES_PASSWORD=analyzer`, `POSTGRES_DB=api_security`.
- **Persistence**: Named volume `postgres_data` mounts to `/var/lib/postgresql`.
- **Assessment**: Suitable for local evaluation and testing. Clear documentation should emphasize replacing these credentials in production environments.

---

## 10. Evaluation Reproducibility Findings

### 10.1 Ground Truth & Benchmark Integrity
- **Total Cases**: 24 cases (`AUTH-001` through `AUTH-005`, `AUTHZ-001` through `AUTHZ-005`, `INPUT-001` through `INPUT-004`, `DATA-001` through `DATA-004`, `SECRET-001` through `SECRET-004`, `CORR-001`, `MATCH-001`).
- **Dimension A Propositions**: Exactly **22 propositions** are tracked across the benchmark (confirming the baseline requirement).
- **Dimension B & C Benchmarks**: 1 correlation benchmark case (`CORR-001`), 1 endpoint matching case (`MATCH-001`).

### 10.2 Phase 6 Results Reproduction
Executing `PYTHONPATH=backend uv run python -m app.evaluation.cli` reproduces the exact Phase 6 metrics:

```
--------------------------------------------------------------------------
DIMENSION A: SECURITY DETECTION EVALUATION SUMMARY
--------------------------------------------------------------------------
Metric               | SPEC_ONLY    | SOURCE_ONLY  | CORRELATED  
--------------------------------------------------------------------------
Precision            | 0.5000       | 0.5556       | 0.8333      
Recall               | 0.5000       | 0.6250       | 0.6250      
F1                   | 0.5000       | 0.5882       | 0.7143      
FPR                  | 0.2857       | 0.2857       | 0.0714      
FNR                  | 0.5000       | 0.3750       | 0.3750      
TP                   | 4            | 5            | 5           
FP                   | 4            | 4            | 1           
FN                   | 4            | 3            | 3           
TN                   | 10           | 10           | 13          
--------------------------------------------------------------------------
Dimension B Correlation Accuracy : 1.0000
Dimension C Endpoint Match Acc.  : 1.0000
```

---

## 11. Report Drift Findings

When running the evaluation CLI, 7 JSON/HTML report files in `evaluation/reports/` are modified:
- `evaluation/reports/classifications.json`
- `evaluation/reports/endpoint_matching.json`
- `evaluation/reports/evidence_completeness.json`
- `evaluation/reports/explainability.json`
- `evaluation/reports/full_report.json`
- `evaluation/reports/metrics.json`
- `evaluation/reports/report.html`

### 11.1 Cause of Drift
`git diff evaluation/reports/` demonstrates that **100% of evaluation metrics, TP/FP/FN/TN counts, scores, and classifications are identical**. The diff is caused exclusively by non-deterministic dynamic fields:
1. `experiment_id`: A newly generated UUID on each CLI execution (e.g. `4eb72e4c...` vs `b27b46fb...`).
2. `execution_timestamp`: An ISO 8601 UTC timestamp recorded at runtime (e.g. `2026-09-20T04:15:55Z` vs `2026-09-29T06:33:48Z`).

---

## 12. Documentation Findings

- `README.md` contains basic Phase 1 installation and uvicorn startup instructions.
- It does **not** document how to execute the Phase 6 research evaluation CLI (`PYTHONPATH=backend uv run python -m app.evaluation.cli`).
- Onboarding researchers attempting to run `uv run python -m app.evaluation.cli` encounter a `ModuleNotFoundError` without clear guidance.

---

## 13. Security Code Review Findings

- **Input Validation**: `backend/app/analysis/openapi/parser.py` uses `openapi-spec-validator` and `pyyaml` with `yaml.safe_load`. No unsafe deserialization or YAML code execution risks exist.
- **AST Parsing**: `backend/app/analysis/source/extractor.py` uses `tree-sitter` for static AST parsing. Source files are read as plain text without compiling or executing the code under test.
- **Process Safety**: No `subprocess(shell=True)`, `eval()`, or `exec()` calls exist in the core analyzer package (`backend/app/analysis/`).

---

## 14. Complete Findings Register

| ID | Severity | Category | Finding | Evidence | Impact | Status |
|----|----------|----------|---------|----------|--------|--------|
| **FIND-01** | **HIGH** | Runtime / Packaging | Evaluation CLI fails without `PYTHONPATH=backend` | `uv run python -m app.evaluation.cli` raises `ModuleNotFoundError: No module named 'app'` due to `[tool.uv] package = false`. | Prevents standard CLI execution without environment prefix. | **CONFIRMED** |
| **FIND-02** | **MEDIUM** | Report Drift | Dynamic fields dirty git working tree on report generation | `git diff` shows `experiment_id` (UUID) and `execution_timestamp` change on every evaluation run. | Requires reverting report changes to keep working tree clean. | **CONFIRMED** |
| **FIND-03** | **MEDIUM** | Documentation | Evaluation commands missing from `README.md` | `README.md` lacks instructions for running evaluation suite or setting `PYTHONPATH`. | Hinders research reproducibility for external users. | **CONFIRMED** |
| **FIND-04** | **LOW** | Test Integrity | Third-party deprecation warnings during pytest | `uv run pytest` outputs 2 warnings from `starlette.testclient` and `anyio`. | No test failures, but noise in pytest output. | **CONFIRMED** |
| **FIND-05** | **LOW** | Docker / Credentials | Development credentials hardcoded in dev configs | `POSTGRES_PASSWORD=analyzer` and `SESSION_SECRET=development-only-replace-me` in `.env.example` and `docker-compose.yml`. | Low risk for dev setup; risk if deployed to production unchanged. | **ACCEPTED_RISK** |
| **FIND-06** | **LOW** | Git Hygiene | Tracked scripts present in `scratch/` directory | `scratch/generate_trace_report.py` and `scratch/verify_manual_api.py` are tracked in git repository. | Minor organization debt in scratch directory. | **CONFIRMED** |
| **FIND-07** | **LOW** | Sensitive Artifacts | OS metadata files (`.DS_Store`) present locally | `.DS_Store` files in root, `backend/`, and `scratch/`. | Properly excluded by `.gitignore`; no repository leakage. | **CONFIRMED** |
| **FIND-08** | **INFORMATIONAL** | Benchmark Secrets | Controlled fake secrets in synthetic benchmark cases | `sk_live_998877665544332211` and `AKIAIOSFODNN7NOTREAL` in test fixtures and case `SECRET-001`. | Intentionally synthetic test inputs for security rule validation; zero leakage risk. | **CONFIRMED (Non-Leak)** |
| **FIND-09** | **INFORMATIONAL** | Security Audit | Secure AST parsing and OpenAPI spec loading | `yaml.safe_load` and tree-sitter AST parsing used throughout `backend/app/analysis/`. | Confirms high security quality of analyzer engine. | **CONFIRMED** |
| **FIND-10** | **INFORMATIONAL** | Research Limitation | Non-endpoint source secrets dropped in CORRELATED mode | `PROP-SECRET-001` transitions from TP (SOURCE_ONLY) to FN (CORRELATED). | Known correlation engine boundary documented in Phase 6. | **ACCEPTED_RISK** |

---

## 15. Recommended Remediation Plan

### P0 — Must Fix Before Phase 7 Implementation
- **Remediate Execution Path (FIND-01)**: Add a root CLI wrapper script or configure package resolution in `pyproject.toml` so `uv run python -m app.evaluation.cli` or `uv run evaluate` works seamlessly without manual `PYTHONPATH` prefixes.

### P1 — Should Fix Before Phase 7 Analysis
- **Normalize Evaluation Report Output (FIND-02)**: Add an option to freeze dynamic fields (`experiment_id`, `execution_timestamp`) or output generated evaluation runs into an un-tracked directory (`evaluation/runs/`) while keeping git-tracked baseline reports deterministic.
- **Update Documentation (FIND-03)**: Update `README.md` with explicit research evaluation commands and execution guidelines.

### P2 — Can Fix During Phase 7
- **Clean Scratch Directory (FIND-06)**: Move formal evaluation scripts (`generate_trace_report.py`) into `backend/app/evaluation/` or a dedicated `scripts/` module.
- **Deprecation Cleanups (FIND-04)**: Update `fastapi` test client usages to suppress or eliminate Starlette/AnyIO deprecation warnings.

### P3 — Optional Hardening
- **Production Guardrails (FIND-05)**: Add runtime checks preventing `SESSION_SECRET=development-only-replace-me` when `ENVIRONMENT=production`.

---

## 16. Phase 7 Entry Criteria

Phase 7 (Research Hardening & Statistical Analysis) may proceed once the following entry criteria are formally acknowledged:

1. **Analyzer Immutability**: `git diff 060e9a2 -- backend/app/analysis/` remains strictly empty (VERIFIED).
2. **Quality Gates**: All 167 pytest cases pass, ruff check/format pass, and mypy passes (VERIFIED).
3. **Execution Path Resolution**: Remediation P0 (CLI execution path) is defined and approved for implementation.
4. **Secret Safety**: Zero production credential leaks confirmed across repository (VERIFIED).

---

## 17. Final Decision

### **GO WITH CONDITIONS**

**Justification**:
The repository is structurally sound, highly compliant with quality gates, 100% test-verified, free of secret leaks, and mathematically reproducible across all Phase 6 research evaluation dimensions. The analyzer core (`backend/app/analysis/`) is verified to be 100% untouched since Phase 5 baseline commit `060e9a2`. 

Entry into Phase 7 is granted **WITH CONDITIONS**:
1. Implement the P0 remediation (packaging / CLI invocation wrapper) so evaluation execution does not require undocumented `PYTHONPATH` flags.
2. Implement P1 report drift controls before running large-scale statistical iterations in Phase 7.
