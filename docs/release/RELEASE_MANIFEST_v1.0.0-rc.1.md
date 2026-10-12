# Intelligent API Security Analyzer — Release Manifest (v1.0.0-rc.1)

**Release Identifier:** `v1.0.0-rc.1`  
**Target Milestone:** Release Candidate 1 (RC1)  
**Date of Generation:** October 13, 2026  
**Status:** **Verified Release Package**  

---

## 1. Source Identification & Git State

- **Repository Branch:** `main`
- **Base Commit:** `814a30c` ("Complete Phase 7.2 security hardening and statistical analysis")
- **Commit Date:** October 2, 2026
- **Working-Tree Status:** **Verified Working-Tree Snapshot**
  - *Note on Working Tree:* The release archive packages the verified working tree corresponding to commit `814a30c` combined with Phase 7.3 external benchmarks, Phase 8 web UI integration, and RC1 security hardening. It is explicitly not a clean snapshot of `HEAD` commit `814a30c`.
  - *Tracked Modifications:*
    - `README.md` (updated security sandboxing documentation)
    - `backend/app/api/router.py` (registered research and scan routes)
    - `backend/app/api/v1/scans.py` (tenant ownership and rate-limiting enforcement)
    - `backend/app/evaluation/cli.py`, `loader.py`, `runner.py` (external benchmark support)
    - `backend/app/repositories/scan.py` (tenant listing and scan recovery)
    - `backend/app/services/report.py` (strict CSP meta tag in report templates)
    - `backend/tests/test_api_security.py` (tenant isolation regression tests)
    - `pyproject.toml` (ruff exclude update for benchmark fixtures)
  - *Untracked Components Included:*
    - `backend/app/api/v1/research.py`
    - `backend/tests/test_phase7_external_benchmark.py`
    - `evaluation/external_dataset/` (VAmPI benchmark cases and ground truth)
    - `evaluation/reports/combined/`, `external/`, `phase7/`
    - `frontend/` (React 19, TypeScript, Vite application and compiled `dist/` build)
    - `docs/release/` (`RC1_REPORT.md`, `RELEASE_NOTES_v1.0.0-rc.1.md`, `RELEASE_MANIFEST_v1.0.0-rc.1.md`)
- **Analyzer Freeze Verification:** `git diff 060e9a2 -- backend/app/analysis/` was strictly validated and contains **0 lines changed (100% frozen)**.
- **Phase 6 Ground Truth Verification:** `git diff HEAD -- evaluation/dataset/ evaluation/reports/phase6/` contains **0 lines changed (100% intact)**.

---

## 2. Release Package Metadata

- **Archive Filename:** `intelligent-api-security-analyzer-v1.0.0-rc.1.tar.gz`
- **Archive Path:** `dist/release/v1.0.0-rc.1/intelligent-api-security-analyzer-v1.0.0-rc.1.tar.gz`
- **Companion Checksum File:** `dist/release/v1.0.0-rc.1/intelligent-api-security-analyzer-v1.0.0-rc.1.tar.gz.sha256`
- **File Size:** `612,337 bytes` (0.58 MB)
- **Archive Member Count:** 398 files
- **Archive Root Directory Prefix:** `intelligent-api-security-analyzer-v1.0.0-rc.1/`
- **SHA-256 Checksum:**
  ```
  59eb5db70b7774d2b582a692b2dc543465c03d2db878e74a86312314b4d943f5
  ```

---

## 3. Dependency Lockfiles & Build Inputs

The release package is fully reproducible using pinned dependency manifests:
- **Backend Lockfile:** `uv.lock` (221 kB, pinning Python 3.14 dependencies including FastAPI 0.141, SQLAlchemy 2.0, Alembic 1.20, psycopg 3.2, tree-sitter 0.23).
- **Frontend Lockfile:** `frontend/package-lock.json` (pinning npm dependencies for React 19.2.8, TypeScript 6.0.2, Vite 8.3.4, Tailwind CSS 4.3.3, Recharts 3.10.1).
- **Frontend Production Build:** `frontend/dist/` (includes `index.html`, `assets/index-DM5rZgiP.js` [249.86 kB / 78.40 kB gzip], `assets/ResearchDashboardScreen-DF4W3Jc9.js` [389.49 kB / 110.55 kB gzip], and 14 other route chunks).
- **Database Schema Definitions:** `backend/alembic/versions/` (3 revisions establishing `scans`, `scan_results`, and `audit_events` tables).
- **Container Infrastructure:** `Dockerfile`, `docker-compose.yml` (PostgreSQL 18 service configured with local binding on `127.0.0.1:5432`).

---

## 4. Verification & Quality-Gate Outcomes

Verification was executed directly against the codebase using documented commands:

| Verification Suite | Exact Command | Execution Result |
|---|---|---|
| Backend Tests | `uv run pytest` | 203 passed, 0 failed in 13.25s |
| Frontend Tests | `cd frontend && npm test` | 15 passed across 3 test files in 7.60s |
| Backend Linting | `uv run ruff check .` | 0 errors |
| Backend Formatting | `uv run ruff format --check .` | 130 files formatted |
| Strict Type Checking | `uv run mypy backend/app backend/tests` | 0 issues across 111 source files |
| Database Migration Check | `uv run alembic check` | Aligned with models (no drift) |
| Dependency Vulnerabilities | `uv run pip-audit` | 0 known vulnerabilities |
| Static Security Analysis | `uv run bandit -r backend/app -ll` | 0 High, 0 Medium issues |
| Frontend Linting | `cd frontend && npx oxlint` | 0 errors across 24 files |
| Frontend Build | `cd frontend && npm run build` | Clean production build (16 chunks) |
| Archive Extraction Test | `tar -xzf <archive> -C <scratch_dir>` | Succeeded with 0 errors |
| Archive Secret Audit | Automated regex scan for private keys | 0 keys, certificates, or tokens |

---

## 5. Excluded Artifacts & Privacy Verification

The following files and directories are strictly excluded from the release archive:
- **Environment Secrets:** `.env` and all files containing usable production credentials.
- **Git Internals:** `.git/` directory and internal git metadata.
- **Dependencies:** `.venv/` (Python virtual environment) and `frontend/node_modules/`.
- **Build & Release Artifacts:** Top-level `dist/` directory (avoiding recursive packaging).
- **Caches & Temporary Files:** `__pycache__/`, `*.pyc`, `*.pyo`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `.coverage*`, `htmlcov/`, `.DS_Store`.
- **Runtime Scans & Logs:** `scratch/` directory and all runtime scan upload directories.

---

## 6. Documented Limitations & Epistemic Boundaries

1. **VAmPI / Connexion Architectural Limitation:** The AST analyzer targets `@app.get` / `@app.route` decorators. VAmPI's dynamic `operationId` routing results in 0 discovered source endpoints (`SOURCE_ONLY` recall = 0.0000). Retained honestly as a design boundary.
2. **Sample Size & Bootstrap Spread:** Small benchmark samples (n=24 baseline, n=12 external) yield wide bootstrap 95% confidence intervals.
3. **Static Analysis Scope:** Findings represent static-analysis evidence of policy discrepancies and potential vulnerabilities, not proof of runtime exploitability.
4. **Browser Automation Distinction:** Automated UI unit/integration tests and real HTTP proxy integration tests passed completely. Headless browser automation (Playwright) was not executed in the container due to blocked external binary downloads.
