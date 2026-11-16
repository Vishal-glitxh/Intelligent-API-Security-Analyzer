# IASA Backend Regression Test Baseline

**Run date:** 2026-11-13  
**Repository:** `/Users/vishalsuhas/Desktop/Intelligent API Security Analyzer`  
**Branch / HEAD:** `main` / `abd385b`  
**Scope:** Complete backend pytest suite with coverage and isolated Alembic verification. No application code, migrations, or tests were changed for this task.

## 1. Executive summary

The complete backend suite collected **403 tests**. The initial run had **392 passed and 11 failed** because the repository `.env` setting `LOCAL_DEV_AUTH_BYPASS=true` leaked into production-mode `Settings` tests. The failures occurred at the authentication-bypass validator before each test reached the configuration condition it intended to verify. After explicitly setting `LOCAL_DEV_AUTH_BYPASS=false` in the test process (without changing `.env` or application defaults), the one corrected full run passed **403/403**, with **0 failures, 0 skips, and 0 errors** in **10.11 seconds**.

Coverage was **86.2%** (5,074 of 5,886 statements). Two upstream deprecation warnings remain. Alembic upgrade, current revision, and consistency checks passed on a disposable PostgreSQL database created for this run.

The existing demo PostgreSQL container remained healthy and its volume was not mounted or accessed. The demo API container was already exited before this task and remained exited; no claim of demo API health or runtime verification is made. The disposable test project, its volume, and temporary credentials/logs were removed after verification.

## 2. Test infrastructure and why the suite was previously blocked

### Project test configuration

- `pyproject.toml` sets `testpaths = ["backend/tests"]`, `addopts = "-q --strict-markers"`, and strict MyPy settings. The documented backend command is `uv run pytest -v --cov=backend/app --cov-report=term-missing`.
- The CI workflow `.github/workflows/ci.yml` starts PostgreSQL 18, sets both `TEST_DATABASE_URL` and `DATABASE_URL` to `api_security_test`, applies Alembic migrations, and runs the full coverage suite.
- `backend/tests/conftest.py` checks `TEST_DATABASE_URL` during `pytest_configure`, before test modules import. It requires a PostgreSQL URL with database name ending `_test` or `_testing`, then sets `DATABASE_URL` and `ENVIRONMENT=testing`.
- `backend/app/db/session.py` creates the SQLAlchemy engine from `settings.database_url` at import time. `backend/alembic/env.py` similarly takes its URL from application settings.
- `pyproject.toml` has no configured coverage threshold. Coverage was requested using the documented `pytest-cov` options.

The suite was previously blocked because `TEST_DATABASE_URL` was absent and no dedicated disposable PostgreSQL target existed. Running persistence tests against the existing demo database would violate the test guard and preservation requirements. For this run, a disposable target was safely provisioned instead.

## 3. Disposable database and isolation evidence

Created a distinct Compose project `iasa-backend-test-20261113-7d2e91` using the already available `postgres:18` image. The project created only:

- Container: `iasa-backend-test-20261113-7d2e91-postgres-1`
- Database: `iasa_backend_test`
- Test user: `iasa_test`
- Dedicated named volume: `iasa-backend-test-20261113-7d2e91_testdata`
- Host port: `127.0.0.1:55439` mapped to container port `5432`

Before tests, `docker inspect` confirmed the new container’s Compose project label, running/healthy status, loopback-only host binding, and mount to the project-specific test volume. `docker port` reported `5432/tcp -> 127.0.0.1:55439`. A query inside that container returned database `iasa_backend_test` and user `iasa_test`. The successful PostgreSQL-backed tests and Alembic operations used `TEST_DATABASE_URL` and `DATABASE_URL` targeting that host port and database. The temporary password is intentionally not recorded.

Pre-run demo inventory showed PostgreSQL container ID `27ccd5818333`, healthy and loopback-bound at `127.0.0.1:5432`, mounted to `iasa-demo-20261030_postgres_data`. The demo API container `iasa-demo-20261030-api-1` was already `Exited (143) 12 days ago`. The test project did not use port 5432, the demo volume, or the demo database. After cleanup, the test container, test network, and test volume were absent; the demo PostgreSQL container ID/status/volume remained unchanged and healthy. The demo API remained exited and was not restarted.

## 4. Exact commands and outcomes

### Disposable database setup

A temporary Compose file and private temporary env file were created under `/tmp/iasa-pg-regression.SHLZMF`. The env file contained a newly generated test-only password and was removed at cleanup. The relevant commands were:

```bash
docker compose --project-name iasa-backend-test-20261113-7d2e91 \
  --env-file <temporary-private-env-file> \
  -f <temporary-compose-file> up -d

docker inspect iasa-backend-test-20261113-7d2e91-postgres-1 \
  --format 'status={{.State.Status}} health={{.State.Health.Status}} project={{index .Config.Labels "com.docker.compose.project"}} ports={{json .NetworkSettings.Ports}} mounts={{range .Mounts}}{{.Name}}:{{.Destination}} {{end}}'

docker exec iasa-backend-test-20261113-7d2e91-postgres-1 \
  psql -U iasa_test -d iasa_backend_test -Atc \
  'select current_database(), current_user, inet_server_port()'
```

Observed: container healthy; project label and dedicated volume were correct; published address was `127.0.0.1:55439`; database/user identity was correct.

### Migration verification

The test process loaded the private temporary env file, constructed `TEST_DATABASE_URL` for `127.0.0.1:55439/iasa_backend_test`, set `DATABASE_URL` to the same value, and used `ENVIRONMENT=testing`.

```bash
uv run --no-sync alembic upgrade head
uv run --no-sync alembic current
uv run --no-sync alembic check
```

Results:

- Upgrade succeeded through revisions `339bbefe3ccc`, `3e61a4f881e2`, and `7b8e1a9c3f2d`.
- Current revision: `7b8e1a9c3f2d (head)`.
- Consistency check: `No new upgrade operations detected.`
- The suite’s database tests also passed against this same isolated database.

### Full backend suite

The first run used the documented suite and coverage options with the isolated database URL, `ENVIRONMENT=testing`, and a temporary `COVERAGE_FILE`. It returned 11 configuration-test failures due to `.env` contamination described below. No tests were skipped and no migrations or tests targeted the demo database.

After establishing that root cause, the single corrected full run added the process-only setting `LOCAL_DEV_AUTH_BYPASS=false` and used a separate temporary coverage file:

```bash
uv run --no-sync pytest -v --cov=backend/app --cov-report=term-missing
```

Environment for the command: `TEST_DATABASE_URL` and `DATABASE_URL` pointed to the disposable `iasa_backend_test` database on `127.0.0.1:55439`; `ENVIRONMENT=testing`; `LOCAL_DEV_AUTH_BYPASS=false`; `COVERAGE_FILE` pointed under the temporary test directory. The password value is omitted.

Result: **403 passed, 0 failed, 0 skipped, 0 errors, 2 warnings, 10.11 seconds**. The first diagnostic run took 10.37 seconds and ended with 392 passed/11 failed; it was not counted as a passing baseline.

## 5. Test results and coverage

The suite exercised configuration, database/session behavior, API routes, authentication and tenant checks, OpenAPI parsing/validation, source static analysis, deterministic rules/correlation, report generation, uploads, worker lifecycle/recovery, RAG index/retrieval/assistant behavior, and evaluation protocol tests. No scanner benchmark or live model generation was launched.

### Coverage by major module

| Module area | Covered / statements | Coverage |
|---|---:|---:|
| Analysis | 2,000 / 2,156 | 92.8% |
| API | 200 / 208 | 96.2% |
| Core | 205 / 233 | 88.0% |
| Database | 57 / 57 | 100.0% |
| Evaluation | 1,317 / 1,808 | 72.8% |
| Jobs | 92 / 114 | 80.7% |
| Main app | 55 / 55 | 100.0% |
| Middleware | 35 / 36 | 97.2% |
| Repositories | 103 / 106 | 97.2% |
| Schemas | 48 / 48 | 100.0% |
| Services | 962 / 1,065 | 90.3% |
| **Total** | **5,074 / 5,886** | **86.2%** |

Coverage output was written under `/tmp/iasa-pg-regression.SHLZMF`, not to a repository `.coverage` file. No project coverage threshold is configured.

## 6. Initial failures and diagnosis

All 11 initial failures were in `backend/tests/test_config.py`. The common actual exception was:

```text
Value error, LOCAL_DEV_AUTH_BYPASS cannot be enabled in production.
```

The test `Settings` constructors for production cases omit `local_dev_auth_bypass=False` and, unlike the `settings_without_env` helper, do not pass `_env_file=None`. The project settings load `.env`; the local `.env` has `LOCAL_DEV_AUTH_BYPASS=true`. Thus the validator rejects production construction at `backend/app/core/config.py:78-79` before the individual case can test its intended condition. This is a **test environment/configuration isolation issue**, not evidence that production accepts the bypass. The rerun set the process environment to false, did not edit `.env`, and all tests passed.

| Failed test | Test location | Intended assertion blocked by earlier bypass validation |
|---|---|---|
| `test_supported_environment_labels_are_normalized` | `backend/tests/test_config.py:24-38` | Production label normalization construction unexpectedly raised. |
| `test_production_requires_session_secret` | `backend/tests/test_config.py:56-64` | Expected missing-session-secret validation; got bypass validation. |
| `test_production_rejects_short_secret` | `backend/tests/test_config.py:67-73` | Expected short-secret validation; got bypass validation. |
| `test_production_rejects_insecure_placeholders` | `backend/tests/test_config.py:76-82` | Expected placeholder-secret validation; got bypass validation. |
| `test_production_rejects_the_builtin_development_fallback_secret` | `backend/tests/test_config.py:85-96` | Expected placeholder rejection and non-echo; got bypass validation first. |
| `test_production_accepts_secure_secret` | `backend/tests/test_config.py:99-107` | Valid production construction unexpectedly raised. |
| `test_production_requires_api_access_token` | `backend/tests/test_config.py:110-118` | Expected missing-token validation; got bypass validation. |
| `test_production_rejects_the_development_api_token_without_echoing_it` | `backend/tests/test_config.py:127-140` | Expected development-token rejection and non-echo; got bypass validation first. |
| `test_production_rejects_the_development_database_url_without_echoing_it` | `backend/tests/test_config.py:142-153` | Expected development-database rejection and non-echo; got bypass validation first. |
| `test_production_accepts_private_ollama_service_name` | `backend/tests/test_config.py:175-185` | Valid production construction unexpectedly raised. |
| `test_production_rejects_unapproved_remote_ollama_host` | `backend/tests/test_config.py:188-199` | Expected remote-Ollama-host validation; got bypass validation first. |

### Warnings

Two dependency deprecation warnings occurred:

1. Starlette’s `TestClient` integration warns that using `httpx` is deprecated and recommends `httpx2`.
2. Starlette warns that `anyio.abc.BlockingPortal` is deprecated in favor of `anyio.from_thread.BlockingPortal`.

They did not fail tests. No tests were skipped, and the final run had no collection or execution errors.

## 7. Blocked and unverified checks

- **Demo API runtime:** not healthy/running at the start (`Exited (143) 12 days ago`) and remained untouched. No demo API health or end-to-end scan claim is made.
- **Demo database scan records:** not queried. The demo database was not accessed, so its records are presumed preserved based on the absence of any connection or volume operation, not independently inspected.
- **Other checks:** this task was limited to the backend suite and migration checks; it did not rerun frontend, lint/type/security checks, Docker build, scanner benchmarks, RAG evaluations, Ollama, or browser workflows.
- **Version control/CI:** no CI job was triggered.

## 8. Recommendations

1. Make configuration tests independent of developer `.env` values by using `_env_file=None` consistently or explicitly setting all security-relevant fields in test helpers. This is a test isolation fix; no source change was made here.
2. Keep the `TEST_DATABASE_URL` guard before test imports. Continue to require a disposable PostgreSQL database whose name ends `_test` or `_testing`.
3. Resolve the Starlette/httpx and AnyIO deprecation warnings through dependency compatibility planning; do not treat them as current functional failures.
4. The 72.8% evaluation-module coverage is lower than other major areas. Prioritize tested behavior only where it supports maintained evaluation protocols; do not change frozen benchmark semantics to raise coverage.
5. Treat the demo API as unavailable until separately verified. No restart was authorized or performed in this task.

## 9. Git and protected-artifact preservation

At task start, branch was `main`, HEAD `abd385b`. Existing modifications and untracked project work were retained. No application source, migration, fixture, or test file was edited. Temporary coverage data, logs, Compose configuration, and generated credentials were stored under `/tmp/iasa-pg-regression.SHLZMF` and removed after the test environment was torn down. The only new repository artifact from this task is this report.

The isolated test container, network, and named volume were removed using the exact Compose project name. No images were removed. The existing demo PostgreSQL container `27ccd5818333` remained healthy, loopback-bound on port 5432, with volume `iasa-demo-20261030_postgres_data`; the demo API container remained in its pre-existing exited state. No demo DB connection or scan-record query occurred.

`git diff --check` passed. The frozen tracked paths `backend/app/analysis/`, `evaluation/dataset/`, `evaluation/external_dataset/`, and `evaluation/reports/` had no diff. The following recorded hashes were unchanged:

| Artifact | SHA-256 |
|---|---|
| Groundedness v1 review-ready manifest | `b8df7483d84cd9e0d8fa86fb4291ee50f1948ad4f1cc94f6b9efedcf6dedf18` |
| Immutable groundedness r2 answers | `655b706267a57e941c2e5f6258a53c971b13705ac6f1bfd75195ac4357f114f9` |
| Immutable groundedness r2 report | `26c470b9838fa51753c031b0f0654cf8b7e1caebb13ae851c4bb5c4daa22ed20` |
| Groundedness v2 review template | `1e0f498c44507da64921058c6164e2bece914b8761ea38a6442cabd70aa9670e` |
| Groundedness v2 metrics | `ee213e4952f6a963fea37cdb0f9c70fb304e83163fb24725c9d95bd76cb0628e` |
| RAG index | `acf1537324fad31a8452870762342dfb87656f3f0c9ec7c13ec5560ade2291df` |

No historical benchmark or RAG candidate was regenerated. The prior dirty worktree was preserved; the requested baseline report is the only additional repository file.
