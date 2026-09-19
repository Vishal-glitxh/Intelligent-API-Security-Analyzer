# Incident: Production Configuration & Startup Validation Failure

## Purpose
This runbook provides procedures for diagnosing and resolving application startup crashes caused by environment variable validation failures in `app/core/config.py`.

## Environment Model
- **Environment A: Local Host Development**: Reads `.env` file via Pydantic `Settings`. When `ENVIRONMENT=development`, a default insecure fallback `SESSION_SECRET` is permitted.
- **Environment B: Docker Compose Integration**: Reads environment variables passed to containers or from `.env`.
- **Environment C: Future Production Deployment**: Secret management platform injects immutable environment variables into application containers at launch.

## Impact
- Application fails immediately at startup with `pydantic.ValidationError` or `ValueError`.
- Uvicorn server cannot initialize or bind ports.
- Backend API is completely unavailable until valid configuration is supplied.

## Symptoms
- Container or console startup log displays configuration validation error:
  - `ValueError: SESSION_SECRET must be explicitly configured in production.`
  - `ValueError: Insecure or placeholder SESSION_SECRET is not allowed in production.`
  - `ValueError: SESSION_SECRET must be at least 32 characters in production environments.`
- Application process exits immediately with exit code `1`.

## Severity
P1 — Production configuration error blocking application startup.

## Immediate Actions
1. Inspect application startup logs for Pydantic validation errors (redacting any sensitive tokens):
   ```bash
   docker compose logs postgres --tail=50
   ```
2. Verify environment configuration state **without printing secret values**:
   ```bash
   # Inspect ENVIRONMENT setting safely
   echo "ENVIRONMENT=${ENVIRONMENT:-development}"

   # Verify presence and length of SESSION_SECRET without revealing value
   python3 -c "import os; s=os.getenv('SESSION_SECRET',''); print(f'SESSION_SECRET_SET={bool(s)}, LENGTH={len(s)}')"

   # Verify presence of DATABASE_URL without revealing credentials
   python3 -c "import os; d=os.getenv('DATABASE_URL',''); print(f'DATABASE_URL_SET={bool(d)}')"
   ```

> [!CAUTION]
> **Secret Redaction Required**: Never execute commands such as `grep SESSION_SECRET .env` or `echo $SESSION_SECRET` that print raw secret values to terminal output or log files.

## Diagnosis

### Step 1: Understand Settings Validation Logic
`app/core/config.py` enforces strict security constraints when `ENVIRONMENT=production`:
1. `session_secret` MUST be explicitly configured (not null or empty).
2. `session_secret` MUST NOT match known insecure placeholders:
   - `dev-insecure-session-secret-do-not-use-in-production`
   - `development-only-replace-me`
   - `secret`
   - `changeme`
   - `password`
3. `session_secret` MUST be at least 32 characters long.

### Step 2: Identify Validation Failure Cause
Review the startup traceback to determine the exact failure mode:
- **Missing Secret**: `SESSION_SECRET` is unset or empty in production.
- **Placeholder Secret**: `SESSION_SECRET` is set to a disallowed default string.
- **Insufficient Length**: `SESSION_SECRET` length is less than 32 characters.

Expected diagnostic status output (conceptual):
```text
ENVIRONMENT=production
SESSION_SECRET=configured
SESSION_SECRET_LENGTH=64
DATABASE_URL=configured
```

## Recovery

### Production / Staging Recovery Procedure
1. Generate a cryptographically secure 64-character hex secret:
   ```bash
   openssl rand -hex 32
   ```
2. Inject the generated secret into the production environment or `.env` file:
   ```env
   ENVIRONMENT=production
   SESSION_SECRET=<generated-64-character-hex-string>
   ```
3. Re-launch or recreate the application container:
   - For host process: Re-run Uvicorn.
   - For container execution: Recreate container to pick up updated environment settings:
     ```bash
     docker compose up -d --force-recreate
     ```

### Future Production Secret Management Recommendation
In production cloud environments, secrets should be injected securely via dedicated secret management platforms (e.g. AWS Secrets Manager, HashiCorp Vault, or GitHub Repository Secrets) during deployment, rather than stored in plain-text `.env` files.

## Validation
Confirm configuration validation succeeds:
1. Verify process or container health:
   ```bash
   curl -i http://localhost:8000/health
   curl -i http://localhost:8000/api/v1/health
   ```
   *Expected Result*: HTTP 200 OK `{"status":"ok"}`.
2. Run configuration test suite:
   ```bash
   uv run pytest backend/tests/test_config.py -v
   ```

## Rollback
- **Development Environment**: If working in local development or integration testing, ensure `ENVIRONMENT=development` is set so fallback development secrets are permitted.
- **Production Environment**: **No rollback to insecure or missing secrets is permitted.** Production deployments MUST supply a valid, >=32 character `SESSION_SECRET`.

## Escalation
Escalate to Security Lead or Operations if:
- Production credentials or session secrets are suspected of being committed to version control.
- Environment variable injection fails across container orchestration pipelines.

## Do Not
- **Do NOT** print, log, or commit actual `SESSION_SECRET` or `DATABASE_URL` values.
- **Do NOT** change `ENVIRONMENT=production` to `development` as a mechanism to bypass production validation.
- **Do NOT** use weak passwords or default placeholders in production configurations.

## Root Cause Follow-Up
1. Verify `.env` is included in `.gitignore`.
2. Ensure production CI/CD deployment pipelines validate secret length prior to container launch.
3. Keep `.env.example` updated with parameter names only (no live credentials).
