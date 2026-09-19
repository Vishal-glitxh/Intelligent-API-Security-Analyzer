# Incident: Application Server / API Service Outage

## Purpose
This runbook provides step-by-step procedures for diagnosing and recovering from a total or partial service outage of the Intelligent API Security Analyzer backend application.

## Environment Model
- **Environment A: Local Host Development**: Application runs directly on host via `uv run uvicorn app.main:app --app-dir backend`.
- **Environment B: Docker Compose Integration**: PostgreSQL runs in `postgres` container service; application runs on host or inside an optional application container.
- **Environment C: Future Production Deployment**: Application runs as a containerized service backed by managed secrets and dedicated database infrastructure.

## Impact
- Users and API clients cannot access the security analyzer API.
- Health probes `GET /health` or `GET /api/v1/health` return HTTP connection errors, `502 Bad Gateway`, or `503 Service Unavailable`.
- Ongoing static analysis requests fail or time out.

> [!NOTE]
> The application does **not** implement a root `GET /` route. A `404 Not Found` response on `GET /` is expected behavior and does **not** indicate a service outage.

## Symptoms
- Health probe `curl http://localhost:8000/health` or `curl http://localhost:8000/api/v1/health` fails or times out.
- Uvicorn application process exited, is stuck in a restart loop, or is unresponsive.
- Error logs indicate application startup crash, unhandled exception, or port binding conflict (`Address already in use`).

## Severity
P0 — Complete backend API service outage.

## Immediate Actions
1. Test system and API health probes:
   ```bash
   curl -i http://localhost:8000/health
   curl -i http://localhost:8000/api/v1/health
   ```
2. Verify running processes or Docker Compose services:
   - For Docker Compose services:
     ```bash
     docker compose ps postgres
     ```
   - For host-managed Uvicorn process:
     ```bash
     pgrep -fl uvicorn
     ```
3. Inspect recent application logs:
   - Host execution: Inspect Uvicorn console stdout/stderr.
   - Container execution:
     ```bash
     docker compose logs postgres --tail=100
     ```

## Diagnosis

### Step 1: Verify Health Endpoints
Execute health checks to confirm failure mode:
```bash
curl -i http://localhost:8000/health
```
- **Connection Refused**: Uvicorn process is down or listening on a different port.
- **HTTP 500 / 502 / 503**: Unhandled startup/runtime exception or downstream database connection failure.

### Step 2: Inspect Application Crash Logs
Locate crash tracebacks in application console or container logs. Common root causes:
- `ValueError: SESSION_SECRET must be explicitly configured in production.` → Refer to [configuration-failure.md](configuration-failure.md).
- `psycopg.OperationalError: could not connect to server` → Refer to [database-failure.md](database-failure.md).
- `OSError: [Errno 98] Address already in use` → Port 8000 is occupied by another process.

### Step 3: Check Process & Port Status
Check if port 8000 is occupied:
```bash
lsof -i :8000
```

## Recovery

### Scenario A: Transient Process or Container Crash
Restart the application process or container service:
- **Host Execution**: Re-launch Uvicorn:
  ```bash
  uv run uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000
  ```
- **Container Execution**: Restart container service:
  ```bash
  docker compose restart <app-service>
  ```

### Scenario B: Configuration, Environment, or Container Definition Change
Recreate the container instance to apply updated environment variables or definitions:
```bash
docker compose up -d --force-recreate <app-service>
```

### Scenario C: Code Base or Container Image Update
Rebuild container image artifacts and recreate service container:
```bash
docker compose up -d --build <app-service>
```

### Scenario D: Port 8000 Binding Conflict
Identify and terminate the conflicting process occupying port 8000:
```bash
lsof -i :8000
# Evaluate conflicting PID before termination
kill -15 <PID>
```
Re-start Uvicorn application process or container.

## Validation
Confirm operational recovery by verifying health endpoints and automated test suite:
1. Verify system health endpoint:
   ```bash
   curl -i http://localhost:8000/health
   ```
   *Expected Result*: HTTP 200 OK `{"status":"ok"}`.
2. Verify API v1 health endpoint:
   ```bash
   curl -i http://localhost:8000/api/v1/health
   ```
   *Expected Result*: HTTP 200 OK `{"status":"ok"}`.
3. Run automated health test suite:
   ```bash
   uv run pytest backend/tests/test_health.py -v
   ```

## Rollback

### Development / Local Environment Rollback
To roll back uncommitted or broken local changes:
```bash
git checkout <last-verified-commit>
uv sync --frozen
```

### Controlled Production Rollback Procedure
1. Identify the last verified stable Git revision or container image tag.
2. Redeploy that specific verified revision/image using the project's deployment pipeline.
3. Verify health endpoints (`GET /health` and `GET /api/v1/health`) after deployment completes.

## Escalation
If recovery procedures do not restore service within 15 minutes, escalate to Lead Maintainers with:
- System and API health check HTTP responses.
- Application exception traceback or last 200 lines of logs.
- Status of database connectivity and configuration settings.

## Do Not
- **Do NOT** treat a `404 Not Found` response on `GET /` as an outage.
- **Do NOT** set insecure session secrets or set `ENVIRONMENT=development` in production to bypass startup checks.
- **Do NOT** force-push unverified code directly to production branches.

## Root Cause Follow-Up
1. Review application logs to add missing error handling for unhandled exceptions.
2. Ensure automated health probes monitor `GET /health` and `GET /api/v1/health`.
3. Document any missing configuration requirements.
