# Incident: Database Connectivity & Migration Failure

## Purpose
This runbook provides diagnostic and operational recovery procedures when PostgreSQL 18 is unreachable, database connections fail, or Alembic schema migrations fail / become desynchronized.

## Environment Model
- **Environment A: Local Host Development**: Application on host connects to PostgreSQL on `localhost:5432`.
  Connection format: `postgresql+psycopg://<user>:<password>@localhost:5432/<database>`
- **Environment B: Docker Compose Integration**: Application container connects to PostgreSQL container `postgres:5432`.
  Connection format: `postgresql+psycopg://<user>:<password>@postgres:5432/<database>`
- **Environment C: Future Production Deployment**: Dedicated managed database instance with TLS and connection pooling.

## Impact
- Application database queries fail.
- Audit event logging (`audit_events` table) fails.
- Database session initialization (`get_db`) throws `psycopg.OperationalError`.
- Schema checks or migrations fail.

## Symptoms
- Application logs report database connectivity errors:
  `psycopg.OperationalError: could not connect to server: Connection refused`
  `sqlalchemy.exc.OperationalError: Connection refused`
- PostgreSQL container status is `Exited` or unresponsive.
- Alembic commands report connection failure or migration mismatch.

## Severity
P0 — Database connectivity outage or migration desynchronization.

## Immediate Actions
1. Check PostgreSQL container status:
   ```bash
   docker compose ps postgres
   ```
2. Verify PostgreSQL container readiness:
   ```bash
   docker compose exec postgres pg_isready -U analyzer -d api_security
   ```
3. Inspect PostgreSQL container logs:
   ```bash
   docker compose logs postgres --tail=100
   ```

## Diagnosis

### Step 1: Verify Database Connectivity
Execute readiness check or connection test:
```bash
docker compose exec postgres pg_isready -U analyzer -d api_security
```
- **Accepting connections**: PostgreSQL is up and accepting TCP connections.
- **No response / Connection refused**: PostgreSQL container is stopped or starting.

### Step 2: Verify Alembic Migration Revision State
Determine the current migration revision applied to the database:
```bash
uv run alembic current
```
Compare current applied revision against the target head revision:
```bash
uv run alembic heads
```
- If `current` matches `heads`, database schema revision is up to date.
- If `current` is behind `heads`, pending migrations need execution (`uv run alembic upgrade head`).

### Step 3: Check for Schema Drift
To check if the database schema differs from SQLAlchemy model definitions:
```bash
uv run alembic check
```
- **No new upgrade operations detected**: Database schema is perfectly synchronized with models.
- **Target database is not up to date / Operations detected**: Model code contains changes not yet reflected in migrations.

### Step 4: Verify Connection String Hostname
Verify `DATABASE_URL` matches the target runtime environment:
- **Host Execution**: Must target `localhost:5432`:
  `postgresql+psycopg://<user>:<password>@localhost:5432/<database>`
- **Container Execution**: Must target Compose service name `postgres:5432`:
  `postgresql+psycopg://<user>:<password>@postgres:5432/<database>`

> [!CAUTION]
> **Credential Safety**: Always redact usernames and passwords when inspecting or sharing `DATABASE_URL` environment variables.

## Recovery

### Scenario A: PostgreSQL Container Down or Unresponsive
1. Restart PostgreSQL container service:
   ```bash
   docker compose restart postgres
   ```
2. Wait for PostgreSQL readiness check to pass:
   ```bash
   docker compose exec postgres pg_isready -U analyzer -d api_security
   ```
3. Verify applied migration revision state:
   ```bash
   uv run alembic current
   ```

### Scenario B: Pending Schema Migrations
If `uv run alembic current` indicates applied schema is behind `heads`:
1. Apply pending schema migrations:
   ```bash
   uv run alembic upgrade head
   ```
2. Confirm migration revision status:
   ```bash
   uv run alembic current
   ```

### Scenario C: Corrupted Local Container Volume (DEVELOPMENT / TEST ONLY)
> [!CAUTION]
> **DEVELOPMENT / TEST ONLY**: The following command destroys the local PostgreSQL volume (`postgres_data`) and all stored data. NEVER run in production environments without explicit human approval and verified backups.

To reset corrupted local development database state:
```bash
docker compose down -v
docker compose up -d postgres
# Wait for readiness check
docker compose exec postgres pg_isready -U analyzer -d api_security
uv run alembic upgrade head
```

## Validation
Confirm database operational recovery:
1. Verify PostgreSQL container readiness:
   ```bash
   docker compose exec postgres pg_isready -U analyzer -d api_security
   ```
2. Verify Alembic migration revision state:
   ```bash
   uv run alembic current
   ```
3. Run database integration test suite:
   ```bash
   uv run pytest backend/tests/test_db.py -v
   ```
4. Verify application health probe:
   ```bash
   curl -i http://localhost:8000/health
   curl -i http://localhost:8000/api/v1/health
   ```

## Rollback & Migration Failure Handling
If an Alembic migration fails during execution:
1. Do **NOT** run generic `alembic downgrade` automatically in production.
2. Inspect migration failure logs to determine whether the failed migration was applied fully, partially, or not at all.
3. For migrations with a verified safe downgrade path, a controlled downgrade may be executed:
   ```bash
   # Migration-specific downgrade (only if safe downgrade path is verified)
   uv run alembic downgrade -1
   ```
4. If a partial schema change occurred without a safe downgrade path, restore from an approved database backup.

## Escalation
Escalate to Database Administrator or Lead Maintainers if:
- PostgreSQL fails to start due to storage volume corruption or disk full errors.
- Database migration failed mid-transaction and cannot be rolled back cleanly.

## Do Not
- **Do NOT** automatically execute `alembic downgrade -1` in production without verifying migration state.
- **Do NOT** execute `docker compose down -v` in production environments.
- **Do NOT** expose raw database credentials in logs or output.

## Root Cause Follow-Up
1. Verify database auto-restart policy (`restart: unless-stopped` in `docker-compose.yml`).
2. Ensure database migrations are tested against realistic schema states prior to release.
