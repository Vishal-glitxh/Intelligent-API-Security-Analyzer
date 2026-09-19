# Intelligent API Security Analyzer

Phase 1 foundation for a defensive, evidence-based REST API security analyzer.

## Local setup

Requirements: Python 3.14.x, uv, Docker.

```bash
uv sync
cp .env.example .env
uv run pytest
uv run ruff check .
uv run mypy backend/app
uv run uvicorn app.main:app --app-dir backend --reload
```

Start PostgreSQL:

```bash
docker compose up -d postgres
```

Health checks:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/health
```

The analysis core is intentionally independent of FastAPI and the database.
# Intelligent-API-Security-Analyzer
