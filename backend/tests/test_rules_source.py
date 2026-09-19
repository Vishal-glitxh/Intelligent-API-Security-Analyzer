from pathlib import Path

from app.analysis.context import AnalysisContext
from app.analysis.findings import Severity
from app.analysis.rules.source.hardcoded_secret import HardcodedSecretRule
from app.analysis.rules.source.missing_auth import SourceMissingAuthRule
from app.analysis.rules.source.missing_authz import SourceMissingAuthzRule
from app.analysis.source import normalize_source_tree
from app.analysis.source.loader import load_source_from_memory

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "source"


def _build_context(files: dict[str, str]) -> AnalysisContext:
    loaded = load_source_from_memory(files)
    tree = normalize_source_tree(loaded)
    return AnalysisContext(source=tree)


# ==============================================================================
# 1. API-SECRET-001: HardcodedSecretRule
# ==============================================================================


def test_secret_rule_positive() -> None:
    code = """
API_KEY = "sk_live_998877665544332211"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY9988776655"
"""
    ctx = _build_context({"config.py": code})
    rule = HardcodedSecretRule()
    findings = rule.analyze(ctx)

    assert len(findings) == 2
    f = findings[0]
    assert f.rule_id == "API-SECRET-001"
    assert f.severity in (Severity.CRITICAL, Severity.HIGH)
    assert f.confidence == 0.85
    assert "Potential Hardcoded Secret" in f.title
    assert "sk_...211" in f.evidence[0].message
    assert "sk_live_998877665544332211" not in f.evidence[0].message  # Value is redacted!


def test_secret_rule_negative() -> None:
    code = """
import os
API_KEY = os.getenv("API_KEY")
DATABASE_PASSWORD = os.environ.get("DB_PASS")
TEST_SECRET = "changeme"  # Placeholder keyword
"""
    ctx = _build_context({"config.py": code})
    rule = HardcodedSecretRule()
    findings = rule.analyze(ctx)

    # Safe environment lookups and placeholders do not generate findings
    assert len(findings) == 0


def test_secret_rule_edge_case() -> None:
    # Empty context without source
    ctx = AnalysisContext()
    rule = HardcodedSecretRule()
    assert rule.analyze(ctx) == []


def test_secret_rule_evidence_location() -> None:
    code = """
# Line 1
# Line 2
SECRET_KEY = "my_super_secret_production_key_123"
"""
    ctx = _build_context({"settings.py": code})
    rule = HardcodedSecretRule()
    findings = rule.analyze(ctx)

    assert len(findings) == 1
    ev = findings[0].evidence[0]
    assert ev.file == "settings.py"
    assert ev.line == 4
    assert ev.provenance == "source:settings.py:4"


# ==============================================================================
# 2. API-SOURCE-AUTH-001: SourceMissingAuthRule
# ==============================================================================


def test_source_auth_missing_positive() -> None:
    code = """
from fastapi import FastAPI
app = FastAPI()

@app.post("/items")
async def create_item():
    return {"status": "ok"}
"""
    ctx = _build_context({"main.py": code})
    rule = SourceMissingAuthRule()
    findings = rule.analyze(ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "API-SOURCE-AUTH-001"
    assert f.severity == Severity.HIGH
    assert f.confidence == 0.70
    assert "Potential Missing Recognizable Authentication Evidence" in f.title
    assert "POST /items" in f.title


def test_source_auth_missing_negative() -> None:
    code = """
from fastapi import FastAPI, Depends
app = FastAPI()

def get_current_user(): return {}

@app.get("/items")
async def list_items(user=Depends(get_current_user)):
    return []
"""
    ctx = _build_context({"main.py": code})
    rule = SourceMissingAuthRule()
    findings = rule.analyze(ctx)

    assert len(findings) == 0


def test_source_auth_missing_edge_case() -> None:
    ctx = AnalysisContext()
    rule = SourceMissingAuthRule()
    assert rule.analyze(ctx) == []


def test_source_auth_missing_evidence_location() -> None:
    code = """
from fastapi import FastAPI
app = FastAPI()

@app.delete("/items/{id}")
async def delete_item(id: str):
    pass
"""
    ctx = _build_context({"routes.py": code})
    rule = SourceMissingAuthRule()
    findings = rule.analyze(ctx)

    assert len(findings) == 1
    ev = findings[0].evidence[0]
    assert ev.file == "routes.py"
    assert ev.line is not None
    assert "DELETE /items/{id}" in ev.message


# ==============================================================================
# 3. API-SOURCE-AUTHZ-001: SourceMissingAuthzRule
# ==============================================================================


def test_source_authz_missing_positive() -> None:
    code = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/users/{user_id}")
async def get_user(user_id: str):
    # Lookup without authz check
    user = db.get("User", user_id)
    return user
"""
    ctx = _build_context({"users.py": code})
    rule = SourceMissingAuthzRule()
    findings = rule.analyze(ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "API-SOURCE-AUTHZ-001"
    assert f.severity == Severity.HIGH
    assert f.confidence == 0.65
    assert "Potential Missing Object-Level Authorization Evidence" in f.title
    assert "GET /users/{user_id}" in f.title


def test_source_authz_missing_negative() -> None:
    code = """
from fastapi import FastAPI, Depends, HTTPException
app = FastAPI()

@app.get("/users/{user_id}")
async def get_user(user_id: str, current_user=Depends(get_current_user)):
    if current_user["id"] != user_id:
        raise HTTPException(403)
    user = db.get("User", user_id)
    return user
"""
    ctx = _build_context({"users.py": code})
    rule = SourceMissingAuthzRule()
    findings = rule.analyze(ctx)

    # Protected by ownership comparison
    assert len(findings) == 0


def test_source_authz_missing_edge_case() -> None:
    ctx = AnalysisContext()
    rule = SourceMissingAuthzRule()
    assert rule.analyze(ctx) == []


def test_source_authz_missing_evidence_location() -> None:
    code = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/orders/{order_id}")
async def get_order(order_id: str):
    order = repo.find_by_id(order_id)
    return order
"""
    ctx = _build_context({"orders.py": code})
    rule = SourceMissingAuthzRule()
    findings = rule.analyze(ctx)

    assert len(findings) == 1
    ev = findings[0].evidence[0]
    assert ev.file == "orders.py"
    assert ev.line is not None
    assert "order_id" in ev.message
