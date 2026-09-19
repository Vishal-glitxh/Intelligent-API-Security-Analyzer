from pathlib import Path

from app.analysis.context import EvidenceCategory, EvidenceStrength
from app.analysis.source import normalize_source_tree
from app.analysis.source.loader import load_source_from_disk
from app.analysis.source.parser import parse_source_file
from app.analysis.source.secrets import extract_secrets, redact_secret

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "source"


def test_redact_secret() -> None:
    assert redact_secret("short") == "***"
    assert redact_secret("sk_live_1234567890abcdef") == "sk_...def"


def test_secrets_distinguishes_env_placeholder_and_hardcoded() -> None:
    path = FIXTURES_DIR / "fastapi_secure.py"
    mod = parse_source_file(path.read_text(encoding="utf-8"), str(path), "sec_hash")
    ev_list = extract_secrets(mod)

    # Should find configuration evidence for DATABASE_PASSWORD = os.getenv(...)
    env_ev = [e for e in ev_list if e.category == EvidenceCategory.CONFIGURATION]
    assert len(env_ev) == 1
    assert "DATABASE_PASSWORD" in env_ev[0].message
    assert env_ev[0].symbol == "DATABASE_PASSWORD"

    # Should find placeholder evidence for TEST_TOKEN = "changeme"
    placeholder_ev = [
        e
        for e in ev_list
        if e.category == EvidenceCategory.SECRET and e.strength == EvidenceStrength.WEAK
    ]
    assert len(placeholder_ev) == 1
    assert "placeholder" in placeholder_ev[0].message


def test_source_tree_extracts_evidence_chains() -> None:
    loaded = load_source_from_disk(FIXTURES_DIR)
    tree = normalize_source_tree(loaded)

    endpoints_by_path = {e.path: e for e in tree.endpoints}

    # Vulnerable FastAPI endpoint: /users/{user_id}
    assert "/users/{user_id}" in endpoints_by_path
    vuln_ep = endpoints_by_path[
        "users/{user_id}" if "users/{user_id}" in endpoints_by_path else "/users/{user_id}"
    ]
    # Has object access evidence but no authz evidence
    assert len(vuln_ep.object_access_evidence) >= 1
    assert "user_id" in vuln_ep.object_access_evidence[0].message
    assert len(vuln_ep.authz_evidence) == 0

    # Secure FastAPI endpoint: /secure/users/{user_id}
    assert "/secure/users/{user_id}" in endpoints_by_path
    sec_ep = endpoints_by_path["/secure/users/{user_id}"]
    # Has both object access and ownership authz evidence
    assert len(sec_ep.object_access_evidence) >= 1
    assert len(sec_ep.authz_evidence) >= 1
    assert any("Ownership comparison" in ev.message for ev in sec_ep.authz_evidence)

    # Tenant-isolated endpoint: /secure/items/{item_id}
    assert "/secure/items/{item_id}" in endpoints_by_path
    tenant_ep = endpoints_by_path["/secure/items/{item_id}"]
    assert len(tenant_ep.tenant_evidence) >= 1
    assert any(
        "Tenant-scoped" in ev.message or "tenant" in ev.message.lower()
        for ev in tenant_ep.tenant_evidence
    )
