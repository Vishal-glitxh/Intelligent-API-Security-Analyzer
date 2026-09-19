from pathlib import Path

from app.analysis.context import AuthState
from app.analysis.source.fastapi import extract_fastapi_endpoints
from app.analysis.source.parser import parse_source_file

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "source"


def test_fastapi_endpoint_extraction_vulnerable() -> None:
    path = FIXTURES_DIR / "fastapi_vulnerable.py"
    mod = parse_source_file(path.read_text(encoding="utf-8"), str(path), "hash_vuln")
    endpoints = extract_fastapi_endpoints(mod)

    assert len(endpoints) == 2
    paths = {e.path: e for e in endpoints}

    # /items (POST)
    assert "/items" in paths
    items_ep = paths["/items"]
    assert items_ep.method == "post"
    assert items_ep.auth_state == AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE
    assert len(items_ep.auth_evidence) == 0

    # /users/{user_id} (GET)
    assert "/users/{user_id}" in paths
    user_ep = paths["/users/{user_id}"]
    assert user_ep.method == "get"
    assert len(user_ep.parameters) == 1
    assert user_ep.parameters[0].name == "user_id"
    assert user_ep.parameters[0].is_path_param is True


def test_fastapi_endpoint_extraction_secure() -> None:
    path = FIXTURES_DIR / "fastapi_secure.py"
    mod = parse_source_file(path.read_text(encoding="utf-8"), str(path), "hash_sec")
    endpoints = extract_fastapi_endpoints(mod)

    assert len(endpoints) == 2
    paths = {e.path: e for e in endpoints}

    # Router prefix was applied: /secure + /users/{user_id}
    assert "/secure/users/{user_id}" in paths
    sec_user_ep = paths["/secure/users/{user_id}"]
    assert sec_user_ep.auth_state == AuthState.AUTH_PRESENT
    assert len(sec_user_ep.auth_evidence) >= 1
    assert "get_current_user" in sec_user_ep.auth_evidence[0].message
