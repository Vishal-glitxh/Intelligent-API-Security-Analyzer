from pathlib import Path

from app.analysis.context import AuthState
from app.analysis.source.flask import extract_flask_endpoints, normalize_flask_path
from app.analysis.source.parser import parse_source_file

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "source"


def test_flask_path_normalization() -> None:
    assert normalize_flask_path("/users/<user_id>") == "/users/{user_id}"
    assert normalize_flask_path("/items/<int:item_id>") == "/items/{item_id}"
    assert normalize_flask_path("/files/<path:file_path>") == "/files/{file_path}"
    assert normalize_flask_path("/<user_id>", prefix="/api/users") == "/api/users/{user_id}"


def test_flask_endpoint_extraction() -> None:
    path = FIXTURES_DIR / "flask_sample.py"
    mod = parse_source_file(path.read_text(encoding="utf-8"), str(path), "hash_flask")
    endpoints = extract_flask_endpoints(mod)

    assert len(endpoints) == 2
    paths = {e.path: e for e in endpoints}

    # Blueprint prefix applied + parameter normalized: /api/users/{user_id}
    assert "/api/users/{user_id}" in paths
    user_ep = paths["/api/users/{user_id}"]
    assert user_ep.method == "get"
    assert user_ep.auth_state == AuthState.AUTH_PRESENT
    assert len(user_ep.auth_evidence) >= 1
    assert "login_required" in user_ep.auth_evidence[0].message

    # /api/users/{item_id}/delete
    assert "/api/users/{item_id}/delete" in paths
    del_ep = paths["/api/users/{item_id}/delete"]
    assert del_ep.method == "delete"
    assert del_ep.auth_state == AuthState.AUTH_ABSENT_IN_ANALYZABLE_SCOPE
