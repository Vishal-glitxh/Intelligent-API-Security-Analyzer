import json
import urllib.error
import urllib.request
from typing import Any, cast

import pytest
from app.core.config import settings
from app.services import local_ai


def test_local_ai_status_detects_installed_and_selected_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "local_ai_enabled", True)
    monkeypatch.setattr(settings, "ollama_model", "qwen2.5:3b")
    monkeypatch.setattr(settings, "ollama_embedding_model", "nomic-embed-text:latest")
    monkeypatch.setattr(
        local_ai,
        "_request_json",
        lambda path, **kwargs: {
            "models": [
                {"name": "qwen2.5:3b"},
                {"name": "nomic-embed-text:latest"},
            ]
        },
    )

    status = local_ai.get_local_ai_status()

    assert status["status"] == "Available"
    assert status["model_name"] == "qwen2.5:3b"
    assert status["embedding_available"] is True
    assert len(status["available_models"]) == 2


def test_local_ai_status_is_disabled_without_probing_ollama(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "local_ai_enabled", False)
    monkeypatch.setattr(
        local_ai,
        "_request_json",
        lambda path, **kwargs: (_ for _ in ()).throw(AssertionError("must not probe")),
    )

    assert local_ai.get_local_ai_status()["status"] == "Disabled"


def test_ollama_connection_failure_keeps_lexical_retrieval_and_scan_isolation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.rag_assistant import answer_scan_question

    monkeypatch.setattr(settings, "local_ai_enabled", True)
    calls: list[str] = []

    def unavailable(path: str, **kwargs: object) -> dict[str, Any]:
        calls.append(path)
        raise urllib.error.URLError("local Ollama is not running")

    monkeypatch.setattr(local_ai, "_request_json", unavailable)
    status_data = local_ai.get_local_ai_status()
    assert status_data["status"] == "Unavailable"
    assert status_data["retrieval_available"] is True

    result = answer_scan_question(
        "Which book endpoint lacks ownership checks?",
        spec_findings=[],
        source_findings=[
            {
                "rule_id": "API-AUTHZ-001",
                "title": "Book lookup lacks an ownership check",
                "severity": "high",
                "endpoint": "GET /books/{book_id}",
                "rationale": "The caller-controlled book id is used without comparing ownership.",
                "remediation": "Check that the authenticated user owns the book.",
                "evidence": [],
            }
        ],
        correlated_findings=[],
        matched_endpoints=[],
        local_ai_status=status_data,
    )
    explanation = local_ai.generate_local_explanation(
        "Which book endpoint lacks ownership checks?",
        result["sources"],
        status_data=status_data,
    )

    assert "Book lookup lacks an ownership check" in result["answer"]
    assert any(source["source_type"] == "scan_finding" for source in result["sources"])
    assert result["external_network_used"] is False
    assert explanation is None
    assert calls == ["/api/tags"]


def test_local_generation_redacts_context_and_validates_citations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(settings, "local_ai_max_context_chars", 300)

    def fake_request(path: str, payload: dict[str, Any], **kwargs: object) -> dict[str, Any]:
        captured.update(payload)
        return {
            "response": json.dumps(
                {
                    "explanation": "The handler has a potential authentication gap.",
                    "recommendations": ["Review the route guard."],
                    "cited_source_ids": ["source-1"],
                }
            )
        }

    monkeypatch.setattr(local_ai, "_request_json", fake_request)
    result = local_ai.generate_local_explanation(
        "Review the API",
        [
            {
                "id": "source-1",
                "title": "Potential missing authentication",
                "excerpt": "password=supersecret evidence",
                "citation": "source file: api.py:8",
            }
        ],
        status_data={"status": "Available", "model_name": "local-test"},
    )

    assert result is not None
    assert result.cited_source_ids == ["source-1"]
    assert "supersecret" not in captured["prompt"]
    assert "untrusted data" in captured["system"]
    assert captured["options"]["num_predict"] <= 320


def test_local_generation_rejects_unknown_citation_and_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        local_ai,
        "_request_json",
        lambda path, payload, **kwargs: {
            "response": json.dumps(
                {
                    "explanation": "A claim without a valid source.",
                    "recommendations": [],
                    "cited_source_ids": ["invented-source"],
                }
            )
        },
    )
    result = local_ai.generate_local_explanation(
        "Question",
        [{"id": "source-1", "excerpt": "Evidence"}],
        status_data={"status": "Available", "model_name": "local-test"},
    )
    assert result is None


def test_secret_redactor_handles_bearer_and_key_values() -> None:
    value = "Authorization: Bearer abc.def API_KEY=supersecret password=hunter2"
    redacted = local_ai.redact_for_model(value)
    assert "abc.def" not in redacted
    assert "supersecret" not in redacted
    assert "hunter2" not in redacted


def test_ollama_redirects_are_rejected_before_prompt_can_leave_local_endpoint() -> None:
    from urllib.request import Request

    with pytest.raises(urllib.error.HTTPError, match="Ollama redirects are disabled"):
        local_ai._RejectRedirects().redirect_request(
            Request("http://127.0.0.1:11434/api/generate"),
            None,
            302,
            "Found",
            {},
            "https://example.invalid/collect",
        )


def test_ollama_http_client_ignores_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[object] = []

    class FakeResponse:
        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def read(self, size: int) -> bytes:
            return b'{"status":"ok"}'

    class FakeOpener:
        def open(self, request: object, timeout: float) -> FakeResponse:
            return FakeResponse()

    def build_opener(*handlers: object) -> FakeOpener:
        captured.extend(handlers)
        return FakeOpener()

    monkeypatch.setattr(urllib.request, "build_opener", build_opener)
    response = local_ai._request_json("/api/tags")

    proxy = next(
        handler for handler in captured if isinstance(handler, urllib.request.ProxyHandler)
    )
    assert cast(Any, proxy).proxies == {}
    assert any(isinstance(handler, local_ai._RejectRedirects) for handler in captured)
    assert response == {"status": "ok"}


def test_non_finite_ollama_embeddings_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "local_ai_enabled", True)
    monkeypatch.setattr(settings, "ollama_embedding_model", "local-embed")
    monkeypatch.setattr(
        local_ai,
        "_request_json",
        lambda *args, **kwargs: {"embeddings": [[float("nan")]]},
    )

    result = local_ai.embed_local_texts(
        ["bounded sample"],
        status_data={"embedding_model": "local-embed", "embedding_available": True},
    )

    assert result is None


def test_local_development_access_works_without_token_only_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.main import app
    from fastapi.testclient import TestClient

    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "local_dev_auth_bypass", True)
    response = TestClient(app).get("/api/v1/ai/session")
    assert response.status_code == 200
    assert response.json() == {"authenticated": True, "auth_mode": "local-development"}

    monkeypatch.setattr(settings, "environment", "production")
    response = TestClient(app).get("/api/v1/ai/session")
    assert response.status_code == 401
