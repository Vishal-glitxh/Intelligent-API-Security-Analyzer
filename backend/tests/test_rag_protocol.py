from app.evaluation.rag_protocol_v1 import evaluate_rag_protocol


def test_rag_retrieval_protocol_is_reproducible_and_separate() -> None:
    first = evaluate_rag_protocol()
    second = evaluate_rag_protocol()

    assert first == second
    assert first["protocol_version"] == "hybrid-rag-retrieval-v1"
    assert first["query_count"] == 8
    assert first["retrieval"]["recall_at_k"] == 1.0
    assert first["retrieved_source_id_validity"]["rate"] == 1.0
    assert first["deterministic_template_support"]["rate"] == 1.0
    assert first["abstention"]["rate"] == 1.0
    assert first["fallback"]["external_network_calls"] == 0
    assert first["failure_categories"] == {}
    assert first["latency"]["status"] == "not_measured"
    assert any("does not evaluate Ollama-generated" in item for item in first["limitations"])
