"""Deterministic, fixture-backed evaluation for hybrid RAG retrieval v1."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, cast

from app.services.rag_assistant import _make_documents, answer_scan_question

PROTOCOL_VERSION = "hybrid-rag-retrieval-v1"
DEFAULT_QUERY_FILE = Path(__file__).resolve().parents[3] / "evaluation/rag/v1/queries.json"


def evaluate_rag_protocol(query_file: Path = DEFAULT_QUERY_FILE) -> dict[str, Any]:
    """Measure deterministic retrieval, source-ID validity, and template support only."""
    manifest_bytes = query_file.read_bytes()
    manifest = json.loads(manifest_bytes)
    if not isinstance(manifest, dict) or manifest.get("protocol_version") != PROTOCOL_VERSION:
        raise ValueError("Invalid hybrid RAG evaluation protocol manifest.")
    cases = manifest.get("queries")
    k = manifest.get("k")
    if not isinstance(cases, list) or not cases or not isinstance(k, int) or k < 1:
        raise ValueError("Invalid hybrid RAG evaluation query set.")

    hits = relevant_total = precision_sum = 0.0
    precision_cases = recall_cases = 0
    valid_source_ids = returned_source_ids = 0
    supported_answers = 0
    abstention_cases = abstention_passes = 0
    fallback_cases = external_network_flags = 0
    details: list[dict[str, Any]] = []
    failure_categories: dict[str, int] = {}

    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Invalid hybrid RAG evaluation case.")
        query = str(case.get("query", ""))
        relevant = set(cast(list[str], case.get("relevant_source_ids", [])))
        source_findings = cast(list[dict[str, Any]], case.get("source_findings", []))
        sources = _make_documents([], source_findings, [], [])
        corpus_ids = {source.document_id for source in sources}
        if not relevant.issubset(corpus_ids):
            raise ValueError("Evaluation query references an unknown retrieval source ID.")

        response = answer_scan_question(
            query,
            spec_findings=[],
            source_findings=source_findings,
            correlated_findings=[],
            matched_endpoints=[],
            limit=k,
            local_ai_status={
                "status": "Unavailable",
                "embedding_available": False,
                "retrieval_available": True,
            },
        )
        returned = [str(source["id"]) for source in response["sources"]]
        retrieved = set(returned)
        found = len(relevant & retrieved)
        hits += found
        if relevant:
            recall_cases += 1
            relevant_total += len(relevant)
            precision_cases += 1
            precision_sum += found / k
        valid_source_ids += sum(source_id in corpus_ids for source_id in returned)
        returned_source_ids += len(returned)

        support_mode = case.get("support_mode")
        if support_mode == "finding":
            expected_fragments = cast(list[str], case.get("expected_answer_fragments", []))
            supported = bool(relevant & retrieved) and all(
                fragment in response["answer"] for fragment in expected_fragments
            )
        elif support_mode == "guidance":
            supported = bool(relevant & retrieved) and (
                "Treat these sources as review guidance" in response["answer"]
            )
        elif support_mode == "abstention":
            abstention_cases += 1
            supported = not response["sources"] and response["answer"].startswith(
                "No relevant scan evidence or security guidance matched"
            )
            abstention_passes += int(supported)
        else:
            raise ValueError("Invalid support mode in hybrid RAG evaluation case.")
        supported_answers += int(supported)
        if not supported:
            failure_categories["unsupported_or_missed_answer"] = (
                failure_categories.get("unsupported_or_missed_answer", 0) + 1
            )
        if any(source_id not in corpus_ids for source_id in returned):
            failure_categories["invalid_source_id"] = (
                failure_categories.get("invalid_source_id", 0) + 1
            )
        fallback_cases += int(response["retrieval"] == "local_hybrid_bm25_hashed_vector")
        external_network_flags += int(response["external_network_used"])
        details.append(
            {
                "query_id": case.get("query_id"),
                "expected_source_ids": sorted(relevant),
                "retrieved_source_ids": returned,
                "relevant_hits_at_k": found,
                "source_ids_valid": all(source_id in corpus_ids for source_id in returned),
                "answer_supported_by_protocol": supported,
                "abstained": not response["sources"],
            }
        )

    return {
        "protocol_version": PROTOCOL_VERSION,
        "query_set_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "query_count": len(cases),
        "k": k,
        "retrieval": {
            "recall_at_k": hits / relevant_total if relevant_total else None,
            "precision_at_k": precision_sum / precision_cases if precision_cases else None,
            "queries_with_relevant_sources": recall_cases,
        },
        "retrieved_source_id_validity": {
            "valid": valid_source_ids,
            "total": returned_source_ids,
            "rate": valid_source_ids / returned_source_ids if returned_source_ids else 1.0,
        },
        "deterministic_template_support": {
            "supported": supported_answers,
            "total": len(cases),
            "rate": supported_answers / len(cases),
        },
        "abstention": {
            "passed": abstention_passes,
            "total": abstention_cases,
            "rate": abstention_passes / abstention_cases if abstention_cases else None,
        },
        "fallback": {
            "lexical_hashed_vector_cases": fallback_cases,
            "total": len(cases),
            "external_network_calls": external_network_flags,
        },
        "latency": {"status": "not_measured"},
        "failure_categories": dict(sorted(failure_categories.items())),
        "cases": details,
        "limitations": [
            "This fixed set evaluates the deterministic retrieval and answer template only.",
            "It does not evaluate Ollama-generated answer groundedness or broad security "
            "detection.",
            "Expected source IDs are manually reviewed protocol labels, not LLM-generated "
            "ground truth.",
            "Latency and resource usage are not measured by this protocol.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=f"Run {PROTOCOL_VERSION}")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--queries", type=Path, default=DEFAULT_QUERY_FILE)
    args = parser.parse_args()
    result = evaluate_rag_protocol(args.queries)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{PROTOCOL_VERSION}: {args.output}")


if __name__ == "__main__":
    main()
