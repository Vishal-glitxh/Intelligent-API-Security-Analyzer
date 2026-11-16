"""Compare bounded retrieval rankers on the unchanged RAG v2 relevance set."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

from app.services.local_ai import embed_local_texts, get_local_ai_status
from app.services.rag_assistant import (
    _QUERY_EXPANSIONS,
    _cosine,
    _documents_from_index,
    _features,
    _make_documents,
    _tokens,
    _unit_vector,
)
from app.services.rag_index import load_index

PROTOCOL_VERSION = "hybrid-rag-precision-experiment-v1"
DEFAULT_QUERY_FILE = Path(__file__).resolve().parents[3] / "evaluation/rag/v2/queries.json"
RANKING_CONFIGURATIONS = {
    "lexical_only": "BM25 order; retain positive BM25 scores; top five.",
    "semantic_only": "Embedding cosine order; retain cosine >= 0.30; top five.",
    "hybrid_rrf_k60": "Current reciprocal-rank fusion; top five after legacy eligibility.",
    "weighted_rank_70_30": (
        "0.70 normalized lexical rank + 0.30 normalized semantic rank; top five."
    ),
    "top3_rank_agreement": "Only documents in both component top threes; ordered by RRF.",
    "hybrid_cosine_min_050": "RRF order with cosine >= 0.50; top five; candidate policy.",
    "hybrid_cosine_min_055": "RRF order with cosine >= 0.55; top five.",
    "hybrid_cosine_min_060": "RRF order with cosine >= 0.60; top five.",
    "hybrid_cosine_min_065": "RRF order with cosine >= 0.65; top five.",
}


def _evaluate_queries(query_file: Path) -> dict[str, Any]:
    try:
        raw = query_file.read_bytes()
        manifest = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("RAG precision experiment query set is unavailable or malformed.") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("protocol_version") != "hybrid-rag-retrieval-v2"
        or not isinstance(manifest.get("queries"), list)
        or not manifest["queries"]
        or manifest.get("k") != 5
    ):
        raise ValueError("RAG precision experiment requires the versioned RAG v2 query set at k=5.")

    status = get_local_ai_status()
    if status.get("embedding_available") is not True:
        raise ValueError("A configured, installed local embedding model is required.")
    chunks, index = load_index(
        expected_model_id=str(status.get("embedding_model") or ""),
        expected_model_digest=str(status.get("embedding_model_digest") or "") or None,
        expected_embedding_dimensions=status.get("embedding_dimensions"),
    )
    if index.get("status") != "ready" or not chunks:
        raise ValueError("A compatible persistent semantic index is required.")

    rows: list[dict[str, Any]] = []
    for case in manifest["queries"]:
        if not isinstance(case, dict):
            raise ValueError("Invalid query case in RAG precision experiment.")
        query = case.get("query")
        findings = case.get("source_findings", [])
        expected = case.get("expected_relevant_source_ids")
        if (
            not isinstance(query, str)
            or not query.strip()
            or len(query) > 2000
            or not isinstance(findings, list)
            or not isinstance(expected, list)
            or any(not isinstance(item, str) for item in expected)
        ):
            raise ValueError("Invalid query metadata in RAG precision experiment.")

        dynamic_documents = _make_documents([], findings, [], [], include_knowledge=False)
        documents = dynamic_documents + _documents_from_index(chunks)
        requests = [query, *(doc.title + " " + doc.content for doc in dynamic_documents)]
        vectors = embed_local_texts(requests, status_data=status)
        if vectors is None or len(vectors) != len(requests):
            raise ValueError("Local query or scan-evidence embedding generation failed.")
        query_vector = _unit_vector(vectors[0])
        if query_vector is None:
            raise ValueError("Local query embedding is invalid.")

        features = [_features(doc.title + " " + doc.content) for doc in documents]
        query_tokens = Counter(_tokens(query))
        for token in tuple(query_tokens):
            for expanded in _QUERY_EXPANSIONS.get(token, ()):
                query_tokens[expanded] += query_tokens[token]
        document_frequency: Counter[str] = Counter()
        for document_features in features:
            document_frequency.update(document_features.keys())
        average_length = sum(sum(item.values()) for item in features) / max(1, len(features))
        count = len(documents)
        scored: list[dict[str, Any]] = []
        for index_in_documents, (document, document_features) in enumerate(
            zip(documents, features, strict=True)
        ):
            length = sum(document_features.values())
            bm25 = 0.0
            for token, weight in query_tokens.items():
                term_frequency = document_features.get(token, 0)
                if not term_frequency:
                    continue
                inverse_frequency = math.log1p(
                    (count - document_frequency[token] + 0.5) / (document_frequency[token] + 0.5)
                )
                denominator = term_frequency + 1.2 * (
                    1 - 0.75 + 0.75 * length / max(1.0, average_length)
                )
                bm25 += inverse_frequency * (term_frequency * 2.2 / denominator) * weight
            if index_in_documents < len(dynamic_documents):
                document_vector = _unit_vector(vectors[index_in_documents + 1])
            else:
                document_vector = document.embedding
            cosine = (
                max(0.0, _cosine(query_vector, document_vector))
                if document_vector is not None
                else 0.0
            )
            scored.append(
                {
                    "source_id": document.chunk_id or document.document_id,
                    "document_id": document.document_id,
                    "title": document.title,
                    "bm25_score": round(bm25, 6),
                    "semantic_cosine": round(cosine, 6),
                }
            )

        lexical = sorted(scored, key=lambda item: (-item["bm25_score"], item["source_id"]))
        semantic = sorted(scored, key=lambda item: (-item["semantic_cosine"], item["source_id"]))
        lexical_rank = {item["source_id"]: rank for rank, item in enumerate(lexical)}
        semantic_rank = {item["source_id"]: rank for rank, item in enumerate(semantic)}
        rrf_order = sorted(
            scored,
            key=lambda item: (
                -(
                    1 / (60 + lexical_rank[item["source_id"]])
                    + 1 / (60 + semantic_rank[item["source_id"]])
                ),
                item["source_id"],
            ),
        )
        weighted_order = sorted(
            scored,
            key=lambda item: (
                -(
                    0.70 * (1 - lexical_rank[item["source_id"]] / max(1, count - 1))
                    + 0.30 * (1 - semantic_rank[item["source_id"]] / max(1, count - 1))
                ),
                item["source_id"],
            ),
        )
        by_id = {item["source_id"]: item for item in scored}
        outputs = {
            "lexical_only": [item["source_id"] for item in lexical if item["bm25_score"] > 0][:5],
            "semantic_only": [
                item["source_id"] for item in semantic if item["semantic_cosine"] >= 0.30
            ][:5],
            "hybrid_rrf_k60": [
                item["source_id"]
                for item in rrf_order
                if item["bm25_score"] > 0 or item["semantic_cosine"] >= 0.30
            ][:5],
            "weighted_rank_70_30": [
                item["source_id"]
                for item in weighted_order
                if item["bm25_score"] > 0 or item["semantic_cosine"] >= 0.30
            ][:5],
            "top3_rank_agreement": [
                item["source_id"]
                for item in rrf_order
                if lexical_rank[item["source_id"]] < 3 and semantic_rank[item["source_id"]] < 3
            ][:5],
        }
        for threshold in (0.50, 0.55, 0.60, 0.65):
            name = f"hybrid_cosine_min_{int(threshold * 100):03d}"
            outputs[name] = [
                item["source_id"]
                for item in rrf_order
                if by_id[item["source_id"]]["semantic_cosine"] >= threshold
            ][:5]
        rows.append(
            {
                "query_id": case.get("query_id"),
                "intent": case.get("category"),
                "query": query,
                "expected_relevant_source_ids": expected,
                "component_rankings": {
                    "lexical_bm25": [item["source_id"] for item in lexical],
                    "semantic_cosine": [item["source_id"] for item in semantic],
                    "hybrid_rrf_k60": [item["source_id"] for item in rrf_order],
                },
                "component_scores": scored,
                "outputs_by_configuration": outputs,
            }
        )

    k = 5
    metrics: dict[str, Any] = {}
    for configuration in RANKING_CONFIGURATIONS:
        hits = relevant = retrieved_count = false_positive_count = false_positive_cases = 0
        abstentions = empty_label_results = 0
        precision_sum = 0.0
        misses: dict[str, list[str]] = {}
        for row in rows:
            retrieved = row["outputs_by_configuration"][configuration]
            expected_ids = set(row["expected_relevant_source_ids"])
            retrieved_ids = set(retrieved)
            true_positives = expected_ids & retrieved_ids
            false_positives = retrieved_ids - expected_ids
            false_negatives = expected_ids - retrieved_ids
            hits += len(true_positives)
            relevant += len(expected_ids)
            retrieved_count += len(retrieved)
            false_positive_count += len(false_positives)
            false_positive_cases += int(bool(false_positives))
            abstentions += int(not retrieved)
            empty_label_results += int(not expected_ids and bool(retrieved))
            precision_sum += len(true_positives) / k
            if false_negatives:
                misses[row["query_id"]] = sorted(false_negatives)
        metrics[configuration] = {
            "recall_at_5_micro": hits / relevant if relevant else None,
            "precision_at_5_macro_fixed_k": precision_sum / len(rows),
            "precision_among_returned_micro": hits / retrieved_count if retrieved_count else None,
            "relevant_retrieved": hits,
            "retrieved_source_count": retrieved_count,
            "false_positive_source_count": false_positive_count,
            "false_positive_query_count": false_positive_cases,
            "zero_relevance_queries_with_results": empty_label_results,
            "abstention_count": abstentions,
            "missed_relevant_sources": misses,
        }

    return {
        "protocol_version": PROTOCOL_VERSION,
        "query_set_protocol": manifest["protocol_version"],
        "query_set_sha256": hashlib.sha256(raw).hexdigest(),
        "k": 5,
        "model": {
            "embedding_model": status.get("embedding_model"),
            "embedding_model_digest": status.get("embedding_model_digest"),
            "dimensions": status.get("embedding_dimensions"),
        },
        "index": index,
        "metric_definitions": {
            "recall_at_5_micro": "Relevant IDs retrieved divided by all labeled relevant IDs.",
            "precision_at_5_macro_fixed_k": (
                "Mean over all queries, including zero-relevance controls, of true positives / 5."
            ),
            "precision_among_returned_micro": (
                "All true positives divided by all returned IDs; abstaining queries "
                "add no returned IDs."
            ),
        },
        "configurations": RANKING_CONFIGURATIONS,
        "metrics": metrics,
        "per_query": rows,
        "limitations": [
            "This small 17-query conformance set does not establish broad retrieval quality.",
            "The cosine threshold is specific to this model and index; it requires "
            "recalibration after either changes.",
            "The protocol evaluates retrieval labels, not answer groundedness or "
            "vulnerability confidence.",
            "No latency or memory instrumentation was used.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=f"Run {PROTOCOL_VERSION}")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--queries", type=Path, default=DEFAULT_QUERY_FILE)
    args = parser.parse_args()
    try:
        result = _evaluate_queries(args.queries)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"RAG precision experiment error: {exc}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{PROTOCOL_VERSION}: {args.output}")


if __name__ == "__main__":
    main()
