"""Broader retrieval evaluation and human-reviewed claim-support scoring for RAG v2."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

from app.services.local_ai import get_local_ai_status
from app.services.rag_assistant import (
    BASELINE_RANKING_POLICY,
    DEFAULT_RANKING_POLICY,
    _make_documents,
    answer_scan_question,
)
from app.services.rag_index import load_index

PROTOCOL_VERSION = "hybrid-rag-retrieval-v2"
CLAIM_REVIEW_VERSION = "hybrid-rag-claim-review-v1"
DEFAULT_QUERY_FILE = Path(__file__).resolve().parents[3] / "evaluation/rag/v2/queries.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_QUERY_SET_BYTES = 4 * 1024 * 1024
MAX_QUERY_CASES = 128


def _evaluate_claim_reviews(
    review_file: Path | None,
    retrieved_by_query: dict[str, list[str]],
) -> dict[str, Any]:
    if review_file is None:
        return {
            "status": "not_provided",
            "reviewed_claims": 0,
            "supported_claim_citation_rate": None,
            "unsupported_claim_rate": None,
            "limitation": (
                "No human-reviewed model answer set was supplied; groundedness is unmeasured."
            ),
        }
    try:
        with review_file.open("rb") as source:
            raw = source.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("claim review file is too large")
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Invalid human claim-review file.") from exc
    if not isinstance(value, dict) or value.get("protocol_version") != CLAIM_REVIEW_VERSION:
        raise ValueError("Invalid human claim-review protocol version.")
    reviews = value.get("reviews")
    if not isinstance(reviews, list) or len(reviews) > len(retrieved_by_query):
        raise ValueError("Invalid human claim-review cases.")

    seen_queries: set[str] = set()
    supported = support_cited = unsupported = total_adjudicated = valid_citations = (
        total_citations
    ) = 0
    rows: list[dict[str, Any]] = []
    for review in reviews:
        if not isinstance(review, dict):
            raise ValueError("Invalid human claim-review case.")
        query_id = review.get("query_id")
        answer_hash = review.get("answer_sha256")
        reviewer = review.get("reviewer")
        model_id = review.get("model_id")
        claims = review.get("claims")
        if (
            not isinstance(query_id, str)
            or query_id not in retrieved_by_query
            or query_id in seen_queries
            or not isinstance(answer_hash, str)
            or not _SHA256.fullmatch(answer_hash)
            or not isinstance(reviewer, str)
            or not reviewer.strip()
            or not isinstance(model_id, str)
            or not model_id.strip()
            or not isinstance(claims, list)
        ):
            raise ValueError("Invalid or duplicate human claim-review metadata.")
        seen_queries.add(query_id)
        allowed = set(retrieved_by_query[query_id])
        case_supported = case_support_cited = case_unsupported = 0
        for claim in claims:
            if not isinstance(claim, dict):
                raise ValueError("Invalid reviewed answer claim.")
            text = claim.get("text")
            disposition = claim.get("review_disposition")
            supporting_ids = claim.get("supporting_source_ids")
            cited_ids = claim.get("model_cited_source_ids")
            if (
                not isinstance(text, str)
                or not text.strip()
                or len(text) > 1500
                or disposition not in {"supported", "unsupported", "uncertain"}
                or not isinstance(supporting_ids, list)
                or not isinstance(cited_ids, list)
                or any(not isinstance(item, str) for item in supporting_ids + cited_ids)
                or len(supporting_ids) > 8
                or len(cited_ids) > 8
                or len(set(supporting_ids)) != len(supporting_ids)
                or len(set(cited_ids)) != len(cited_ids)
                or not set(supporting_ids).issubset(allowed)
            ):
                raise ValueError("Invalid claim review or supporting evidence ID.")
            if disposition == "supported" and not supporting_ids:
                raise ValueError("Supported claims must name a reviewed supporting source.")
            cited_support = bool(set(supporting_ids) & set(cited_ids) & allowed)
            total_citations += len(cited_ids)
            valid_citations += sum(item in allowed for item in cited_ids)
            if disposition == "supported":
                supported += 1
                case_supported += 1
                support_cited += int(cited_support)
                case_support_cited += int(cited_support)
            elif disposition == "unsupported":
                unsupported += 1
                case_unsupported += 1
            if disposition != "uncertain":
                total_adjudicated += 1
        rows.append(
            {
                "query_id": query_id,
                "model_id": model_id,
                "answer_sha256": answer_hash,
                "reviewer": reviewer,
                "supported_claims": case_supported,
                "supported_claims_with_matching_model_citation": case_support_cited,
                "unsupported_claims": case_unsupported,
            }
        )
    return {
        "status": "human_reviewed",
        "review_file_sha256": hashlib.sha256(raw).hexdigest(),
        "reviewed_claims": supported + unsupported,
        "supported_claims": supported,
        "supported_claims_with_matching_model_citation": support_cited,
        "supported_claim_citation_rate": support_cited / supported if supported else None,
        "unsupported_claims": unsupported,
        "unsupported_claim_rate": unsupported / total_adjudicated if total_adjudicated else None,
        "model_citation_validity": (valid_citations / total_citations if total_citations else None),
        "reviews": rows,
        "uncertain_claims_excluded": sum(
            len(cast(list[Any], item.get("claims", []))) for item in reviews
        )
        - supported
        - unsupported,
    }


def evaluate_rag_protocol_v2(
    query_file: Path = DEFAULT_QUERY_FILE,
    *,
    claim_review_file: Path | None = None,
    local_embeddings: bool = False,
    ranking_policy: str = DEFAULT_RANKING_POLICY,
) -> dict[str, Any]:
    try:
        with query_file.open("rb") as source:
            raw = source.read(MAX_QUERY_SET_BYTES + 1)
        if len(raw) > MAX_QUERY_SET_BYTES:
            raise ValueError("RAG v2 query set exceeds the configured size limit.")
        manifest = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("RAG v2 query set is unavailable or malformed.") from exc
    if not isinstance(manifest, dict) or manifest.get("protocol_version") != PROTOCOL_VERSION:
        raise ValueError("Invalid hybrid RAG v2 protocol manifest.")
    cases = manifest.get("queries")
    k = manifest.get("k")
    if (
        not isinstance(cases, list)
        or not cases
        or len(cases) > MAX_QUERY_CASES
        or not isinstance(k, int)
        or isinstance(k, bool)
        or not 1 <= k <= 8
    ):
        raise ValueError("Invalid hybrid RAG v2 query set.")
    status_data = (
        get_local_ai_status()
        if local_embeddings
        else {"status": "Unavailable", "embedding_available": False}
    )
    index_chunks, index_metadata = load_index(
        expected_model_id=(
            str(status_data.get("embedding_model") or "") if local_embeddings else None
        ),
        expected_model_digest=(
            str(status_data.get("embedding_model_digest") or "") if local_embeddings else None
        ),
        expected_embedding_dimensions=(
            cast(int | None, status_data.get("embedding_dimensions")) if local_embeddings else None
        ),
    )

    total_hits = total_relevant = 0
    precision_sum = 0.0
    total_false_positives = abstentions = 0
    valid_retrieved_ids = returned_retrieved_ids = 0
    query_rows: list[dict[str, Any]] = []
    retrieved_by_query: dict[str, list[str]] = {}
    failures: dict[str, int] = {}
    categories: dict[str, dict[str, int]] = {}
    seen_query_ids: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Invalid query case in RAG v2 manifest.")
        query_id = case.get("query_id")
        category = case.get("category")
        query = case.get("query")
        findings = case.get("source_findings", [])
        expected_raw = case.get("expected_relevant_source_ids")
        if (
            not isinstance(query_id, str)
            or not isinstance(category, str)
            or not category.strip()
            or not isinstance(query, str)
            or not query.strip()
            or len(query) > 2000
            or query_id in seen_query_ids
            or not isinstance(findings, list)
            or len(findings) > 128
            or not isinstance(expected_raw, list)
            or any(not isinstance(item, str) for item in expected_raw)
        ):
            raise ValueError("Invalid query metadata in RAG v2 manifest.")
        seen_query_ids.add(query_id)
        expected = set(cast(list[str], expected_raw))
        documents = _make_documents([], cast(list[dict[str, Any]], findings), [], [])
        valid_source_ids = {document.document_id for document in documents}
        valid_source_ids.update(str(chunk.get("chunk_id")) for chunk in index_chunks)
        if not expected.issubset(valid_source_ids):
            raise ValueError("RAG v2 relevance labels reference unknown source IDs.")
        response = answer_scan_question(
            query,
            spec_findings=[],
            source_findings=cast(list[dict[str, Any]], findings),
            correlated_findings=[],
            matched_endpoints=[],
            limit=k,
            local_ai_status=status_data,
            ranking_policy=ranking_policy,
        )
        returned = [str(source["id"]) for source in response["sources"]]
        retrieved_by_query[query_id] = returned
        valid_returned = sum(source_id in valid_source_ids for source_id in returned)
        valid_retrieved_ids += valid_returned
        returned_retrieved_ids += len(returned)
        retrieved = set(returned)
        true_positive = expected & retrieved
        false_positive = retrieved - expected
        false_negative = expected - retrieved
        total_hits += len(true_positive)
        total_false_positives += len(false_positive)
        total_relevant += len(expected)
        abstentions += int(not returned)
        precision_sum += len(true_positive) / k
        category_metrics = categories.setdefault(category, {"cases": 0, "hits": 0, "relevant": 0})
        category_metrics["cases"] += 1
        category_metrics["hits"] += len(true_positive)
        category_metrics["relevant"] += len(expected)
        if false_positive:
            failures["false_positive_retrieval"] = failures.get("false_positive_retrieval", 0) + 1
        if false_negative:
            failures["missed_relevant_source"] = failures.get("missed_relevant_source", 0) + 1
        query_rows.append(
            {
                "query_id": query_id,
                "category": category,
                "expected_relevant_source_ids": sorted(expected),
                "retrieved_source_ids": returned,
                "retrieved_count": len(returned),
                "retrieved_ids_valid": valid_returned == len(returned),
                "true_positive_source_ids": sorted(true_positive),
                "false_positive_source_ids": sorted(false_positive),
                "false_negative_source_ids": sorted(false_negative),
                "precision_at_k": len(true_positive) / k,
                "precision_among_returned": (
                    len(true_positive) / len(returned) if returned else None
                ),
                "recall_at_k": len(true_positive) / len(expected) if expected else None,
                "index_status": response["index_status"],
                "retrieval_method": response["retrieval"],
            }
        )
    claim_review = _evaluate_claim_reviews(claim_review_file, retrieved_by_query)
    return {
        "protocol_version": PROTOCOL_VERSION,
        "query_set_sha256": hashlib.sha256(raw).hexdigest(),
        "query_count": len(cases),
        "k": k,
        "relevance_definition": (
            "A source is relevant only when its content directly answers the specific query or "
            "provides the cited scan evidence requested by that query; topical similarity alone "
            "does not count. Labels are manually reviewed and versioned with the fixture."
        ),
        "retrieval": {
            "recall_at_k": total_hits / total_relevant if total_relevant else None,
            "precision_at_k_macro": precision_sum / len(cases),
            "micro_precision_among_returned": (
                total_hits / returned_retrieved_ids if returned_retrieved_ids else None
            ),
            "relevant_source_count": total_relevant,
            "retrieved_source_count": returned_retrieved_ids,
            "false_positive_source_count": total_false_positives,
            "false_positive_query_count": sum(
                bool(row["false_positive_source_ids"]) for row in query_rows
            ),
            "abstention_count": abstentions,
        },
        "ranking": {
            "policy": ranking_policy,
            "baseline_policy": BASELINE_RANKING_POLICY,
            "semantic_similarity_threshold": (
                0.50 if ranking_policy == DEFAULT_RANKING_POLICY else None
            ),
            "threshold_applies_only_when_compatible_live_embeddings_are_used": True,
        },
        "retrieved_source_id_validity": {
            "valid": valid_retrieved_ids,
            "total": returned_retrieved_ids,
            "rate": (
                valid_retrieved_ids / returned_retrieved_ids if returned_retrieved_ids else 1.0
            ),
        },
        "per_category": {
            name: {
                **values,
                "recall": values["hits"] / values["relevant"] if values["relevant"] else None,
            }
            for name, values in sorted(categories.items())
        },
        "false_positive_cases": [row for row in query_rows if row["false_positive_source_ids"]],
        "cases": query_rows,
        "index": {
            "status": index_metadata.get("status", "missing"),
            "version": index_metadata.get("index_version"),
            "embedding_model": index_metadata.get("embedding_model"),
            "embedding_model_digest": index_metadata.get("embedding_model_digest"),
            "embedding_dimensions": index_metadata.get("embedding_dimensions"),
            "document_count": index_metadata.get("document_count", 0),
            "chunk_count": index_metadata.get("chunk_count", 0),
        },
        "claim_support": claim_review,
        "limitations": [
            "Retrieval labels are a small manually reviewed benchmark, not broad quality proof.",
            "Claim support is not measured unless a separate human-reviewed model-answer file "
            "is supplied.",
            "The protocol never treats citation existence alone as proof that a claim is "
            "supported.",
            "Latency and memory are not measured.",
            "This RAG protocol is separate from deterministic scanner benchmark metrics.",
        ],
        "failure_categories": dict(sorted(failures.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=f"Run {PROTOCOL_VERSION}")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--queries", type=Path, default=DEFAULT_QUERY_FILE)
    parser.add_argument("--claim-review", type=Path)
    parser.add_argument(
        "--local-embeddings",
        action="store_true",
        help="check the configured local Ollama embedding model and use a compatible index",
    )
    parser.add_argument(
        "--ranking-policy",
        choices=(BASELINE_RANKING_POLICY, DEFAULT_RANKING_POLICY),
        default=DEFAULT_RANKING_POLICY,
    )
    args = parser.parse_args()
    try:
        result = evaluate_rag_protocol_v2(
            args.queries,
            claim_review_file=args.claim_review,
            local_embeddings=args.local_embeddings,
            ranking_policy=args.ranking_policy,
        )
    except (OSError, ValueError) as exc:
        parser.exit(2, f"RAG evaluation error: {exc}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{PROTOCOL_VERSION}: {args.output}")


if __name__ == "__main__":
    main()
