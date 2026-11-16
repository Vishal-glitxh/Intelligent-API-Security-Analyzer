"""Generate separate local-model answer samples for human groundedness review."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from app.services import local_ai
from app.services.rag_assistant import answer_scan_question

PROTOCOL_VERSION = "hybrid-rag-groundedness-v1"
REVIEW_PROTOCOL_VERSION = "hybrid-rag-groundedness-review-v1"
DEFAULT_CASE_FILE = (
    Path(__file__).resolve().parents[3] / "evaluation/rag/groundedness-v1/cases.json"
)
MAX_CASE_FILE_BYTES = 2 * 1024 * 1024
MAX_CASES = 64
MAX_REVIEW_BYTES = 4 * 1024 * 1024
MAX_ANSWER_BYTES = 32 * 1024 * 1024


def _load_cases(path: Path) -> tuple[bytes, list[dict[str, Any]]]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_CASE_FILE_BYTES + 1)
        if len(raw) > MAX_CASE_FILE_BYTES:
            raise ValueError("Groundedness case file exceeds the configured size limit.")
        manifest = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Groundedness case file is unavailable or malformed.") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("protocol_version") != PROTOCOL_VERSION
        or manifest.get("status") != "draft_pending_human_review"
        or not isinstance(manifest.get("cases"), list)
        or not manifest["cases"]
        or len(manifest["cases"]) > MAX_CASES
    ):
        raise ValueError("Invalid groundedness case manifest.")
    cases = manifest["cases"]
    seen: set[str] = set()
    for case in cases:
        if (
            not isinstance(case, dict)
            or not isinstance(case.get("case_id"), str)
            or case["case_id"] in seen
            or not isinstance(case.get("question"), str)
            or not case["question"].strip()
            or len(case["question"]) > 2000
            or not isinstance(case.get("source_findings"), list)
            or len(case["source_findings"]) > 32
            or case.get("human_review_status") != "pending"
        ):
            raise ValueError("Invalid or duplicate groundedness case.")
        seen.add(case["case_id"])
    return raw, cases


def _atomic_private_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as out:
            temporary = out.name
            os.chmod(temporary, 0o600)
            out.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _generate_and_capture(
    question: str, sources: list[dict[str, Any]], status: dict[str, Any]
) -> tuple[local_ai.AIExplanation | None, str | None]:
    captured_raw_response: str | None = None
    original_request = local_ai._request_json

    def capture_generation_response(
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        response_limit: int = 65536,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        nonlocal captured_raw_response
        response = original_request(path, payload, response_limit=response_limit, timeout=timeout)
        raw_response = response.get("response") if path == "/api/generate" else None
        if isinstance(raw_response, str):
            captured_raw_response = raw_response
        return response

    local_ai._request_json = capture_generation_response
    try:
        explanation = local_ai.generate_local_explanation(question, sources, status_data=status)
    finally:
        local_ai._request_json = original_request
    return explanation, captured_raw_response


def run_groundedness_cases(case_file: Path, output_file: Path) -> dict[str, Any]:
    raw, cases = _load_cases(case_file)
    status = local_ai.get_local_ai_status()
    model_id = status.get("model_name")
    if status.get("status") != "Available" or not isinstance(model_id, str) or not model_id:
        raise ValueError("A configured, installed local Ollama generation model is required.")

    rows: list[dict[str, Any]] = []
    for case in cases:
        findings = case["source_findings"]
        retrieved = answer_scan_question(
            case["question"],
            spec_findings=[],
            source_findings=findings,
            correlated_findings=[],
            matched_endpoints=[],
            local_ai_status=status,
        )
        explanation, captured_raw_response = _generate_and_capture(
            case["question"], retrieved["sources"], status
        )
        rows.append(
            {
                "case_id": case["case_id"],
                "question": case["question"],
                "model_used": explanation is not None,
                "model_id": model_id,
                "retrieval_method": retrieved["retrieval"],
                "index_status": retrieved["index_status"],
                "index_version": retrieved["index_version"],
                "retrieved_sources": retrieved["sources"],
                "deterministic_fallback_answer": retrieved["answer"],
                "raw_ollama_response": captured_raw_response,
                "raw_ollama_response_sha256": (
                    hashlib.sha256(captured_raw_response.encode("utf-8")).hexdigest()
                    if captured_raw_response is not None
                    else None
                ),
                "raw_model_answer": (
                    {
                        "explanation": explanation.explanation,
                        "recommendations": explanation.recommendations,
                        "cited_source_ids": explanation.cited_source_ids,
                    }
                    if explanation
                    else None
                ),
                "raw_answer_sha256": (
                    hashlib.sha256(
                        json.dumps(
                            {
                                "explanation": explanation.explanation,
                                "recommendations": explanation.recommendations,
                                "cited_source_ids": explanation.cited_source_ids,
                            },
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).hexdigest()
                    if explanation
                    else None
                ),
                "answer_sha256": hashlib.sha256(
                    (
                        captured_raw_response
                        if captured_raw_response is not None
                        else retrieved["answer"]
                    ).encode("utf-8")
                ).hexdigest(),
            }
        )
    result = {
        "protocol_version": PROTOCOL_VERSION,
        "case_file_sha256": hashlib.sha256(raw).hexdigest(),
        "model_id": model_id,
        "model_digest": status.get("model_digest"),
        "retrieval": {
            "index_status": status.get("rag_index_status"),
            "index_version": status.get("rag_index_version"),
            "embedding_model": status.get("embedding_model"),
            "embedding_model_digest": status.get("embedding_model_digest"),
            "embedding_dimensions": status.get("rag_index_embedding_dimensions"),
            "document_count": status.get("rag_index_document_count", 0),
            "chunk_count": status.get("rag_index_chunk_count", 0),
            "method": (
                "production assistant retrieval path; semantic vectors used only if a "
                "compatible persistent index is ready"
            ),
        },
        "human_review_status": "pending",
        "cases": rows,
        "notice": (
            "Raw local model outputs are unadjudicated. No groundedness metric is computed "
            "by this runner."
        ),
    }
    _atomic_private_write(output_file, result)
    return result


def evaluate_groundedness_reviews(
    case_file: Path, answers_file: Path, review_file: Path
) -> dict[str, Any]:
    """Score explicit human judgments bound to exact generated-answer hashes."""
    _, cases = _load_cases(case_file)
    try:
        with answers_file.open("rb") as stream:
            answer_raw = stream.read(MAX_ANSWER_BYTES + 1)
        with review_file.open("rb") as stream:
            review_raw = stream.read(MAX_REVIEW_BYTES + 1)
        if len(answer_raw) > MAX_ANSWER_BYTES:
            raise ValueError("Groundedness answer file exceeds the configured size limit.")
        if len(review_raw) > MAX_REVIEW_BYTES:
            raise ValueError("Groundedness review file exceeds the configured size limit.")
        answers = json.loads(answer_raw)
        reviews_manifest = json.loads(review_raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Groundedness answer or review file is unavailable or malformed.") from exc
    if (
        not isinstance(answers, dict)
        or answers.get("protocol_version") != PROTOCOL_VERSION
        or not isinstance(answers.get("cases"), list)
        or not isinstance(reviews_manifest, dict)
        or reviews_manifest.get("protocol_version") != REVIEW_PROTOCOL_VERSION
        or not isinstance(reviews_manifest.get("reviews"), list)
        or len(reviews_manifest["reviews"]) > len(cases)
    ):
        raise ValueError("Invalid groundedness answer or review protocol.")

    case_map = {case["case_id"]: case for case in cases}
    answer_map = {
        item.get("case_id"): item
        for item in answers["cases"]
        if isinstance(item, dict) and isinstance(item.get("case_id"), str)
    }
    seen: set[str] = set()
    total_claims = supported_claims = unsupported_claims = uncertain_claims = 0
    total_citations = valid_citations = 0
    unique_citations: set[tuple[str, str]] = set()
    correct_citation_pairs: set[tuple[str, str]] = set()
    relevant_citation_claim_pairs = valid_citation_claim_pairs = 0
    total_abstention_cases = correct_abstentions = 0
    no_evidence_cases = appropriate_no_evidence_abstentions = 0
    reviewer_rows: list[dict[str, Any]] = []

    for review in reviews_manifest["reviews"]:
        if not isinstance(review, dict):
            raise ValueError("Invalid groundedness review case.")
        case_id = review.get("case_id")
        answer_hash = review.get("answer_sha256")
        reviewer = review.get("reviewer")
        claims = review.get("claims")
        reviewer_notes = review.get("reviewer_notes")
        answer_abstained = review.get("answer_abstained")
        retrieval_found_relevant = review.get("retrieval_found_relevant_evidence")
        if (
            not isinstance(case_id, str)
            or case_id not in case_map
            or case_id in seen
            or case_id not in answer_map
            or not isinstance(answer_hash, str)
            or answer_hash != answer_map[case_id].get("answer_sha256")
            or not isinstance(reviewer, str)
            or not reviewer.strip()
            or review.get("human_review_status") != "reviewed"
            or not isinstance(claims, list)
            or len(claims) > 32
            or not isinstance(reviewer_notes, str)
            or len(reviewer_notes) > 2000
            or not isinstance(answer_abstained, bool)
            or not isinstance(retrieval_found_relevant, bool)
        ):
            raise ValueError("Invalid review metadata or answer hash binding.")
        seen.add(case_id)
        case = case_map[case_id]
        answer = answer_map[case_id]
        retrieved_ids = {
            str(source.get("id"))
            for source in answer.get("retrieved_sources", [])
            if isinstance(source, dict) and isinstance(source.get("id"), str)
        }
        expected_citations = case.get("expected_citation_references", [])
        abstention_expected = case.get("abstention_appropriate")
        if not isinstance(abstention_expected, bool):
            raise ValueError("Groundedness case is missing its abstention reference label.")
        total_abstention_cases += 1
        correct_abstentions += int(answer_abstained == abstention_expected)
        if not retrieval_found_relevant:
            no_evidence_cases += 1
            appropriate_no_evidence_abstentions += int(answer_abstained)

        case_supported = case_unsupported = 0
        cited_unique_for_case: set[str] = set()
        relevant_unique_for_case: set[str] = set()
        for claim in claims:
            if not isinstance(claim, dict):
                raise ValueError("Invalid reviewed claim.")
            text = claim.get("text")
            disposition = claim.get("disposition")
            supporting_ids = claim.get("supporting_source_ids")
            cited_ids = claim.get("model_cited_source_ids")
            relevant_cited_ids = claim.get("relevant_cited_source_ids")
            if (
                not isinstance(text, str)
                or not text.strip()
                or len(text) > 1500
                or disposition not in {"supported", "unsupported", "uncertain"}
                or not isinstance(supporting_ids, list)
                or not isinstance(cited_ids, list)
                or not isinstance(relevant_cited_ids, list)
            ):
                raise ValueError("Invalid claim judgment or source attribution.")
            if (
                any(
                    not isinstance(source_id, str)
                    for value in (supporting_ids, cited_ids, relevant_cited_ids)
                    for source_id in value
                )
                or any(
                    len(value) > 8 or len(set(value)) != len(value)
                    for value in (supporting_ids, cited_ids, relevant_cited_ids)
                )
                or not set(supporting_ids).issubset(retrieved_ids)
                or not set(relevant_cited_ids).issubset(set(cited_ids) & retrieved_ids)
                or disposition == "supported"
                and not supporting_ids
            ):
                raise ValueError("Invalid claim judgment or source attribution.")
            total_claims += 1
            if disposition == "supported":
                supported_claims += 1
                case_supported += 1
            elif disposition == "unsupported":
                unsupported_claims += 1
                case_unsupported += 1
            else:
                uncertain_claims += 1
            total_citations += len(cited_ids)
            valid_citations += sum(source_id in retrieved_ids for source_id in cited_ids)
            unique_citations.update((case_id, source_id) for source_id in cited_ids)
            cited_unique_for_case.update(cited_ids)
            relevant_unique_for_case.update(relevant_cited_ids)
            relevant_citation_claim_pairs += len(relevant_cited_ids)
            valid_citation_claim_pairs += sum(source_id in retrieved_ids for source_id in cited_ids)
        correct_citation_pairs.update(
            (case_id, source_id) for source_id in cited_unique_for_case & relevant_unique_for_case
        )
        reviewer_rows.append(
            {
                "case_id": case_id,
                "reviewer": reviewer,
                "reviewer_notes": reviewer_notes,
                "answer_sha256": answer_hash,
                "expected_citation_references": expected_citations,
                "supported_claims": case_supported,
                "unsupported_claims": case_unsupported,
                "answer_abstained": answer_abstained,
                "abstention_expected": abstention_expected,
                "retrieval_found_relevant_evidence": retrieval_found_relevant,
            }
        )

    adjudicated_claims = supported_claims + unsupported_claims
    return {
        "protocol_version": REVIEW_PROTOCOL_VERSION,
        "status": "human_reviewed" if reviewer_rows else "not_reviewed",
        "case_file_sha256": hashlib.sha256(case_file.read_bytes()).hexdigest(),
        "answers_file_sha256": hashlib.sha256(answer_raw).hexdigest(),
        "review_file_sha256": hashlib.sha256(review_raw).hexdigest(),
        "reviewed_case_count": len(reviewer_rows),
        "claim_metrics": {
            "supported": supported_claims,
            "unsupported": unsupported_claims,
            "uncertain_excluded": uncertain_claims,
            "support_rate": supported_claims / adjudicated_claims if adjudicated_claims else None,
            "unsupported_claim_rate": (
                unsupported_claims / adjudicated_claims if adjudicated_claims else None
            ),
        },
        "citation_metrics": {
            "citation_reference_validity": valid_citations / total_citations
            if total_citations
            else None,
            "citation_correctness": len(correct_citation_pairs) / len(unique_citations)
            if unique_citations
            else None,
            "evidence_to_claim_relevance": (
                relevant_citation_claim_pairs / valid_citation_claim_pairs
                if valid_citation_claim_pairs
                else None
            ),
        },
        "abstention_metrics": {
            "appropriate_abstention_accuracy": (
                correct_abstentions / total_abstention_cases if total_abstention_cases else None
            ),
            "no_relevant_evidence_cases": no_evidence_cases,
            "appropriate_abstentions_when_no_relevant_evidence": (
                appropriate_no_evidence_abstentions / no_evidence_cases
                if no_evidence_cases
                else None
            ),
        },
        "reviewers": reviewer_rows,
        "notice": (
            "Metrics are human-grounded only when each included case has a named reviewer "
            "and an answer-hash-bound review."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=f"Generate local answers for {PROTOCOL_VERSION}")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASE_FILE)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--answers", type=Path)
    parser.add_argument("--review-file", type=Path)
    parser.add_argument("--review-output", type=Path)
    args = parser.parse_args()
    try:
        if args.review_file:
            if not args.answers or not args.review_output:
                parser.error("--review-file requires --answers and --review-output.")
            result = evaluate_groundedness_reviews(args.cases, args.answers, args.review_file)
            _atomic_private_write(args.review_output, result)
        else:
            if not args.output:
                parser.error("--output is required when generating answer samples.")
            result = run_groundedness_cases(args.cases, args.output)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Groundedness generation error: {exc}\n")
    if args.review_file:
        print(
            f"{REVIEW_PROTOCOL_VERSION}: scored {result['reviewed_case_count']} "
            f"answer-hash-bound human reviews; status={result['status']}"
        )
    else:
        print(
            f"{PROTOCOL_VERSION}: generated {len(result['cases'])} "
            f"unreviewed local answer records; model={result['model_id']}"
        )


if __name__ == "__main__":
    main()
