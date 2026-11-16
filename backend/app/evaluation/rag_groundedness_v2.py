"""Version 2 groundedness review with separate reference and reviewer abstention labels."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "hybrid-rag-groundedness-review-v2"
_SUPPORT_VALUES = {"supported", "partial", "unsupported", "uncertain", "unassessed"}
_CLAIM_DISPOSITIONS = {"supported", "unsupported", "uncertain"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_INPUT_BYTES = 10 * 1024 * 1024
_UNAVAILABLE_CHECKPOINT_SHA256 = "3f30545b06eea66fd13bb84db9a319d3178680ae2bdc20873b8514229f507bbc"
_CLAIM_KEYS = {
    "text",
    "disposition",
    "supporting_source_ids",
    "model_cited_source_ids",
    "relevant_cited_source_ids",
}
_REVIEW_KEYS = {
    "case_id",
    "answer_sha256",
    "reviewer",
    "review_status",
    "reviewer_notes",
    "manifest_expected_abstention_appropriate",
    "actual_answer_abstained",
    "reviewer_assessed_abstention_appropriate",
    "retrieval_found_relevant_evidence",
    "raw_response_status",
    "raw_response_sha256",
    "raw_response_overall_support",
    "raw_claims",
    "final_response_overall_support",
    "final_claims",
}


class ReviewValidationError(ValueError):
    """Raised when a v2 review cannot be safely or faithfully scored."""


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _validate_claims(
    claims: object,
    *,
    retrieved_ids: set[str],
    location: str,
) -> list[dict[str, Any]]:
    if not isinstance(claims, list) or len(claims) > 32:
        raise ReviewValidationError(f"{location} claims must be a list of at most 32 entries.")
    validated: list[dict[str, Any]] = []
    for index, claim in enumerate(claims):
        label = f"{location} claim {index + 1}"
        if not isinstance(claim, dict) or set(claim) != _CLAIM_KEYS:
            raise ReviewValidationError(f"{label} has invalid fields.")
        text = claim["text"]
        disposition = claim["disposition"]
        if not isinstance(text, str) or not text.strip() or len(text) > 1500:
            raise ReviewValidationError(f"{label} text is invalid.")
        if not isinstance(disposition, str) or disposition not in _CLAIM_DISPOSITIONS:
            raise ReviewValidationError(f"{label} disposition is invalid.")

        source_lists: dict[str, list[str]] = {}
        for key in (
            "supporting_source_ids",
            "model_cited_source_ids",
            "relevant_cited_source_ids",
        ):
            values = claim[key]
            if not isinstance(values, list) or len(values) > 8:
                raise ReviewValidationError(f"{label} {key} is invalid.")
            if any(not isinstance(value, str) or not value for value in values):
                raise ReviewValidationError(f"{label} {key} is invalid.")
            if len(set(values)) != len(values):
                raise ReviewValidationError(f"{label} {key} is invalid.")
            source_lists[key] = values

        supporting = set(source_lists["supporting_source_ids"])
        model_cited = set(source_lists["model_cited_source_ids"])
        relevant_cited = set(source_lists["relevant_cited_source_ids"])
        if not supporting.issubset(retrieved_ids):
            raise ReviewValidationError(f"{label} supporting sources were not retrieved.")
        if not relevant_cited.issubset(model_cited & retrieved_ids):
            raise ReviewValidationError(
                f"{label} relevant citations must be cited and retrieved sources."
            )
        if disposition == "supported" and not supporting:
            raise ReviewValidationError(f"{label} supported disposition requires evidence.")
        validated.append(claim)
    return validated


def validate_review_document(
    manifest: dict[str, Any],
    answers: dict[str, Any],
    review_document: dict[str, Any],
    *,
    manifest_sha256: str,
    answers_sha256: str,
) -> list[dict[str, Any]]:
    """Validate all six review records and return them in manifest order."""
    if manifest.get("protocol_version") != "hybrid-rag-groundedness-v1":
        raise ReviewValidationError("Unsupported case manifest protocol.")
    if answers.get("protocol_version") != "hybrid-rag-groundedness-v1":
        raise ReviewValidationError("Unsupported answers protocol.")
    if review_document.get("protocol_version") != PROTOCOL_VERSION:
        raise ReviewValidationError("Unsupported review protocol.")
    if set(review_document) != {"protocol_version", "provenance", "reviews"}:
        raise ReviewValidationError("Review document has invalid top-level fields.")

    provenance = review_document.get("provenance")
    if not isinstance(provenance, dict):
        raise ReviewValidationError("Review provenance is required.")
    if set(provenance) != {
        "manifest_sha256",
        "answers_sha256",
        "source_review_sha256",
        "source_review_file",
        "original_provenance_checkpoint",
    }:
        raise ReviewValidationError("Review provenance fields are invalid.")
    if provenance.get("manifest_sha256") != manifest_sha256:
        raise ReviewValidationError("Manifest hash does not match review provenance.")
    if provenance.get("answers_sha256") != answers_sha256:
        raise ReviewValidationError("Answers hash does not match review provenance.")
    if not _is_sha256(provenance.get("source_review_sha256")):
        raise ReviewValidationError("Source review hash is invalid.")
    if (
        not isinstance(provenance.get("source_review_file"), str)
        or not provenance["source_review_file"].strip()
    ):
        raise ReviewValidationError("Source review file is required.")
    checkpoint = provenance.get("original_provenance_checkpoint")
    if (
        not isinstance(checkpoint, dict)
        or set(checkpoint) != {"status", "expected_sha256", "role"}
        or checkpoint.get("status") != "unavailable"
        or checkpoint.get("expected_sha256") != _UNAVAILABLE_CHECKPOINT_SHA256
        or checkpoint.get("role") != "provenance_checkpoint_not_runtime_input"
    ):
        raise ReviewValidationError("Original provenance checkpoint status is invalid.")

    case_list = manifest.get("cases")
    answer_list = answers.get("cases")
    review_list = review_document.get("reviews")
    if not all(isinstance(value, list) for value in (case_list, answer_list, review_list)):
        raise ReviewValidationError("Case, answer, and review lists are required.")
    assert isinstance(case_list, list)
    assert isinstance(answer_list, list)
    assert isinstance(review_list, list)
    if not case_list:
        raise ReviewValidationError("The review set must contain at least one case.")

    def index_by_case_id(values: list[Any], label: str) -> dict[str, dict[str, Any]]:
        indexed: dict[str, dict[str, Any]] = {}
        for item in values:
            if not isinstance(item, dict):
                raise ReviewValidationError(f"{label} entries must be objects.")
            case_id = item.get("case_id")
            if not isinstance(case_id, str) or not case_id or case_id in indexed:
                raise ReviewValidationError(f"{label} case IDs are invalid or duplicated.")
            indexed[case_id] = item
        return indexed

    case_map = index_by_case_id(case_list, "Manifest")
    answer_map = index_by_case_id(answer_list, "Answers")
    review_map = index_by_case_id(review_list, "Review")
    if set(case_map) != set(answer_map) or set(case_map) != set(review_map):
        raise ReviewValidationError("Manifest, answers, and reviews must have identical case IDs.")

    ordered: list[dict[str, Any]] = []
    for case_id in case_map:
        case = case_map[case_id]
        answer = answer_map[case_id]
        review = review_map[case_id]
        if set(review) != _REVIEW_KEYS:
            raise ReviewValidationError(f"Review fields are invalid for {case_id}.")
        if review.get("review_status") != "reviewed":
            raise ReviewValidationError(f"Review is pending for {case_id}.")
        if review.get("answer_sha256") != answer.get("answer_sha256") or not _is_sha256(
            review.get("answer_sha256")
        ):
            raise ReviewValidationError(f"Answer hash mismatch for {case_id}.")
        reviewer = review.get("reviewer")
        if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 255:
            raise ReviewValidationError(f"Reviewer identity is missing or invalid for {case_id}.")
        notes = review.get("reviewer_notes")
        if not isinstance(notes, str) or not notes.strip() or len(notes) > 2000:
            raise ReviewValidationError(f"Reviewer notes are missing or invalid for {case_id}.")

        manifest_expected = case.get("abstention_appropriate")
        if not isinstance(manifest_expected, bool):
            raise ReviewValidationError(f"Manifest abstention label is invalid for {case_id}.")
        if review.get("manifest_expected_abstention_appropriate") is not manifest_expected:
            raise ReviewValidationError(
                f"Manifest expectation was changed for {case_id}; keep it immutable."
            )
        for key in (
            "actual_answer_abstained",
            "reviewer_assessed_abstention_appropriate",
            "retrieval_found_relevant_evidence",
        ):
            if not isinstance(review.get(key), bool):
                raise ReviewValidationError(f"{key} must be a boolean for {case_id}.")

        raw_response = answer.get("raw_ollama_response")
        raw_status = review.get("raw_response_status")
        raw_hash = review.get("raw_response_sha256")
        raw_support = review.get("raw_response_overall_support")
        answer_raw_hash = answer.get("raw_ollama_response_sha256")
        if raw_response is None:
            if (
                raw_status != "not_generated"
                or raw_hash is not None
                or raw_support is not None
                or answer_raw_hash is not None
                or review.get("raw_claims") != []
            ):
                raise ReviewValidationError(
                    f"not_generated raw response must have no hash, "
                    f"support, or claims for {case_id}."
                )
        else:
            if not isinstance(raw_response, str) or raw_status != "generated":
                raise ReviewValidationError(f"Raw response status mismatch for {case_id}.")
            expected_raw_hash = hashlib.sha256(raw_response.encode("utf-8")).hexdigest()
            if raw_hash != expected_raw_hash or answer_raw_hash != expected_raw_hash:
                raise ReviewValidationError(f"Raw response hash mismatch for {case_id}.")
            if not isinstance(raw_support, str) or raw_support not in _SUPPORT_VALUES:
                raise ReviewValidationError(f"Raw response support is invalid for {case_id}.")

        final_support = review.get("final_response_overall_support")
        if not isinstance(final_support, str) or final_support not in _SUPPORT_VALUES:
            raise ReviewValidationError(f"Final response support is invalid for {case_id}.")
        retrieved = answer.get("retrieved_sources")
        if not isinstance(retrieved, list):
            raise ReviewValidationError(f"Retrieved sources are invalid for {case_id}.")
        retrieved_ids: set[str] = set()
        for source in retrieved:
            if isinstance(source, dict):
                source_id = source.get("id")
                if isinstance(source_id, str):
                    retrieved_ids.add(source_id)
        if len(retrieved_ids) != len(retrieved):
            raise ReviewValidationError(f"Retrieved source IDs are invalid for {case_id}.")
        validated_review = dict(review)
        validated_review["raw_claims"] = _validate_claims(
            review.get("raw_claims"), retrieved_ids=retrieved_ids, location=f"{case_id} raw"
        )
        validated_review["final_claims"] = _validate_claims(
            review.get("final_claims"), retrieved_ids=retrieved_ids, location=f"{case_id} final"
        )
        validated_review["_retrieved_ids"] = retrieved_ids
        ordered.append(validated_review)
    return ordered


def _claim_metrics(reviews: list[dict[str, Any]], field: str) -> dict[str, Any]:
    claims = [claim for review in reviews for claim in review[field]]
    supported = sum(claim["disposition"] == "supported" for claim in claims)
    unsupported = sum(claim["disposition"] == "unsupported" for claim in claims)
    uncertain = sum(claim["disposition"] == "uncertain" for claim in claims)
    cited_ids = [source_id for claim in claims for source_id in claim["model_cited_source_ids"]]
    relevant_ids = [
        source_id for claim in claims for source_id in claim["relevant_cited_source_ids"]
    ]
    retrieved_by_case = {review["case_id"]: set(review["_retrieved_ids"]) for review in reviews}
    all_valid = sum(
        source_id in retrieved_by_case[review["case_id"]]
        for review in reviews
        for claim in review[field]
        for source_id in claim["model_cited_source_ids"]
    )
    decided = supported + unsupported
    return {
        "claim_count": len(claims),
        "supported": supported,
        "unsupported": unsupported,
        "uncertain_excluded": uncertain,
        "support_rate": supported / decided if decided else None,
        "citation_ids": {
            "valid": all_valid,
            "denominator": len(cited_ids),
            "validity_rate": all_valid / len(cited_ids) if cited_ids else None,
        },
        "claim_citation_relevance": {
            "relevant": len(relevant_ids),
            "denominator": len(cited_ids),
            "rate": len(relevant_ids) / len(cited_ids) if cited_ids else None,
        },
    }


def score_review_document(
    manifest: dict[str, Any],
    answers: dict[str, Any],
    review_document: dict[str, Any],
    *,
    manifest_sha256: str,
    answers_sha256: str,
    source_review_sha256: str | None = None,
) -> dict[str, Any]:
    """Score only complete v2 reviews and report manifest/reviewer metrics separately."""
    reviews = validate_review_document(
        manifest,
        answers,
        review_document,
        manifest_sha256=manifest_sha256,
        answers_sha256=answers_sha256,
    )
    if (
        source_review_sha256 is not None
        and review_document["provenance"]["source_review_sha256"] != source_review_sha256
    ):
        raise ReviewValidationError("Source review hash does not match review provenance.")
    denominator = len(reviews)
    manifest_agreements = sum(
        review["actual_answer_abstained"] == review["manifest_expected_abstention_appropriate"]
        for review in reviews
    )
    reviewer_agreements = sum(
        review["actual_answer_abstained"] == review["reviewer_assessed_abstention_appropriate"]
        for review in reviews
    )
    generated = sum(review["raw_response_status"] == "generated" for review in reviews)
    actual_abstentions = sum(review["actual_answer_abstained"] for review in reviews)
    no_evidence = [review for review in reviews if not review["retrieval_found_relevant_evidence"]]

    case_rows = []
    for review in reviews:
        case_rows.append(
            {
                "case_id": review["case_id"],
                "answer_sha256": review["answer_sha256"],
                "reviewer": review["reviewer"],
                "review_status": review["review_status"],
                "manifest_expected_abstention_appropriate": review[
                    "manifest_expected_abstention_appropriate"
                ],
                "actual_answer_abstained": review["actual_answer_abstained"],
                "reviewer_assessed_abstention_appropriate": review[
                    "reviewer_assessed_abstention_appropriate"
                ],
                "raw_response_status": review["raw_response_status"],
                "retrieval_found_relevant_evidence": review["retrieval_found_relevant_evidence"],
                "reviewer_notes": review["reviewer_notes"],
            }
        )

    return {
        "protocol_version": PROTOCOL_VERSION,
        "status": "human_reviewed",
        "provenance": {
            "manifest_sha256": manifest_sha256,
            "answers_sha256": answers_sha256,
            "source_review_sha256": review_document["provenance"]["source_review_sha256"],
            "source_review_file": review_document["provenance"]["source_review_file"],
            "original_provenance_checkpoint": review_document["provenance"][
                "original_provenance_checkpoint"
            ],
        },
        "case_count": denominator,
        "abstention_metrics": {
            "manifest_agreement": {
                "agreements": manifest_agreements,
                "denominator": denominator,
                "rate": manifest_agreements / denominator if denominator else None,
            },
            "reviewer_agreement": {
                "agreements": reviewer_agreements,
                "denominator": denominator,
                "rate": reviewer_agreements / denominator if denominator else None,
            },
            "actual_abstentions": actual_abstentions,
            "no_evidence_cases": len(no_evidence),
            "actual_abstentions_on_no_evidence": sum(
                review["actual_answer_abstained"] for review in no_evidence
            ),
        },
        "raw_response_coverage": {
            "generated": generated,
            "not_generated": denominator - generated,
            "denominator": denominator,
        },
        "claim_metrics": {
            "raw": _claim_metrics(reviews, "raw_claims"),
            "final": _claim_metrics(reviews, "final_claims"),
        },
        "cases": case_rows,
    }


def evaluate_review_files(
    case_file: Path,
    answers_file: Path,
    review_file: Path,
    source_review_file: Path,
) -> dict[str, Any]:
    """Read immutable inputs and score an answer-hash-bound v2 review."""
    paths = (case_file, answers_file, review_file, source_review_file)
    try:
        raw_inputs = []
        for path in paths:
            with path.open("rb") as stream:
                raw = stream.read(_MAX_INPUT_BYTES + 1)
            if len(raw) > _MAX_INPUT_BYTES:
                raise ReviewValidationError("An evaluation input exceeds the size limit.")
            raw_inputs.append(raw)
        raw_case, raw_answers, raw_review, raw_source_review = raw_inputs
        manifest = json.loads(raw_case)
        answers = json.loads(raw_answers)
        review_document = json.loads(raw_review)
    except ReviewValidationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ReviewValidationError("An evaluation input is unavailable or malformed.") from exc
    if not all(isinstance(value, dict) for value in (manifest, answers, review_document)):
        raise ReviewValidationError("Evaluation inputs must be JSON objects.")
    result = score_review_document(
        manifest,
        answers,
        review_document,
        manifest_sha256=_digest(raw_case),
        answers_sha256=_digest(raw_answers),
        source_review_sha256=_digest(raw_source_review),
    )
    result["provenance"]["review_file_sha256"] = _digest(raw_review)
    return result


def _write_private_new_file(path: Path, value: dict[str, Any]) -> None:
    """Create a private report without replacing an existing artifact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Score v2 human groundedness reviews.")
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--answers", type=Path, required=True)
    parser.add_argument("--review-file", type=Path, required=True)
    parser.add_argument("--source-review", type=Path, required=True)
    parser.add_argument("--report-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = evaluate_review_files(
            args.cases, args.answers, args.review_file, args.source_review
        )
        _write_private_new_file(args.report_output, result)
    except ReviewValidationError as exc:
        parser.error(str(exc))
    except OSError:
        parser.error("Report output is unavailable or already exists; no artifact was overwritten.")
    print(f"Wrote private {PROTOCOL_VERSION} report with {result['case_count']} reviewed cases.")


if __name__ == "__main__":
    main()
