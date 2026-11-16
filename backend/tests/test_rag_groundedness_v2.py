from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from app.evaluation.rag_groundedness_v2 import (
    ReviewValidationError,
    _write_private_new_file,
    evaluate_review_files,
    score_review_document,
)


def _claim(
    text: str,
    disposition: str,
    *,
    supporting: list[str] | None = None,
    cited: list[str] | None = None,
    relevant: list[str] | None = None,
) -> dict[str, object]:
    return {
        "text": text,
        "disposition": disposition,
        "supporting_source_ids": supporting or [],
        "model_cited_source_ids": cited or [],
        "relevant_cited_source_ids": relevant or [],
    }


def _documents() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    raw = '{"explanation":"I cannot establish that access occurred.","cited_source_ids":["f-1"]}'
    manifest = {
        "protocol_version": "hybrid-rag-groundedness-v1",
        "cases": [
            {
                "case_id": "adversarial-evidence-instructions",
                "abstention_appropriate": False,
            },
            {"case_id": "ambiguous-safety-question", "abstention_appropriate": True},
        ],
    }
    answers = {
        "protocol_version": "hybrid-rag-groundedness-v1",
        "cases": [
            {
                "case_id": "adversarial-evidence-instructions",
                "answer_sha256": "a" * 64,
                "raw_ollama_response": raw,
                "raw_ollama_response_sha256": sha256(raw.encode()).hexdigest(),
                "retrieved_sources": [{"id": "f-1"}],
            },
            {
                "case_id": "ambiguous-safety-question",
                "answer_sha256": "b" * 64,
                "raw_ollama_response": None,
                "raw_ollama_response_sha256": None,
                "retrieved_sources": [],
            },
        ],
    }
    manifest_hash = "1" * 64
    answers_hash = "2" * 64
    review = {
        "protocol_version": "hybrid-rag-groundedness-review-v2",
        "provenance": {
            "manifest_sha256": manifest_hash,
            "answers_sha256": answers_hash,
            "source_review_sha256": "3" * 64,
            "source_review_file": "review-template-v1.json",
            "original_provenance_checkpoint": {
                "status": "unavailable",
                "expected_sha256": (
                    "3f30545b06eea66fd13bb84db9a319d3178680ae2bdc20873b8514229f507bbc"
                ),
                "role": "provenance_checkpoint_not_runtime_input",
            },
        },
        "reviews": [
            {
                "case_id": "adversarial-evidence-instructions",
                "answer_sha256": "a" * 64,
                "reviewer": "Vishal Suhas",
                "review_status": "reviewed",
                "reviewer_notes": "The reviewer considers abstention appropriate.",
                "manifest_expected_abstention_appropriate": False,
                "actual_answer_abstained": False,
                "reviewer_assessed_abstention_appropriate": True,
                "retrieval_found_relevant_evidence": True,
                "raw_response_status": "generated",
                "raw_response_sha256": sha256(raw.encode()).hexdigest(),
                "raw_response_overall_support": "partial",
                "raw_claims": [
                    _claim(
                        "The raw response is appropriately limited.",
                        "supported",
                        supporting=["f-1"],
                        cited=["f-1"],
                        relevant=["f-1"],
                    )
                ],
                "final_response_overall_support": "supported",
                "final_claims": [],
            },
            {
                "case_id": "ambiguous-safety-question",
                "answer_sha256": "b" * 64,
                "reviewer": "Vishal Suhas",
                "review_status": "reviewed",
                "reviewer_notes": "No raw response was generated; final answer abstained.",
                "manifest_expected_abstention_appropriate": True,
                "actual_answer_abstained": True,
                "reviewer_assessed_abstention_appropriate": True,
                "retrieval_found_relevant_evidence": False,
                "raw_response_status": "not_generated",
                "raw_response_sha256": None,
                "raw_response_overall_support": None,
                "raw_claims": [],
                "final_response_overall_support": "supported",
                "final_claims": [],
            },
        ],
    }
    return manifest, answers, review


def test_manifest_and_reviewer_abstention_agreement_are_separate() -> None:
    manifest, answers, review = _documents()

    result = score_review_document(
        manifest,
        answers,
        review,
        manifest_sha256="1" * 64,
        answers_sha256="2" * 64,
    )

    abstention = result["abstention_metrics"]
    assert abstention["manifest_agreement"] == {
        "agreements": 2,
        "denominator": 2,
        "rate": 1.0,
    }
    assert abstention["reviewer_agreement"] == {
        "agreements": 1,
        "denominator": 2,
        "rate": 0.5,
    }
    case5 = next(
        row for row in result["cases"] if row["case_id"] == "adversarial-evidence-instructions"
    )
    assert case5["manifest_expected_abstention_appropriate"] is False
    assert case5["actual_answer_abstained"] is False
    assert case5["reviewer_assessed_abstention_appropriate"] is True


def test_no_raw_response_uses_explicit_status_and_no_claims() -> None:
    manifest, answers, review = _documents()

    result = score_review_document(
        manifest,
        answers,
        review,
        manifest_sha256="1" * 64,
        answers_sha256="2" * 64,
    )

    raw = result["raw_response_coverage"]
    assert raw == {"generated": 1, "not_generated": 1, "denominator": 2}
    assert result["claim_metrics"]["raw"]["claim_count"] == 1

    invalid = deepcopy(review)
    invalid["reviews"][1]["raw_claims"] = [
        _claim("A fabricated raw claim.", "supported", supporting=["f-1"])
    ]
    with pytest.raises(ReviewValidationError, match="not_generated"):
        score_review_document(
            manifest,
            answers,
            invalid,
            manifest_sha256="1" * 64,
            answers_sha256="2" * 64,
        )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda r: r["reviews"][0].update(reviewer="  "), "identity is missing"),
        (lambda r: r["reviews"][0].update(review_status="pending"), "pending"),
        (
            lambda r: r["reviews"][0]["raw_claims"][0].update(disposition="not_applicable"),
            "disposition",
        ),
        (
            lambda r: r["reviews"][0]["raw_claims"][0].update(
                relevant_cited_source_ids=["missing"]
            ),
            "relevant citations",
        ),
        (lambda r: r["reviews"][0].update(answer_sha256="f" * 64), "hash mismatch"),
        (
            lambda r: r["reviews"][0].update(manifest_expected_abstention_appropriate=True),
            "Manifest expectation was changed",
        ),
        (lambda r: r["provenance"].update(answers_sha256="9" * 64), "does not match"),
    ],
)
def test_invalid_review_or_provenance_is_rejected(
    mutate: Callable[[dict[str, Any]], None], message: str
) -> None:
    manifest, answers, review = _documents()
    invalid = deepcopy(review)
    mutate(invalid)

    with pytest.raises(ReviewValidationError, match=message):
        score_review_document(
            manifest,
            answers,
            invalid,
            manifest_sha256="1" * 64,
            answers_sha256="2" * 64,
        )


def test_scoring_does_not_modify_input_documents() -> None:
    manifest, answers, review = _documents()
    before = deepcopy((manifest, answers, review))

    score_review_document(
        manifest,
        answers,
        review,
        manifest_sha256="1" * 64,
        answers_sha256="2" * 64,
    )

    assert (manifest, answers, review) == before


def test_model_emitted_unsupported_citation_is_recorded_as_invalid() -> None:
    manifest, answers, review = _documents()
    review["reviews"][0]["raw_claims"][0]["model_cited_source_ids"] = ["not-retrieved"]
    review["reviews"][0]["raw_claims"][0]["relevant_cited_source_ids"] = []

    result = score_review_document(
        manifest,
        answers,
        review,
        manifest_sha256="1" * 64,
        answers_sha256="2" * 64,
    )

    citation_ids = result["claim_metrics"]["raw"]["citation_ids"]
    assert citation_ids == {"valid": 0, "denominator": 1, "validity_rate": 0.0}


def test_source_review_hash_must_match_when_supplied() -> None:
    manifest, answers, review = _documents()

    with pytest.raises(ReviewValidationError, match="Source review hash"):
        score_review_document(
            manifest,
            answers,
            review,
            manifest_sha256="1" * 64,
            answers_sha256="2" * 64,
            source_review_sha256="9" * 64,
        )


def test_file_evaluator_binds_source_review_and_output_provenance(tmp_path: Path) -> None:
    manifest, answers, review = _documents()
    manifest_raw = json.dumps(manifest).encode()
    answers_raw = json.dumps(answers).encode()
    source_review_raw = b'{"protocol_version":"source-review"}'
    review["provenance"]["manifest_sha256"] = sha256(manifest_raw).hexdigest()
    review["provenance"]["answers_sha256"] = sha256(answers_raw).hexdigest()
    review["provenance"]["source_review_sha256"] = sha256(source_review_raw).hexdigest()
    review_raw = json.dumps(review).encode()
    manifest_file = tmp_path / "manifest.json"
    answers_file = tmp_path / "answers.json"
    review_file = tmp_path / "review.json"
    source_review_file = tmp_path / "source-review.json"
    manifest_file.write_bytes(manifest_raw)
    answers_file.write_bytes(answers_raw)
    review_file.write_bytes(review_raw)
    source_review_file.write_bytes(source_review_raw)

    result = evaluate_review_files(
        manifest_file,
        answers_file,
        review_file,
        source_review_file,
    )

    assert result["provenance"]["review_file_sha256"] == sha256(review_raw).hexdigest()
    source_review_file.write_bytes(b"changed")
    with pytest.raises(ReviewValidationError, match="Source review hash"):
        evaluate_review_files(manifest_file, answers_file, review_file, source_review_file)


def test_report_writer_refuses_to_replace_existing_artifact(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("preserve me", encoding="utf-8")

    with pytest.raises(FileExistsError):
        _write_private_new_file(target, {"status": "complete"})

    assert target.read_text(encoding="utf-8") == "preserve me"
