import json
from pathlib import Path
from typing import Any

import pytest
from app.evaluation.rag_groundedness_v1 import _load_cases, run_groundedness_cases
from app.services import local_ai


def test_groundedness_manifest_requires_pending_human_review(tmp_path: Path) -> None:
    manifest = {
        "protocol_version": "hybrid-rag-groundedness-v1",
        "status": "human_reviewed",
        "cases": [{"case_id": "x", "question": "Question?", "source_findings": []}],
    }
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid groundedness case manifest"):
        _load_cases(path)


def test_runner_records_local_answer_and_keeps_groundedness_unadjudicated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.evaluation.rag_groundedness_v1 as protocol

    case_file = tmp_path / "cases.json"
    case_file.write_text(
        json.dumps(
            {
                "protocol_version": "hybrid-rag-groundedness-v1",
                "status": "draft_pending_human_review",
                "cases": [
                    {
                        "case_id": "sample",
                        "question": "Why was this flagged?",
                        "source_findings": [],
                        "human_review_status": "pending",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        local_ai,
        "get_local_ai_status",
        lambda: {"status": "Available", "model_name": "local-test", "rag_index_status": "missing"},
    )
    monkeypatch.setattr(
        protocol,
        "answer_scan_question",
        lambda *args, **kwargs: {
            "answer": "No matching evidence.",
            "sources": [],
            "retrieval": "local_hybrid_bm25_hashed_vector",
            "index_status": "missing",
            "index_version": None,
        },
    )
    monkeypatch.setattr(
        local_ai,
        "_request_json",
        lambda *args, **kwargs: {"response": "unvalidated raw model response"},
    )

    def rejected_response(*args: object, **kwargs: object) -> None:
        local_ai._request_json("/api/generate", {})
        return None

    monkeypatch.setattr(local_ai, "generate_local_explanation", rejected_response)
    output = tmp_path / "raw.json"

    result = run_groundedness_cases(case_file, output)

    assert result["human_review_status"] == "pending"
    assert result["cases"][0]["raw_model_answer"] is None
    assert result["cases"][0]["raw_ollama_response"] == "unvalidated raw model response"
    assert result["cases"][0]["deterministic_fallback_answer"] == "No matching evidence."
    assert output.stat().st_mode & 0o777 == 0o600
    assert json.loads(output.read_text(encoding="utf-8"))["case_file_sha256"]


def test_groundedness_review_metrics_bind_answer_and_distinguish_validity_from_support(
    tmp_path: Path,
) -> None:
    from app.evaluation.rag_groundedness_v1 import evaluate_groundedness_reviews

    case_file = tmp_path / "cases.json"
    case_file.write_text(
        json.dumps(
            {
                "protocol_version": "hybrid-rag-groundedness-v1",
                "status": "draft_pending_human_review",
                "cases": [
                    {
                        "case_id": "supported-case",
                        "question": "What is supported?",
                        "source_findings": [],
                        "expected_supported_claims": [],
                        "unsupported_or_misleading_claims": [],
                        "expected_citation_references": [],
                        "abstention_appropriate": False,
                        "human_review_status": "pending",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    answer_cases: list[dict[str, Any]] = [
        {
            "case_id": "supported-case",
            "answer_sha256": "answer-hash",
            "retrieved_sources": [{"id": "source-a"}],
        }
    ]
    answer = {
        "protocol_version": "hybrid-rag-groundedness-v1",
        "cases": answer_cases,
    }
    answer_file = tmp_path / "answers.json"
    answer_file.write_text(json.dumps(answer), encoding="utf-8")
    review_file = tmp_path / "review.json"
    review_file.write_text(
        json.dumps(
            {
                "protocol_version": "hybrid-rag-groundedness-review-v1",
                "reviews": [
                    {
                        "case_id": "supported-case",
                        "answer_sha256": "answer-hash",
                        "reviewer": "reviewer-one",
                        "reviewer_notes": "Verified against retrieved source excerpt.",
                        "human_review_status": "reviewed",
                        "answer_abstained": False,
                        "retrieval_found_relevant_evidence": True,
                        "claims": [
                            {
                                "text": "This statement is supported.",
                                "disposition": "supported",
                                "supporting_source_ids": ["source-a"],
                                "model_cited_source_ids": ["source-a", "invalid-id"],
                                "relevant_cited_source_ids": ["source-a"],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = evaluate_groundedness_reviews(case_file, answer_file, review_file)

    assert result["status"] == "human_reviewed"
    assert result["claim_metrics"]["support_rate"] == 1.0
    assert result["citation_metrics"]["citation_reference_validity"] == 0.5
    assert result["citation_metrics"]["citation_correctness"] == 0.5
    assert result["citation_metrics"]["evidence_to_claim_relevance"] == 1.0
    assert result["abstention_metrics"]["appropriate_abstention_accuracy"] == 1.0

    answer_cases[0]["answer_sha256"] = "different-answer"
    answer_file.write_text(json.dumps(answer), encoding="utf-8")
    with pytest.raises(ValueError, match="answer hash binding"):
        evaluate_groundedness_reviews(case_file, answer_file, review_file)


def test_groundedness_review_cli_writes_metrics_and_reports_review_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import sys

    from app.evaluation import rag_groundedness_v1

    case_file = tmp_path / "cases.json"
    case_file.write_text(
        json.dumps(
            {
                "protocol_version": "hybrid-rag-groundedness-v1",
                "status": "draft_pending_human_review",
                "cases": [
                    {
                        "case_id": "reviewed-case",
                        "question": "Is the answer supported?",
                        "source_findings": [],
                        "expected_supported_claims": [],
                        "unsupported_or_misleading_claims": [],
                        "expected_citation_references": [],
                        "abstention_appropriate": True,
                        "human_review_status": "pending",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    answer_file = tmp_path / "answers.json"
    answer_file.write_text(
        json.dumps(
            {
                "protocol_version": "hybrid-rag-groundedness-v1",
                "cases": [
                    {"case_id": "reviewed-case", "answer_sha256": "hash", "retrieved_sources": []}
                ],
            }
        ),
        encoding="utf-8",
    )
    review_file = tmp_path / "review.json"
    review_file.write_text(
        json.dumps(
            {
                "protocol_version": "hybrid-rag-groundedness-review-v1",
                "reviews": [
                    {
                        "case_id": "reviewed-case",
                        "answer_sha256": "hash",
                        "reviewer": "fixture-reviewer",
                        "reviewer_notes": "Test fixture only.",
                        "human_review_status": "reviewed",
                        "answer_abstained": True,
                        "retrieval_found_relevant_evidence": False,
                        "claims": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output_file = tmp_path / "reviewed-metrics.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "rag_groundedness_v1",
            "--cases",
            str(case_file),
            "--answers",
            str(answer_file),
            "--review-file",
            str(review_file),
            "--review-output",
            str(output_file),
        ],
    )

    rag_groundedness_v1.main()

    assert json.loads(output_file.read_text(encoding="utf-8"))["status"] == "human_reviewed"
    assert "scored 1 answer-hash-bound human reviews" in capsys.readouterr().out
