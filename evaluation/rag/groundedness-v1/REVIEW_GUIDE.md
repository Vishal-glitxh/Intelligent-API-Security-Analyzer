# `hybrid-rag-groundedness-v1` review guide

This draft is not human reviewed. Do not report groundedness metrics until a reviewer has inspected the actual local-model response, the cited source excerpts, and the expected claims for each included case.

Generate answer samples into a private temporary file:

```bash
cd backend
OLLAMA_MODEL=llama3.2:latest OLLAMA_EMBEDDING_MODEL=nomic-embed-text:latest \
  RAG_INDEX_PATH=scratch/rag-index-v1.json \
  uv run python -m app.evaluation.rag_groundedness_v1 \
  --output /tmp/rag-groundedness-v1-answers.json
```

Review the `raw_ollama_response` for every case, including responses rejected by the application's schema or citation checks. Compare each statement with `retrieved_sources`; a citation ID that exists is not proof that it supports the claim. The draft `expected_supported_claims`, `unsupported_or_misleading_claims`, expected citations, and abstention labels are proposed references that the reviewer must confirm or correct.

Create a separate review file with this shape:

```json
{
  "protocol_version": "hybrid-rag-groundedness-review-v1",
  "reviews": [
    {
      "case_id": "object-ownership-evidence",
      "answer_sha256": "copy answer_sha256 from the matching answer record",
      "reviewer": "reviewer name or audit identifier",
      "reviewer_notes": "Document evidence checks and any corrected reference claims.",
      "human_review_status": "reviewed",
      "answer_abstained": false,
      "retrieval_found_relevant_evidence": true,
      "claims": [
        {
          "text": "one factual claim from the generated response",
          "disposition": "supported",
          "supporting_source_ids": ["finding-source code-0"],
          "model_cited_source_ids": ["finding-source code-0"],
          "relevant_cited_source_ids": ["finding-source code-0"]
        }
      ]
    }
  ]
}
```

Use `unsupported` for a contradicted or unsupported factual claim and `uncertain` when the evidence does not permit a reliable judgment; uncertain claims are excluded from the support-rate denominator. `supporting_source_ids` records the human-identified evidence that supports a claim. `model_cited_source_ids` must reflect what the model actually emitted, including unsupported IDs from a rejected response. `relevant_cited_source_ids` contains only cited IDs that the reviewer confirms support that particular claim. Set `answer_abstained` from the reviewed answer, not from a citation check. Set `retrieval_found_relevant_evidence` from the reviewed source content, not topical similarity.

Score only the answer-hash-bound human reviews, writing a separate private result:

```bash
cd backend
uv run python -m app.evaluation.rag_groundedness_v1 \
  --answers /tmp/rag-groundedness-v1-answers.json \
  --review-file /path/to/human-review.json \
  --review-output /tmp/rag-groundedness-v1-reviewed-metrics.json
```

The report separately counts supported and unsupported claims, citation ID validity against retrieved IDs, citation correctness, human-marked evidence-to-claim relevance, abstention agreement with reviewed case labels, and abstention when the reviewer found no relevant retrieved evidence. A review file is accepted only when it names a reviewer, marks a case reviewed, supplies reviewer notes, and binds to the exact answer hash.

## Precision sprint review copy

`cases-review-ready-v1.json` is the six-case copy prepared for human adjudication. It identifies the frozen-analyzer fixture-derived case, illustrative static-finding cases, and negative controls. Every case and checklist item remains pending; no reviewer identity or judgment has been prefilled. Use `review-template-r2-candidate-2026-10-28.json` for the r2 answers; its six records are bound to each corresponding `answer_sha256` in the immutable r2 answer file. It remains pending and is not scoreable until a human completes every included review.

The immutable candidate answers and report are in `candidate-runs/candidate-2026-10-28-targeted-fixes-r2/answers.json` and `candidate-runs/candidate-2026-10-28-targeted-fixes-r2/REPORT.md`. Their SHA-256 values are respectively `655b706267a57e941c2e5f6258a53c971b13705ac6f1bfd75195ac4357f114f9` and `26c470b9838fa51753c031b0f0654cf8b7e1caebb13ae851c4bb5c4daa22ed20`. The run used `llama3.2:latest` (digest `a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72`) and `nomic-embed-text:latest` with the compatible index version recorded in the answer file. Four cases have raw Ollama responses; all four were rejected by application validation and used deterministic fallbacks. Two no-evidence controls abstained before generation and have no raw response. Review every raw response as well as the final application answer; a citation ID existing or passing a schema check is not evidence of groundedness.

The earlier temporary provenance checkpoint `/tmp/iasa-groundedness-v1-candidate-draft.json` is unavailable (expected SHA-256 `3f30545b06eea66fd13bb84db9a319d3178680ae2bdc20873b8514229f507bbc`). It was not recreated or replaced. Its absence prevents direct comparison with that earlier candidate-policy sample; it is not an r2 runtime input.

For every case, confirm the expected answer scope, source evidence, supported and unsupported claims, citation support per claim, abstention decision, and rationale. `object-ownership-evidence` derives from the frozen analyzer running on `backend/tests/fixtures/source/fastapi_vulnerable.py`; the other findings are illustrative fixtures and the no-evidence cases are negative controls. Do not mark checklist fields complete until a human has inspected the exact candidate output and retrieved excerpts. If the sample is too small to assess, record that limitation in reviewer notes rather than inferring general behavior.

After a human completes the pending records in `review-template-r2-candidate-2026-10-28.json`, score that review against the immutable r2 answer file:

```bash
cd backend
uv run python -m app.evaluation.rag_groundedness_v1 \
  --cases ../evaluation/rag/groundedness-v1/cases-review-ready-v1.json \
  --answers \
    ../evaluation/rag/groundedness-v1/candidate-runs/candidate-2026-10-28-targeted-fixes-r2/answers.json \
  --review-file \
    ../evaluation/rag/groundedness-v1/review-template-r2-candidate-2026-10-28.json \
  --review-output /tmp/iasa-groundedness-v1-r2-reviewed-metrics.json
```

The template is intentionally incomplete and the command must reject it until a reviewer supplies real judgments, identity, notes, and abstention/retrieval decisions.
