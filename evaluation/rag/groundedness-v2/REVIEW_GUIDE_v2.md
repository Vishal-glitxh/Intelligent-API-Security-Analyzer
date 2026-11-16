# Hybrid RAG Groundedness Review v2

This protocol is a separately versioned, human-adjudicated review of the six immutable r2 answer records. It does not change the `hybrid-rag-groundedness-v1` manifest, scorer, review template, candidate answers, scanner behavior, or historical research results.

## Why v2 exists

The v1 manifest's `abstention_appropriate` field is a proposed reference label. The v1 scorer compares the observed `answer_abstained` value only with that manifest label; it cannot separately encode a human reviewer who disagrees with the proposal. V2 therefore stores and reports three distinct values:

- `manifest_expected_abstention_appropriate`: copied unchanged from the manifest;
- `actual_answer_abstained`: what the final application response did;
- `reviewer_assessed_abstention_appropriate`: the human reviewer's judgment.

V2 publishes manifest agreement and reviewer agreement with separate numerators and denominators. A mismatch is retained as a result, not silently corrected. For Case 5 the manifest expects `false`, the final answer did not abstain (`false`), and the reviewer judged abstention appropriate (`true`). Those values intentionally produce different interpretations.

## Immutable inputs and provenance

- Manifest: `../groundedness-v1/cases-review-ready-v1.json`
- Answers: `../groundedness-v1/candidate-runs/candidate-2026-10-28-targeted-fixes-r2/answers.json`
- Source v1 review record: `../groundedness-v1/review-template-r2-candidate-2026-10-28.json`
- Schema: `review-schema-v2.json`
- Answer-bound v2 review: `review-template-r2-candidate-2026-10-28-v2.json`

The v2 review records the SHA-256 of the manifest, answers, and source v1 review. The original `/tmp/iasa-groundedness-v1-candidate-draft.json` remains **unavailable** with expected SHA-256 `3f30545b06eea66fd13bb84db9a319d3178680ae2bdc20873b8514229f507bbc`. It was a provenance checkpoint, not an r2 runtime input; it was not recreated or replaced. This limitation prevents direct comparison with that earlier candidate-policy sample.

## Review and claim rules

1. Review raw model output and final application output separately. A valid schema or accepted citation ID does not prove semantic support.
2. Claim records are separated into `raw_claims` and `final_claims`. Preserve answer wording, supporting sources, and the model's actual citation IDs. The model-cited list may contain an ID that was not retrieved; record it faithfully so the scorer can count citation validity. `relevant_cited_source_ids` must contain only citations that were both emitted and retrieved and that the reviewer confirms support that claim.
3. `supporting_source_ids` identifies retrieved evidence the reviewer believes supports the claim. A `supported` claim requires at least one supporting source. `uncertain` claims are excluded from support-rate denominators.
4. A proposition that the answer did not assert is not a claim. Put related uncertainty or context in `reviewer_notes`; do not turn a reviewer hypothesis into model output.
5. `raw_response_status` is `generated` only if the immutable answer record contains a raw response. Generated responses require a matching raw-response SHA-256 and an explicit raw response disposition. If the answer record has no raw response, use `not_generated`, null raw hash, null raw overall support, and an empty raw claims list. Null here represents absence of an artifact, not a `Not Applicable` judgment.
6. `final_response_overall_support` and `raw_response_overall_support` summarize the human assessment. Use `unassessed` when the reviewer did not make an overall judgment. Do not infer an overall judgment from individual claims.
7. Each review must include a reviewer identity, notes, exact answer hash, actual abstention, evidence relevance, manifest reference, reviewer abstention judgment, and `review_status: reviewed`. Do not score partial or pending review sets.

The v2 template carries forward explicit human judgments from the existing v1 review record and the user's explicitly supplied case decisions. Case 1's broader uncertainty about possible authorization in another layer and Case 2's concern about public reachability are retained in notes where they do not map to assertions in the answers. They are not invented as model claims. Case 6's raw-response overall support remains null because no raw response exists; the prior raw-support selection is described in notes but is not attached to a nonexistent response.

## Metrics

Run the v2 scorer from the backend directory:

```bash
uv run python -m app.evaluation.rag_groundedness_v2 \
  --cases ../evaluation/rag/groundedness-v1/cases-review-ready-v1.json \
  --answers ../evaluation/rag/groundedness-v1/candidate-runs/candidate-2026-10-28-targeted-fixes-r2/answers.json \
  --review-file ../evaluation/rag/groundedness-v2/review-template-r2-candidate-2026-10-28-v2.json \
  --source-review ../evaluation/rag/groundedness-v1/review-template-r2-candidate-2026-10-28.json \
  --report-output ../evaluation/rag/groundedness-v2/reports/r2-review-metrics-v2.json
```

The report is created as a new private file and the scorer refuses to overwrite an existing output. Metrics include:

- observed abstention agreement with the immutable manifest expectation;
- observed abstention agreement with the reviewer's judgment;
- actual abstention and no-relevant-evidence counts;
- raw response availability, including `not_generated` cases;
- supported/unsupported claim counts and support rates for raw and final responses separately;
- citation-ID validity against retrieved source IDs and reviewer-judged citation relevance.

Each rate includes its denominator. These six hand-selected cases are a small qualitative sample, not a population estimate or proof of general model behavior. The metrics do not replace human review and are not comparable to the v1 manifest-agreement metric unless the chosen label and denominator are stated.

## Case-specific provenance

- Case 5 keeps the manifest's `false` expectation, observed `false` answer behavior, and reviewer `true` appropriateness judgment as separate fields.
- Case 6 has no raw model response. It has no raw claims or raw support disposition; the final abstention is reviewed independently.
- Cases 1 and 2 retain uncertainty about controls outside the static evidence and do not state that unauthorized access or public reachability was established.
- The two negative controls remain separate from generated-answer claim metrics when no raw response exists.

Human review is recorded in the v2 review file. No scores or review decisions are inferred by the scorer; it only aggregates explicit recorded judgments after hash and schema validation.
