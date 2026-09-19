# Phase 4 — Evidence Correlation Engine Architecture & Specification

## 1. Research Objective & Context

The central research hypothesis of the **Intelligent API Security Analyzer** is that cross-correlating OpenAPI specification evidence with source-code implementation evidence improves precision, reduces false positives, and provides richer explainability compared to either specification-only or source-only analysis.

Phase 4 introduces the **Evidence Correlation Engine**, which ingests the frozen baseline results from Phase 2 (OpenAPI Specification Analyzer) and Phase 3 (Source-Code Static Analyzer) and determines whether cross-layer evidence:
* **SUPPORTED**: Cross-layer evidence is mutually consistent with the evaluated proposition (e.g. both layers confirm missing authentication on mutations, or both layers confirm authentication controls). `SUPPORTED` does not inherently mean "secure" or "vulnerable"; the rule determines the security conclusion.
* **CONTRADICTED**: The two layers directly conflict (e.g. OpenAPI claims authentication but source code lacks recognizable evidence, or OpenAPI defines a public route while source enforces auth dependencies).
* **COMPLEMENTARY**: The two layers provide distinct, non-overlapping facts that together synthesize a complete risk profile (e.g. OpenAPI exposes a user-controlled object identifier parameter, while source queries a database using that identifier without recognizable authorization checks, forming a correlated BOLA indicator).
* **INCONCLUSIVE**: Evidence exists or is evaluated, but static cross-layer correspondence cannot be established with confidence.

---

## 2. Directory Architecture

The Phase 4 architecture is implemented in two modular packages:

```text
backend/app/analysis/correlation/
├── __init__.py          # Exported symbols and facade
├── models.py            # Immutable frozen dataclasses and StrEnums
├── matcher.py           # Deterministic 4-tier endpoint matching
├── aligner.py           # Cross-layer structured evidence aligner
├── metrics.py           # Benchmark evaluation metrics (Phase 6 slots)
└── engine.py            # CorrelationEngine orchestrator

backend/app/analysis/rules/correlation/
├── __init__.py          # Rule exports
├── base.py              # CorrelationRule abstract base class
├── auth_correlation.py  # CORR-AUTH-001 (Divergence, drift, corroborated missing auth)
├── authz_correlation.py # CORR-AUTHZ-001 (BOLA/IDOR evidence chain synthesis)
├── sensitive_data.py    # CORR-DATA-001 (Contract sensitive data exposure)
├── input_constraints.py # CORR-INPUT-001 (Contract drift vs missing validation)
└── surface_divergence.py# CORR-SURF-001 (Potential Shadow & Zombie endpoints)
```

---

## 3. Deterministic Endpoint Matching

Endpoint matching never uses probabilistic heuristics, fuzzy string matching, vector embeddings, or LLM reasoning. Matching operates via a strict deterministic 4-tier hierarchy:

1. **Exact Match (`EXACT_MATCH`)**:
   Matches identical HTTP method and identical raw path string (e.g., `GET /api/v1/users` matches `GET /api/v1/users`).
2. **Canonical Parameter-Normalized Match (`PARAMETER_NORMALIZED_MATCH`)**:
   Normalizes path parameters to `{param}` templates (e.g., `/users/{userId}` and `/users/{user_id}` both normalize to `/users/{param}`). If exactly one candidate matches, it resolves cleanly.
3. **Disambiguation via `operationId` ↔ `handler_name`**:
   If multiple candidates share the normalized path template, matching checks if OpenAPI `operationId` matches the Python handler function name (case-insensitive, ignoring underscores/hyphens).
4. **Ambiguous Match (`AMBIGUOUS_MATCH`)**:
   If multiple candidates share the path and cannot be disambiguated, an `AMBIGUOUS_MATCH` pair is produced to avoid incorrect correlation.
5. **No Match (`NO_MATCH`)**:
   Operations present only in specification are identified as potential zombie candidates; route handlers present only in source code are identified as potential shadow candidates.

### Semantic Preservation
Canonical parameter normalization is applied **strictly for routing comparison**. The original semantic representations (`spec_path`, `source_path`, parameter names, handler names, locations) are preserved in `MatchedEndpointPair` and all generated findings.

---

## 4. Evidence Alignment & Lineage

The aligner aligns structured evidence items between layers without touching raw ASTs:
* **Authentication**: Aligns `spec_op.effective_security` against `source_ep.auth_state` (`AUTH_PRESENT`, `AUTH_ABSENT_IN_ANALYZABLE_SCOPE`, `AUTH_UNKNOWN`) and `auth_evidence`.
* **Authorization / BOLA**: Aligns path ID parameters against `object_access_evidence`, `authz_evidence`, and `tenant_evidence`.
* **Input Validation**: Strictly maps parameter-level schema constraints to in-handler validation evidence (`symbol` level).
* **Surface Divergence**: Maps unmatched spec endpoints and unmatched source endpoints with qualified terminology.

---

## 5. Result Preservation (`MultiLayerAnalysisResult`)

Phase 4 guarantees **zero mutation** of Phase 2 and Phase 3 findings:
* `spec_only_findings`: The exact tuple of `Finding` instances produced by Phase 2.
* `source_only_findings`: The exact tuple of `Finding` instances produced by Phase 3.
* `correlated_findings`: A dedicated tuple of `CorrelatedFinding` instances containing explicit lineage (`spec_findings`, `source_findings`, `evidence_pairs`, `matched_endpoint`).

---

## 6. Safety & Qualification Guarantees

1. **BOLA Safety Requirement**: BOLA is never inferred solely from the presence of a path parameter. Correlation demands the explicit evidence chain:
   $$\text{Path ID Parameter} \to \text{Data Store Lookup} \to \text{Absence of Authz Checks}$$
   Findings are reported as static indicators requiring architectural verification, never asserting runtime exploitability.
2. **Authentication Safety Requirement**: Absence of authentication in source code is modeled as `AUTH_ABSENT_IN_ANALYZABLE_SCOPE`. Findings acknowledge that upstream gateways, service meshes, or external proxies may enforce security.
3. **Surface Parity Qualification**: Surface divergence findings use strictly qualified terminology:
   - `Potential Shadow Endpoint`
   - `Potential Zombie Endpoint`
   Never claims endpoints are definitively exploitable, malicious, or obsolete.
4. **Confidence Representation**: All numeric confidence values (e.g., `0.80` for `CORR-AUTH-001`, `0.85` for `CORR-AUTHZ-001`) are uncalibrated static-analysis research metadata.
