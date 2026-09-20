# Phase 6 Research Evaluation — Individual Security Proposition Trace

## 1. Methodology Note
This document traces all **22 Dimension-A security propositions** across the 24 benchmark cases of the Intelligent API Security Analyzer. Each proposition represents an explicit, fine-grained security condition (`missing_authentication`, `missing_object_level_authorization`, `unconstrained_input`, `sensitive_data_exposure`, `hardcoded_secret`) evaluated against three independent execution modes:
1. **SPEC_ONLY**: Static evaluation of OpenAPI 3.0 specification evidence alone.
2. **SOURCE_ONLY**: Static AST evaluation of Python source code evidence alone.
3. **CORRELATED**: Multi-layer cross-evidence correlation aligning spec operations and source handlers.

Ground truth labels and analyzer findings are preserved strictly as produced during the post-fix Phase 6 benchmark execution. No code, rules, parameters, or ground truth definitions were altered during this tracing.

### Definition of the CORRELATED Evaluation Layer
1. **SPEC_ONLY** evaluates findings emitted by the specification-only analyzer.
2. **SOURCE_ONLY** evaluates findings emitted by the source-only analyzer.
3. **CORRELATED** evaluates findings emitted by the Phase 4 cross-layer correlation engine, specifically the `correlated_findings` result set.
4. **CORRELATED is NOT defined as**: `SOURCE_ONLY` findings + specification findings + correlation findings.
5. A source-only finding without an OpenAPI counterpart may therefore be absent from the `CORRELATED` finding set.
6. This is intentional in the current experimental design because the research component under evaluation is cross-layer evidence correlation.
7. Consequently, source-intrinsic conditions such as hardcoded secrets may be detected in `SOURCE_ONLY` but not represented in `CORRELATED` if no correlation rule applies.
8. **SECRET-001** is the concrete benchmark example: `SPEC_ONLY = FN`, `SOURCE_ONLY = TP`, `CORRELATED = FN`.
9. This does **NOT** mean the underlying source analyzer failed to detect `SECRET-001`. The source analyzer correctly produced `API-SECRET-001`.
10. The result demonstrates a boundary of the current `CORRELATED` evaluation-layer definition: cross-layer correlation requires complementary evidence across the specification and source layers.
11. This limitation must be distinguished from a vulnerability-detection failure.

### Evaluation Limitation
The `CORRELATED` layer measures findings produced by cross-layer correlation rules rather than the union of all specification and source findings. Therefore, source-intrinsic security conditions that have no corresponding OpenAPI evidence surface may be absent from the `CORRELATED` result set. `SECRET-001` demonstrates this boundary: the source-only analyzer correctly detects a hardcoded-secret condition, while no correlation rule emits a correlated finding because the condition has no OpenAPI counterpart. This distinction is important when interpreting recall and false-negative metrics for the `CORRELATED` layer.

The three modes are therefore distinct experimental baselines, not cumulative stages in which every finding from an earlier layer must survive into the next layer.

---

## 2. Full 22-Row Security Proposition Table

| proposition_id | category | endpoint | method | condition | ground_truth | SPEC_ONLY_prediction | SPEC_ONLY_classification | SOURCE_ONLY_prediction | SOURCE_ONLY_classification | CORRELATED_prediction | CORRELATED_classification | spec_evidence_present | source_evidence_present | correlated_evidence_present | explanation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| PROP-AUTH-001 | authentication | `/api/v1/profile` | `GET` | `missing_authentication` | `false` | `None` | **TN** | `None` | **TN** | `None` | **TN** | false | false | false | Case AUTH-001: GT=False. SPEC=TN (None), SOURCE=TN (None), CORR=TN (None). |
| PROP-AUTH-002 | authentication | `/api/v1/admin/users` | `GET` | `missing_authentication` | `true` | `None` | **FN** | `API-SOURCE-AUTH-001` | **TP** | `CORR-AUTH-001` | **TP** | false | true | true | Case AUTH-002: GT=True. SPEC=FN (None), SOURCE=TP (API-SOURCE-AUTH-001), CORR=TP (CORR-AUTH-001). |
| PROP-AUTH-003 | authentication | `/api/v1/health` | `GET` | `missing_authentication` | `false` | `API-AUTH-001` | **FP** | `API-SOURCE-AUTH-001` | **FP** | `None` | **TN** | true | true | false | Case AUTH-003: GT=False. SPEC=FP (API-AUTH-001), SOURCE=FP (API-SOURCE-AUTH-001), CORR=TN (None). |
| PROP-AUTH-004 | authentication | `/api/v1/public/ping` | `GET` | `missing_authentication` | `false` | `API-AUTH-001` | **FP** | `API-SOURCE-AUTH-001` | **FP** | `None` | **TN** | true | true | false | Case AUTH-004: GT=False. SPEC=FP (API-AUTH-001), SOURCE=FP (API-SOURCE-AUTH-001), CORR=TN (None). |
| PROP-AUTH-005 | authentication | `/api/v1/secure/data` | `GET` | `missing_authentication` | `false` | `None` | **TN** | `None` | **TN** | `None` | **TN** | false | false | false | Case AUTH-005: GT=False. SPEC=TN (None), SOURCE=TN (None), CORR=TN (None). |
| PROP-AUTHZ-001 | authorization | `/api/v1/documents/{doc_id}` | `GET` | `missing_object_level_authorization` | `false` | `API-AUTHZ-001` | **FP** | `None` | **TN** | `None` | **TN** | true | false | false | Case AUTHZ-001: GT=False. SPEC=FP (API-AUTHZ-001), SOURCE=TN (None), CORR=TN (None). |
| PROP-AUTHZ-002 | authorization | `/api/v1/accounts/{account_id}` | `GET` | `missing_object_level_authorization` | `true` | `API-AUTHZ-001` | **TP** | `API-SOURCE-AUTHZ-001` | **TP** | `CORR-AUTHZ-001` | **TP** | true | true | true | Case AUTHZ-002: GT=True. SPEC=TP (API-AUTHZ-001), SOURCE=TP (API-SOURCE-AUTHZ-001), CORR=TP (CORR-AUTHZ-001). |
| PROP-AUTHZ-003 | authorization | `/api/v1/projects/{project_id}` | `GET` | `missing_object_level_authorization` | `false` | `API-AUTHZ-001` | **FP** | `API-SOURCE-AUTHZ-001` | **FP** | `CORR-AUTHZ-001` | **FP** | true | true | true | Case AUTHZ-003: GT=False. SPEC=FP (API-AUTHZ-001), SOURCE=FP (API-SOURCE-AUTHZ-001), CORR=FP (CORR-AUTHZ-001). |
| PROP-AUTHZ-004 | authorization | `/api/v1/orders/{order_id}` | `GET` | `missing_object_level_authorization` | `true` | `API-AUTHZ-001` | **TP** | `API-SOURCE-AUTHZ-001` | **TP** | `CORR-AUTHZ-001` | **TP** | true | true | true | Case AUTHZ-004: GT=True. SPEC=TP (API-AUTHZ-001), SOURCE=TP (API-SOURCE-AUTHZ-001), CORR=TP (CORR-AUTHZ-001). |
| PROP-AUTHZ-005 | authorization | `/api/v1/reports/{report_id}` | `GET` | `missing_object_level_authorization` | `true` | `API-AUTHZ-001` | **TP** | `API-SOURCE-AUTHZ-001` | **TP** | `CORR-AUTHZ-001` | **TP** | true | true | true | Case AUTHZ-005: GT=True. SPEC=TP (API-AUTHZ-001), SOURCE=TP (API-SOURCE-AUTHZ-001), CORR=TP (CORR-AUTHZ-001). |
| PROP-DATA-001 | sensitive_data | `/api/v1/products` | `GET` | `sensitive_data_exposure` | `false` | `None` | **TN** | `None` | **TN** | `None` | **TN** | false | false | false | Case DATA-001: GT=False. SPEC=TN (None), SOURCE=TN (None), CORR=TN (None). |
| PROP-DATA-002 | sensitive_data | `/api/v1/users/{id}` | `GET` | `sensitive_data_exposure` | `true` | `API-DATA-001` | **TP** | `None` | **FN** | `CORR-DATA-001` | **TP** | true | false | true | Case DATA-002: GT=True. SPEC=TP (API-DATA-001), SOURCE=FN (None), CORR=TP (CORR-DATA-001). |
| PROP-DATA-003 | sensitive_data | `/api/v1/public_key` | `GET` | `sensitive_data_exposure` | `false` | `None` | **TN** | `None` | **TN** | `None` | **TN** | false | false | false | Case DATA-003: GT=False. SPEC=TN (None), SOURCE=TN (None), CORR=TN (None). |
| PROP-DATA-004 | sensitive_data | `/api/v1/items` | `GET` | `sensitive_data_exposure` | `false` | `None` | **TN** | `None` | **TN** | `None` | **TN** | false | false | false | Case DATA-004: GT=False. SPEC=TN (None), SOURCE=TN (None), CORR=TN (None). |
| PROP-INPUT-001 | input_validation | `/api/v1/users` | `POST` | `unconstrained_input` | `false` | `None` | **TN** | `None` | **TN** | `None` | **TN** | false | false | false | Case INPUT-001: GT=False. SPEC=TN (None), SOURCE=TN (None), CORR=TN (None). |
| PROP-INPUT-002 | input_validation | `/api/v1/search` | `POST` | `unconstrained_input` | `true` | `None` | **FN** | `None` | **FN** | `None` | **FN** | false | false | false | Case INPUT-002: GT=True. SPEC=FN (None), SOURCE=FN (None), CORR=FN (None). |
| PROP-INPUT-003 | input_validation | `/api/v1/register` | `POST` | `unconstrained_input` | `true` | `None` | **FN** | `None` | **FN** | `None` | **FN** | false | false | false | Case INPUT-003: GT=True. SPEC=FN (None), SOURCE=FN (None), CORR=FN (None). |
| PROP-INPUT-004 | input_validation | `/api/v1/comments` | `POST` | `unconstrained_input` | `false` | `None` | **TN** | `None` | **TN** | `None` | **TN** | false | false | false | Case INPUT-004: GT=False. SPEC=TN (None), SOURCE=TN (None), CORR=TN (None). |
| PROP-SECRET-001 | secrets | `N/A` | `N/A` | `hardcoded_secret` | `true` | `None` | **FN** | `API-SECRET-001` | **TP** | `None` | **FN** | false | true | false | Case SECRET-001: GT=True. SPEC=FN (None), SOURCE=TP (API-SECRET-001), CORR=FN (None). |
| PROP-SECRET-002 | secrets | `N/A` | `N/A` | `hardcoded_secret` | `false` | `None` | **TN** | `None` | **TN** | `None` | **TN** | false | false | false | Case SECRET-002: GT=False. SPEC=TN (None), SOURCE=TN (None), CORR=TN (None). |
| PROP-SECRET-003 | secrets | `N/A` | `N/A` | `hardcoded_secret` | `false` | `None` | **TN** | `None` | **TN** | `None` | **TN** | false | false | false | Case SECRET-003: GT=False. SPEC=TN (None), SOURCE=TN (None), CORR=TN (None). |
| PROP-SECRET-004 | secrets | `N/A` | `N/A` | `hardcoded_secret` | `false` | `None` | **TN** | `API-SECRET-001` | **FP** | `None` | **TN** | false | true | false | Case SECRET-004: GT=False. SPEC=TN (None), SOURCE=FP (API-SECRET-001), CORR=TN (None). |

---

## 3. Category Summary

| category | propositions | positives | negatives | SPEC TP FP FN TN | SOURCE TP FP FN TN | CORRELATED TP FP FN TN |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Authentication | 5 | 1 | 4 | 0 / 2 / 1 / 2 | 1 / 2 / 0 / 2 | 1 / 0 / 0 / 4 |
| Authorization / BOLA | 5 | 3 | 2 | 3 / 2 / 0 / 0 | 3 / 1 / 0 / 1 | 3 / 1 / 0 / 1 |
| Input Validation | 4 | 2 | 2 | 0 / 0 / 2 / 2 | 0 / 0 / 2 / 2 | 0 / 0 / 2 / 2 |
| Sensitive Data | 4 | 1 | 3 | 1 / 0 / 0 / 3 | 0 / 0 / 1 / 3 | 1 / 0 / 0 / 3 |
| Hardcoded Secrets | 4 | 1 | 3 | 0 / 0 / 1 / 3 | 1 / 1 / 0 / 2 | 0 / 0 / 1 / 3 |
| **Total** | **22** | **8** | **14** | **4 / 4 / 4 / 10** | **5 / 4 / 3 / 10** | **5 / 1 / 3 / 13** |

---

## 4. FP/FN Error Trace & Root Cause Analysis

### PROP-AUTH-002 (AUTH-002)
- **Expected Condition**: `true (missing_authentication)`
- **Evaluation Mode(s)**: SPEC_ONLY
- **Outcome / Prediction**: **FN** (`None`)
- **Evidence Used**: OpenAPI spec defines global security scheme `bearerAuth`; source code lacks auth decorator on `/api/v1/admin/users`.
- **Divergence Explanation**: Spec-only analyzer observes security scheme declaration in OpenAPI spec and assumes authentication is required, predicting no spec vulnerability finding.
- **Identified Root Cause**: Specification-only analysis limitation (specification metadata does not reveal missing source code handler security decorators).

### PROP-AUTH-003 (AUTH-003)
- **Expected Condition**: `false (missing_authentication absent)`
- **Evaluation Mode(s)**: SPEC_ONLY, SOURCE_ONLY
- **Outcome / Prediction**: **FP (SPEC_ONLY: API-AUTH-001, SOURCE_ONLY: API-SOURCE-AUTH-001)** (`API-AUTH-001 / API-SOURCE-AUTH-001`)
- **Evidence Used**: OpenAPI spec lacks security on `/api/v1/health`; source code handler lacks `@app.get` auth decorator.
- **Divergence Explanation**: Both single-layer analyzers flag missing authentication heuristics on public health check endpoint because neither layer alone can infer intentional public design intent.
- **Identified Root Cause**: Specification-only and Source-only analysis limitations. Resolved in CORRELATED mode where cross-layer alignment recognizes public endpoint context.

### PROP-AUTH-004 (AUTH-004)
- **Expected Condition**: `false (missing_authentication absent)`
- **Evaluation Mode(s)**: SPEC_ONLY, SOURCE_ONLY
- **Outcome / Prediction**: **FP (SPEC_ONLY: API-AUTH-001, SOURCE_ONLY: API-SOURCE-AUTH-001)** (`API-AUTH-001 / API-SOURCE-AUTH-001`)
- **Evidence Used**: Spec has global security but explicit operation override `security: []` on `/api/v1/public/ping`; source handler lacks auth decorator.
- **Divergence Explanation**: Single-layer rules interpret missing auth as a vulnerability. CORRELATED mode correctly validates the explicit public override.
- **Identified Root Cause**: Single-layer rule heuristic scope boundary. Resolved in CORRELATED mode.

### PROP-AUTHZ-001 (AUTHZ-001)
- **Expected Condition**: `false (missing_object_level_authorization absent)`
- **Evaluation Mode(s)**: SPEC_ONLY
- **Outcome / Prediction**: **FP** (`API-AUTHZ-001`)
- **Evidence Used**: OpenAPI path parameter `/api/v1/documents/{doc_id}` lacks schema-level authz metadata. Source function contains `verify_document_access()`.
- **Divergence Explanation**: Spec-only rule flags potential BOLA/IDOR on all path parameter endpoints. Source analyzer detects `verify_document_access()`.
- **Identified Root Cause**: Specification-only analysis limitation (OpenAPI contracts do not capture internal function-level authorization checks). Resolved in CORRELATED mode.

### PROP-AUTHZ-003 (AUTHZ-003)
- **Expected Condition**: `false (missing_object_level_authorization absent)`
- **Evaluation Mode(s)**: SPEC_ONLY, SOURCE_ONLY, CORRELATED
- **Outcome / Prediction**: **FP (SPEC: API-AUTHZ-001, SOURCE: API-SOURCE-AUTHZ-001, CORR: CORR-AUTHZ-001)** (`API-AUTHZ-001 / API-SOURCE-AUTHZ-001 / CORR-AUTHZ-001`)
- **Evidence Used**: Path parameter `/api/v1/projects/{project_id}` uses custom project permission helper `check_project_permission()` outside standard AST symbol table.
- **Divergence Explanation**: Custom authorization helper is not included in built-in AST symbol table (`_AUTHZ_CALL_NAMES`), causing both source and spec analyzers to report missing object-level authorization.
- **Identified Root Cause**: Analyzer capability boundary (AST static analysis symbol table coverage for custom helper functions).

### PROP-INPUT-002 (INPUT-002)
- **Expected Condition**: `true (unconstrained_input)`
- **Evaluation Mode(s)**: SPEC_ONLY, SOURCE_ONLY, CORRELATED
- **Outcome / Prediction**: **FN (No finding produced)** (`None`)
- **Evidence Used**: POST `/api/v1/search` request body schema has unconstrained string field; source handler accepts unvalidated payload.
- **Divergence Explanation**: Analyzer rule `InputConstraintsRule` requires object property constraints or explicit schema definitions beyond raw dictionary payloads.
- **Identified Root Cause**: Analyzer capability boundary (input validation rule trigger threshold for body payload schemas).

### PROP-INPUT-003 (INPUT-003)
- **Expected Condition**: `true (unconstrained_input)`
- **Evaluation Mode(s)**: SPEC_ONLY, SOURCE_ONLY, CORRELATED
- **Outcome / Prediction**: **FN (No finding produced)** (`None`)
- **Evidence Used**: POST `/api/v1/register` has string fields without length/format constraints.
- **Divergence Explanation**: Partial input validation in source code was not categorized as a full unconstrained input finding by rule threshold.
- **Identified Root Cause**: Analyzer capability boundary (partial vs full input constraint heuristic).

### PROP-DATA-002 (DATA-002)
- **Expected Condition**: `true (sensitive_data_exposure)`
- **Evaluation Mode(s)**: SOURCE_ONLY
- **Outcome / Prediction**: **FN** (`None`)
- **Evidence Used**: Source code returns `user.to_dict()` containing `ssn` field; OpenAPI spec explicitly documents `ssn` property in response schema.
- **Divergence Explanation**: AST source parser cannot inspect ORM class attribute schemas or dynamic dictionary serialization in `SOURCE_ONLY` mode. `SPEC_ONLY` and `CORRELATED` modes successfully detect it.
- **Identified Root Cause**: Source-only analysis limitation (dynamic ORM dictionary serialization cannot be resolved from source AST alone).

### PROP-SECRET-001 (SECRET-001)
- **Expected Condition**: `true (hardcoded_secret)`
- **Evaluation Mode(s)**: SPEC_ONLY, CORRELATED
- **Outcome / Prediction**: **FN** (`None`)
- **Evidence Used**: Source code contains `AWS_SECRET_KEY = "AKIAIOSFODNN7NOTREAL"`. OpenAPI specification does not contain hardcoded source secrets.
- **Divergence Explanation**: Secrets are module-level source code security findings, not spec-level or endpoint-matched cross-layer findings. `SOURCE_ONLY` mode correctly predicts TP (`API-SECRET-001`).
- **Identified Root Cause**: Specification-only limitation (secrets reside in source code) and Correlation engine scope definition (secrets are source-level non-endpoint findings).

### PROP-SECRET-004 (SECRET-004)
- **Expected Condition**: `false (hardcoded_secret absent)`
- **Evaluation Mode(s)**: SOURCE_ONLY
- **Outcome / Prediction**: **FP** (`API-SECRET-001`)
- **Evidence Used**: Test file `test_app.py` contains `API_KEY = "sk_test_51Mz..."`. Source secret rule flags hardcoded string literal.
- **Divergence Explanation**: Source-only AST parser scans all `.py` files without filtering test context heuristics. CORRELATED mode eliminates this FP by requiring alignment with OpenAPI endpoints.
- **Identified Root Cause**: Source-only analysis limitation (test file context isolation). Resolved in CORRELATED mode.

---

## 5. Correlation Effect Trace

| proposition_id | SPEC_ONLY result | SOURCE_ONLY result | CORRELATED result | change_type | evidence responsible | correlation rationale |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| PROP-AUTH-002 | FN (None) | TP (API-SOURCE-AUTH-001) | TP (CORR-AUTH-001) | **FN_REMOVED** | Spec bearer requirement vs source missing auth decorator (`CONTRADICTED`). | Cross-layer correlation detects discrepancy between OpenAPI security declaration and un-decorated source handler, removing spec-only FN. |
| PROP-AUTH-003 | FP (API-AUTH-001) | FP (API-SOURCE-AUTH-001) | TN (None) | **FP_REMOVED** | Spec public endpoint aligned with un-decorated source handler (`/api/v1/health`). | Cross-layer alignment confirms endpoint is intentionally public, eliminating single-layer false positive missing auth heuristics. |
| PROP-AUTH-004 | FP (API-AUTH-001) | FP (API-SOURCE-AUTH-001) | TN (None) | **FP_REMOVED** | Spec operation override `security: []` aligned with source handler (`/api/v1/public/ping`). | Cross-layer alignment recognizes explicit operation-level security override, eliminating false positives. |
| PROP-AUTHZ-001 | FP (API-AUTHZ-001) | TN (None) | TN (None) | **FP_REMOVED** | Spec `{doc_id}` parameter aligned with source containing `verify_document_access()`. | Source authorization evidence refutes specification-only BOLA suspicion, removing spec-only FP. |
| PROP-DATA-002 | TP (API-DATA-001) | FN (None) | TP (CORR-DATA-001) | **FN_REMOVED** | Spec response schema property `ssn` aligned with source handler returning user object (`SUPPORTED`). | Specification response contract evidence recovers source-only FN where ORM dictionary serialization masked field sensitivity. |
| PROP-SECRET-001 | FN (None) | TP (API-SECRET-001) | FN (None) | **FN_INTRODUCED** | Source AST assigns hardcoded secret `AWS_SECRET_KEY = 'AKIAIOSFODNN7NOTREAL'`; OpenAPI spec contains no secrets. | The source analyzer detects API-SECRET-001, but the current CORRELATED layer contains only findings emitted by cross-layer correlation rules. Hardcoded secrets are source-only non-endpoint findings without an OpenAPI counterpart, so no CorrelatedFinding is emitted for SECRET-001. |
| PROP-SECRET-004 | TN (None) | FP (API-SECRET-001) | TN (None) | **FP_REMOVED** | Source secret in test file not matched to any OpenAPI specification endpoint. | Endpoint matching alignment isolates non-endpoint test fixture secrets from production API security surface findings. |

---

## 6. Aggregate Consistency Check

Recalculated metrics from the 22 individual proposition rows:

| Analysis Mode | TP | FP | FN | TN | Total | Precision | Recall | F1 Score | FPR | FNR | Exact Match Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **SPEC_ONLY** | 4 | 4 | 4 | 10 | 22 | 0.5000 | 0.5000 | 0.5000 | 0.2857 | 0.5000 | **MATCH** |
| **SOURCE_ONLY** | 5 | 4 | 3 | 10 | 22 | 0.5556 | 0.6250 | 0.5882 | 0.2857 | 0.3750 | **MATCH** |
| **CORRELATED** | 5 | 1 | 3 | 13 | 22 | 0.8333 | 0.6250 | 0.7143 | 0.0714 | 0.3750 | **MATCH** |

### Metric Formulas Verification
- **SPEC_ONLY**:
  - Precision = 4 / (4 + 4) = **0.5000**
  - Recall = 4 / (4 + 4) = **0.5000**
  - F1 = 2 * (0.5 * 0.5) / (0.5 + 0.5) = **0.5000**
  - FPR = 4 / (4 + 10) = **0.2857**
  - FNR = 4 / (4 + 4) = **0.5000**
- **SOURCE_ONLY**:
  - Precision = 5 / (5 + 4) = **0.5556**
  - Recall = 5 / (5 + 3) = **0.6250**
  - F1 = 2 * (5/9 * 5/8) / (5/9 + 5/8) = **0.5882**
  - FPR = 4 / (4 + 10) = **0.2857**
  - FNR = 3 / (5 + 3) = **0.3750**
- **CORRELATED**:
  - Precision = 5 / (5 + 1) = **0.8333**
  - Recall = 5 / (5 + 3) = **0.6250**
  - F1 = 2 * (5/6 * 5/8) / (5/6 + 5/8) = **0.7143**
  - FPR = 1 / (1 + 13) = **0.0714**
  - FNR = 3 / (5 + 3) = **0.3750**

---

Dimension A proposition trace is reproducible and consistent with the reported Phase 6 aggregate metrics.
