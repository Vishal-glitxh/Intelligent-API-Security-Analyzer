# Intelligent API Security Analyzer — Evaluation Dataset

## Dataset Overview
- **Dataset Version**: 6.0.0
- **Total Cases**: 24 cases
- **Total Execution Runs**: 72 runs (24 cases × 3 analysis modes: `SPEC_ONLY`, `SOURCE_ONLY`, `CORRELATED`)

## Research Principles
1. **Independent Ground Truth**: Ground truth is defined independently prior to analysis. Analyzer findings are never used to define ground truth.
2. **Static Security Conditions**: Ground truth labels describe static security conditions (e.g. `missing_authentication`, `unconstrained_input`), not runtime exploitability claims.
3. **Decoupled Evaluation Dimensions**:
   - **Dimension A**: Security Detection Evaluation (`TP`/`FP`/`FN`/`TN`, Precision, Recall, F1, FPR, FNR)
   - **Dimension B**: Correlation-State Evaluation (`SUPPORTED`, `CONTRADICTED`, `COMPLEMENTARY`, `INCONCLUSIVE`)
   - **Dimension C**: Endpoint Matching Evaluation (`EXACT_MATCH`, `PARAMETER_NORMALIZED_MATCH`, `AMBIGUOUS_MATCH`, `NO_MATCH`)

## Case Distribution (24 Cases)
- **Authentication (AUTH 001–005)**: 5 cases
- **Authorization / BOLA (AUTHZ 001–005)**: 5 cases
- **Input Validation (INPUT 001–004)**: 4 cases
- **Sensitive Data Exposure (DATA 001–004)**: 4 cases
- **Hardcoded Secrets (SECRET 001–004)**: 4 cases
- **Cross-Layer Correlation (CORR-001)**: 1 case
- **Endpoint Matching (MATCH-001)**: 1 case (multi-pair)

## Definition of the CORRELATED Evaluation Layer
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

## Evaluation Limitation
The `CORRELATED` layer measures findings produced by cross-layer correlation rules rather than the union of all specification and source findings. Therefore, source-intrinsic security conditions that have no corresponding OpenAPI evidence surface may be absent from the `CORRELATED` result set. `SECRET-001` demonstrates this boundary: the source-only analyzer correctly detects a hardcoded-secret condition, while no correlation rule emits a correlated finding because the condition has no OpenAPI counterpart. This distinction is important when interpreting recall and false-negative metrics for the `CORRELATED` layer.

The three modes are therefore distinct experimental baselines, not cumulative stages in which every finding from an earlier layer must survive into the next layer.

