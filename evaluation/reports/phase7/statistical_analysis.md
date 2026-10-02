# Phase 7 Statistical Analysis & Research Hardening Report

**Dataset Version**: 6.0.0
**Total Benchmark Cases**: 24
**Dimension-A Security Propositions**: 22

---

## 1. Executive Summary

This report provides the formal statistical analysis for **Phase 7 Research Hardening**
over the frozen Phase 6 evaluation baseline of the **Intelligent API Security Analyzer**.

The analysis evaluates three experimental modes (`SPEC_ONLY`, `SOURCE_ONLY`, `CORRELATED`)
across 24 benchmark cases and 22 Dimension-A security propositions. Statistical uncertainty is
quantified using **95% Wilson Score Confidence Intervals** for binomial proportions and a
**10,000-sample percentile bootstrap** for the non-linear F1 score.

### Primary Results Summary
- **SPEC_ONLY**: Precision = `0.5000` (95% CI: `[0.2152, 0.7848]`),
  Recall = `0.5000` (95% CI: `[0.2152, 0.7848]`),
  F1 = `0.5000` (95% CI: `[0.2222, 0.7500]`).
- **SOURCE_ONLY**: Precision = `0.5556` (95% CI: `[0.2667, 0.8112]`),
  Recall = `0.6250` (95% CI: `[0.3057, 0.8632]`),
  F1 = `0.5882` (95% CI: `[0.3333, 0.8000]`).
- **CORRELATED**: Precision = **`0.8333`** (95% CI: **`[0.4365, 0.9699]`**),
  Recall = `0.6250` (95% CI: `[0.3057, 0.8632]`),
  F1 = **`0.7143`** (95% CI: **`[0.4444, 0.8889]`**),
  FPR = **`0.0714`** (95% CI: **`[0.0127, 0.3147]`**).
- **Dimension B (Correlation Accuracy)**: **`1.0000`** (95% CI: `[0.2471, 1.0000]`).
- **Dimension C (Endpoint Match Accuracy)**: **`1.0000`** (95% CI: `[0.5101, 1.0000]`).

---

## 2. 95% Confidence Intervals (Wilson Score & Bootstrap)

| Mode | Metric | Point Est. | 95% Confidence Interval | Method |
|:---|:---|:---|:---|:---|
| `SPEC_ONLY` | Precision | `0.5000` | `[0.2152, 0.7848]` | Wilson Score ($N=8$) |
| `SPEC_ONLY` | Recall | `0.5000` | `[0.2152, 0.7848]` | Wilson Score ($N=8$) |
| `SPEC_ONLY` | F1 Score | `0.5000` | `[0.2222, 0.7500]` | Bootstrap ($B=10k, N=22$) |
| `SPEC_ONLY` | FPR | `0.2857` | `[0.1170, 0.5464]` | Wilson Score ($N=14$) |
| `SOURCE_ONLY` | Precision | `0.5556` | `[0.2667, 0.8112]` | Wilson Score ($N=9$) |
| `SOURCE_ONLY` | Recall | `0.6250` | `[0.3057, 0.8632]` | Wilson Score ($N=8$) |
| `SOURCE_ONLY` | F1 Score | `0.5882` | `[0.3333, 0.8000]` | Bootstrap ($B=10k, N=22$) |
| `SOURCE_ONLY` | FPR | `0.2857` | `[0.1170, 0.5464]` | Wilson Score ($N=14$) |
| `CORRELATED` | Precision | **`0.8333`** | `[0.4365, 0.9699]` | Wilson Score ($N=6$) |
| `CORRELATED` | Recall | `0.6250` | `[0.3057, 0.8632]` | Wilson Score ($N=8$) |
| `CORRELATED` | F1 Score | **`0.7143`** | `[0.4444, 0.8889]` | Bootstrap ($B=10k, N=22$) |
| `CORRELATED` | FPR | **`0.0714`** | `[0.0127, 0.3147]` | Wilson Score ($N=14$) |

---

## 3. Mode Comparisons & Absolute Differences

| Metric | Baseline | Comparison | Base | CORR | Diff | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| Precision | `SPEC_ONLY` | `CORRELATED` | `0.5000` | `0.8333` | **`+0.3333`** | $N=22$ |
| Recall | `SPEC_ONLY` | `CORRELATED` | `0.5000` | `0.6250` | **`+0.1250`** | $N=22$ |
| F1 | `SPEC_ONLY` | `CORRELATED` | `0.5000` | `0.7143` | **`+0.2143`** | $N=22$ |
| FPR | `SPEC_ONLY` | `CORRELATED` | `0.2857` | `0.0714` | **`-0.2143`** | $N=22$ |
| Precision | `SOURCE_ONLY` | `CORRELATED` | `0.5556` | `0.8333` | **`+0.2778`** | $N=22$ |
| Recall | `SOURCE_ONLY` | `CORRELATED` | `0.6250` | `0.6250` | `0.0000` | $N=22$ |
| F1 | `SOURCE_ONLY` | `CORRELATED` | `0.5882` | `0.7143` | **`+0.1261`** | $N=22$ |
| FPR | `SOURCE_ONLY` | `CORRELATED` | `0.2857` | `0.0714` | **`-0.2143`** | $N=22$ |

---

## 4. Correlation-Effect Transition Analysis

Dynamic tracking across all 22 Dimension-A propositions reveals key correlation effects:

- **False Positives Eliminated**: `PROP-AUTH-003`, `PROP-AUTH-004`, `PROP-AUTHZ-001`.
- **False Negatives Recovered**: `PROP-AUTH-002`, `PROP-DATA-002`.
- **Source Secret Excluded**: `PROP-SECRET-001` (source secret lacks spec counterpart).

---

## 5. Error Taxonomy & Qualitative Breakdown

| Error Source Category | `SPEC_ONLY` Errors | `SOURCE_ONLY` Errors | `CORRELATED` Errors |
|:---|:---|:---|:---|
| **`SPECIFICATION`** | 8 | 0 | 0 |
| **`SOURCE`** | 0 | 7 | 0 |
| **`CORRELATION`** | 0 | 0 | 1 |
| **`SOURCE_INTRINSIC_NON_ENDPOINT`** | 0 | 0 | 3 |
| **`OTHER`** | 0 | 0 | 0 |
| **Total Errors** | 8 | 7 | 4 |

---

## 6. Research Limitations

- Benchmark contains 24 total benchmark cases and 22 Dimension-A security propositions.
- Dimension-A propositions are evaluated against a controlled, synthetic benchmark dataset.
- Confidence intervals (95% Wilson score and bootstrap percentile) reflect small-sample uncertainty bounds (N=22).
- Experimental metrics and precision/recall tradeoffs should not be extrapolated to arbitrary commercial REST APIs without broader sampling.
- The CORRELATED layer is a cross-layer evidence synthesis layer, not a cumulative union of all single-layer findings.
- Source-intrinsic non-endpoint findings (e.g., standalone hardcoded secrets without OpenAPI counterparts) remain absent from CORRELATED findings by design.
- Ground-truth declarations govern classification metrics and error taxonomy assignments.
