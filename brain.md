# Intelligent API Security Analyzer — Project Brain / Continuation Context

> This document is the authoritative continuation context for the Intelligent API Security Analyzer project.
> It is intended to allow another coding agent (Codex/Antigravity/etc.) to continue development without
> losing architectural, research, implementation, testing, or phase-history context.

---

# 1. PROJECT IDENTITY

Project Name:
Intelligent API Security Analyzer

Repository:
Intelligent-API-Security-Analyzer

GitHub:
https://github.com/Vishal-glitxh/Intelligent-API-Security-Analyzer

Project Type:
Defensive, evidence-based REST API security analyzer.

Primary objective:
Build a deterministic security analysis system that evaluates REST APIs using:

1. OpenAPI specification analysis
2. Source-code static analysis
3. Evidence correlation between specification and implementation
4. Deterministic security rules
5. Evidence-based findings
6. Reproducible evaluation
7. Statistical research analysis

IMPORTANT:
The project intentionally does NOT use an LLM as the security detection engine.

The security analyzer is deterministic and rule-based.

LLMs may potentially be used externally for documentation/research assistance, but they are NOT part of the
core security detection methodology.

---

# 2. CURRENT PROJECT PHILOSOPHY

The analyzer is designed around the following principles:

- Evidence-based security analysis
- Deterministic behavior
- Reproducibility
- Explainability
- Static analysis
- OpenAPI-aware analysis
- Source-aware analysis
- Cross-layer evidence correlation
- No heuristic guessing
- No LLM-based vulnerability classification
- Research-grade evaluation
- Frozen experimental baselines
- Statistical reporting
- Strict quality gates

The project should favor correctness and scientific reproducibility over adding features quickly.

Do not modify the frozen analyzer merely to improve evaluation metrics.

---

# 3. TECHNOLOGY STACK

Current Python requirement:

Python >= 3.14,<3.15

Core stack:

- Python 3.14
- FastAPI
- Uvicorn
- SQLAlchemy 2
- Alembic
- PostgreSQL
- Pydantic / pydantic-settings
- PyYAML
- OpenAPI Specification Validator
- Python AST / Tree-sitter
- tree-sitter-python
- pytest
- pytest-cov
- Ruff
- mypy
- Docker / Docker Compose
- uv

Evaluation / research layer:

- deterministic benchmark dataset
- Wilson Score confidence intervals
- bootstrap F1 confidence intervals
- statistical comparison
- error taxonomy
- reproducible report generation
- HTML/JSON/Markdown artifacts

Frontend/UI technology has NOT yet been established as a completed implementation phase.

Do not assume a production UI currently exists.

---

# 4. HIGH-LEVEL ARCHITECTURE

The conceptual architecture is:

                    ┌─────────────────────────┐
                    │       API Inputs        │
                    │                         │
                    │  OpenAPI Specification  │
                    │  Source Code            │
                    └────────────┬────────────┘
                                 │
                ┌────────────────┴────────────────┐
                │                                 │
                ▼                                 ▼
      ┌──────────────────┐             ┌──────────────────┐
      │ OpenAPI Analysis │             │ Source Analysis  │
      │                  │             │                  │
      │ Loader           │             │ Source Loader    │
      │ Validator        │             │ Parser           │
      │ Normalizer       │             │ Route Extractor  │
      │ Resolver ($ref)  │             │ AST/Tree-sitter  │
      │ Endpoint Extract │             │ Framework aware  │
      └────────┬─────────┘             └────────┬─────────┘
               │                                │
               ▼                                ▼
      ┌──────────────────┐             ┌──────────────────┐
      │ OpenAPI Security │             │ Source Security  │
      │ Rules            │             │ Rules            │
      └────────┬─────────┘             └────────┬─────────┘
               │                                │
               └──────────────┬─────────────────┘
                              ▼
                 ┌──────────────────────────┐
                 │ Evidence Correlation     │
                 │                          │
                 │ Endpoint Alignment       │
                 │ Evidence Matching        │
                 │ Conflict Resolution      │
                 │ Correlation Rules        │
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌──────────────────────────┐
                 │ Deterministic Findings   │
                 │                          │
                 │ Rule ID                  │
                 │ Severity                 │
                 │ Evidence                 │
                 │ Location                 │
                 │ Explanation              │
                 └────────────┬─────────────┘
                              │
                              ▼
                 ┌──────────────────────────┐
                 │ Persistence / API Layer  │
                 │                          │
                 │ FastAPI                  │
                 │ SQLAlchemy               │
                 │ PostgreSQL               │
                 │ Scan Jobs                │
                 │ Reports                  │
                 └──────────────────────────┘

Research/evaluation operates around the analyzer without modifying the core analyzer:

                 ┌──────────────────────────────┐
                 │ Frozen Analyzer              │
                 │ Phase 1–5                    │
                 └──────────────┬───────────────┘
                                │
                                ▼
                 ┌──────────────────────────────┐
                 │ Phase 6 Evaluation           │
                 │ Benchmark Dataset             │
                 │ SPEC_ONLY                    │
                 │ SOURCE_ONLY                  │
                 │ CORRELATED                   │
                 └──────────────┬───────────────┘
                                │
                                ▼
                 ┌──────────────────────────────┐
                 │ Phase 7 Statistical Layer    │
                 │                              │
                 │ CIs                          │
                 │ Bootstrap                    │
                 │ Mode comparisons             │
                 │ Error taxonomy               │
                 │ Transition analysis           │
                 └──────────────────────────────┘

---

# 5. PHASE HISTORY

## PHASE 1 — FOUNDATION

Status:
FROZEN / COMPLETE

Purpose:
Establish the core project foundation.

Implemented foundation includes:

- Python backend
- FastAPI application
- configuration
- database layer
- SQLAlchemy
- PostgreSQL integration
- Alembic migrations
- health endpoints
- project structure
- test infrastructure
- basic service architecture

The project established the backend application structure:

backend/
└── app/
    ├── analysis/
    ├── api/
    ├── core/
    ├── db/
    ├── jobs/
    ├── repositories/
    ├── schemas/
    ├── services/
    └── main.py

Phase 1 is frozen.

Do not casually redesign the foundation.

---

# 6. PHASE 2 — OPENAPI SPECIFICATION ANALYZER

Status:
FROZEN / COMPLETE

Purpose:
Analyze REST APIs from their OpenAPI specification.

Major functionality:

- OpenAPI loading
- OpenAPI validation
- normalization
- endpoint extraction
- `$ref` resolution
- specification structure analysis
- security rule evaluation
- deterministic findings

Important components include:

- OpenAPI loader
- validator
- normalizer
- resolver
- endpoint extraction
- OpenAPI security rules

The analyzer should support valid OpenAPI inputs and produce normalized evidence.

Phase 2 is frozen.

---

# 7. PHASE 3 — SOURCE-CODE STATIC ANALYZER

Status:
FROZEN / COMPLETE

Purpose:
Analyze API implementation source code independently of the OpenAPI specification.

Capabilities include:

- source loading
- source parsing
- route extraction
- FastAPI route analysis
- Flask route analysis
- AST/static analysis
- Tree-sitter support
- source-level security rules
- endpoint evidence extraction

The project deliberately avoids dynamic execution of arbitrary application source code.

Source analysis is static/evidence based.

Phase 3 is frozen.

---

# 8. PHASE 4 — EVIDENCE CORRELATION ENGINE

Status:
FROZEN / COMPLETE

Purpose:
Correlate evidence obtained from:

1. OpenAPI specification
2. Source implementation

The correlation engine aligns endpoints and combines evidence.

Core concepts:

- endpoint matching
- evidence alignment
- correlation rules
- conflict handling
- evidence preservation
- reproducibility

Phase 4 established the central research hypothesis:

Combining specification-level and source-level evidence should reduce false positives and improve
security detection quality compared with analyzing either layer independently.

Phase 4 is frozen.

---

# 9. PHASE 5 — OPERATIONAL / FAILURE-PATH HARDENING

Status:
FROZEN / COMPLETE

Phase 5 focused on operational robustness.

Areas validated included:

- API behavior
- security controls
- worker behavior
- failure recovery
- failure paths
- service-level behavior
- persistence interactions
- reproducibility

Important operational runbooks were created/corrected, including:

- application-down.md
- configuration-failure.md
- database-failure.md

Runbook corrections included:

- health endpoints:
  GET /health
  GET /api/v1/health

- production SESSION_SECRET requirements
- secret redaction
- PostgreSQL host/container hostname distinctions
- pg_isready usage
- production configuration handling

Phase 5 established the baseline that the analyzer itself should remain frozen while research/evaluation evolves around it.

---

# 10. PHASE 6 — RESEARCH EVALUATION

Status:
COMPLETE / FROZEN BASELINE

Git commit:

21d2b2c Add complete Phase 6 evaluation artifacts

Previous commits:

de40e5b Finalize Phase 6 research evaluation
060e9a2 Complete Phase 5 failure-path validation
3ea0f55 Add Phase 1-5 analyzer implementation
16c1a54 first commit

Phase 6 introduced a benchmark-based research evaluation layer.

Implemented files:

backend/app/evaluation/
├── __init__.py
├── classifier.py
├── cli.py
├── loader.py
├── metrics.py
├── models.py
├── reporter.py
└── runner.py

Benchmark dataset:

evaluation/
├── dataset/
│   ├── cases/
│   └── ground_truth.yaml
└── reports/

Benchmark cases include categories such as:

AUTH
AUTHZ
CORR
DATA
INPUT
MATCH
SECRET

Examples:

AUTH-001 through AUTH-005
AUTHZ-001 through AUTHZ-005
CORR-001
DATA-001 through DATA-004
INPUT-001 through INPUT-004
MATCH-001
SECRET-001 through SECRET-004

Total:
24 benchmark cases.

The evaluation compares three experimental modes:

1. SPEC_ONLY
2. SOURCE_ONLY
3. CORRELATED

---

# 11. PHASE 6 EXPERIMENTAL RESULTS

Published Phase 6 baseline:

                 SPEC_ONLY   SOURCE_ONLY   CORRELATED

Precision          0.5000       0.5556        0.8333
Recall             0.5000       0.6250        0.6250
F1                 0.5000       0.5882        0.7143
FPR                0.2857       0.2857        0.0714
FNR                0.5000       0.3750        0.3750

Confusion matrices:

SPEC_ONLY:
TP = 4
FP = 4
FN = 4
TN = 10

SOURCE_ONLY:
TP = 5
FP = 4
FN = 3
TN = 10

CORRELATED:
TP = 5
FP = 1
FN = 3
TN = 13

Evidence completeness:

SPEC_ONLY    = 1.0000
SOURCE_ONLY  = 1.0000
CORRELATED   = 1.0000

Explainability:

SPEC_ONLY    = 1.0000
SOURCE_ONLY  = 0.9885
CORRELATED   = 1.0000

Dimension B:
Correlation Accuracy = 1.0000

Dimension C:
Endpoint Match Accuracy = 1.0000

IMPORTANT:
These values are the frozen Phase 6 baseline and must not be silently changed.

---

# 12. PHASE 6 CLI

Original issue discovered:

Running:

uv run python -m app.evaluation.cli

failed with:

ModuleNotFoundError: No module named 'app'

because backend/ was not automatically on Python's module search path.

Temporary workaround:

PYTHONPATH=backend uv run python -m app.evaluation.cli

This worked.

The issue was later fixed during Phase 7 pre-flight remediation.

---

# 13. PHASE 7 PRE-FLIGHT AUDIT

Before implementing Phase 7 statistical research hardening, a repository error/code-leak audit was performed.

Audit report:

phase7_preflight_audit.md

Total findings:
10

Severity:

Critical:
0

High:
1

Medium:
2

Low:
4

Informational:
3

---

# 14. PRE-FLIGHT AUDIT FINDINGS

## High

Evaluation CLI execution-path / packaging issue.

Original command:

uv run python -m app.evaluation.cli

failed without PYTHONPATH.

This was subsequently fixed.

---

## Medium

1. Report drift caused by:
   - dynamic experiment UUID
   - execution timestamp

2. README lacked complete evaluation documentation.

Both were subsequently addressed.

---

## Low

1. Third-party pytest deprecation warnings
2. Development credentials in .env.example
3. .DS_Store files
4. tracked scratch scripts

---

## Informational

1. Synthetic benchmark secrets verified as non-real.
2. AST/YAML parsing safety verified.
3. Known CORRELATED-mode non-endpoint secret tradeoff.

---

# 15. SECRET / CODE LEAK AUDIT

Confirmed production secrets:

0

No real credentials, private tokens, API keys, or production secrets were detected.

Development-only credentials existed:

POSTGRES_USER=analyzer
POSTGRES_PASSWORD=analyzer
SESSION_SECRET=development-only-replace-me

These are classified as accepted development/test risk.

Synthetic benchmark credentials exist intentionally.

Examples:

sk_live_998877665544332211

AWS_SECRET_KEY = "AKIAIOSFODNN7NOTREAL"

These are test fixtures / synthetic benchmark data and are classified as:

CONFIRMED NON-LEAK

Do NOT replace these blindly because they are part of the security benchmark dataset.

---

# 16. ANALYZER IMMUTABILITY

A critical project rule:

The frozen analyzer must not be modified merely to improve research metrics.

The following check has repeatedly been used:

git diff 060e9a2 -- backend/app/analysis/

Expected result:

EMPTY

This means the core analyzer under:

backend/app/analysis/

has remained untouched since the Phase 5 baseline.

This immutability is essential for research validity.

Phase 6 and Phase 7 evaluation functionality should live outside the core analyzer.

---

# 17. PHASE 7 PRE-FLIGHT REMEDIATION

Status:
COMPLETE

P0 CLI packaging was fixed.

`pyproject.toml` was changed to support package discovery with setuptools:

where = ["backend"]

An entrypoint was also introduced:

evaluate = "app.evaluation.cli:main"

The repository now supports:

uv run python -m app.evaluation.cli

and:

uv run evaluate

without manually setting:

PYTHONPATH=backend

---

# 18. PHASE 7 DETERMINISTIC REPORTING

Report generation was made deterministic.

Default:

uv run evaluate

produces deterministic baseline reports.

Published artifacts remain stable and:

git diff evaluation/reports/

should remain empty after a normal baseline evaluation.

Dynamic experiment output is supported separately:

uv run evaluate --dynamic --output-dir evaluation/runs

Dynamic artifacts should not overwrite the published baseline.

The conceptual distinction is:

evaluation/reports/
    = frozen/published baseline

evaluation/runs/
    = dynamic researcher experiments

---

# 19. PHASE 7 DOCUMENTATION

README.md was expanded to document:

- evaluation commands
- CLI usage
- benchmark composition
- 24 benchmark cases
- 22 Dimension-A propositions
- experimental modes
- Phase 6 baseline metrics
- artifact locations
- security credential policies
- Phase 7 statistical analysis

---

# 20. PHASE 7.1

Phase 7.1 represents the research hardening/preparation stage.

Primary goals:

- repository reproducibility
- deterministic artifact generation
- CLI usability
- documentation
- baseline preservation
- audit/remediation
- research-readiness

Status:

COMPLETE

Phase 7.1 established the repository as ready for statistical analysis.

---

# 21. PHASE 7.2 — STATISTICAL IMPLEMENTATION

Status:
COMPLETE & VERIFIED

Phase 7.2 introduces a statistical research layer over the frozen Phase 6 baseline.

IMPORTANT:
The core analyzer remains frozen.

New file:

backend/app/evaluation/statistics.py

New tests:

backend/tests/test_phase7_statistics.py

The test suite added 7 statistical tests covering:

- CI formulas
- deterministic bootstrap
- mode comparison
- transition tracking
- SECRET-001 classification
- zero/empty inputs
- end-to-end serialization

---

# 22. PHASE 7.2 STATISTICAL METHODS

## Wilson Score Confidence Intervals

Used for proportion metrics:

- Precision
- Recall
- FPR
- FNR
- Dimension B accuracy
- Dimension C accuracy

Confidence level:

95%

No normal approximation is used.

This is important because the benchmark sample size is small.

---

## Bootstrap F1 Confidence Intervals

F1 uses:

10,000 bootstrap samples

Method:

Percentile bootstrap

Seed:

42

This ensures deterministic statistical output.

---

# 23. PHASE 7.2 CONFIDENCE INTERVAL RESULTS

SPEC_ONLY:

Precision:
0.5000
95% CI:
[0.2152, 0.7848]

Recall:
0.5000
95% CI:
[0.2152, 0.7848]

FPR:
0.2857
95% CI:
[0.1172, 0.5465]

FNR:
0.5000
95% CI:
[0.2152, 0.7848]

F1:
0.5000
95% CI:
[0.1667, 0.7692]

SOURCE_ONLY:

Precision:
0.5556
95% CI:
[0.2667, 0.8112]

Recall:
0.6250
95% CI:
[0.3057, 0.8632]

FPR:
0.2857
95% CI:
[0.1172, 0.5465]

FNR:
0.3750
95% CI:
[0.1368, 0.6943]

F1:
0.5882
95% CI:
[0.2667, 0.8333]

CORRELATED:

Precision:
0.8333
95% CI:
[0.4365, 0.9699]

Recall:
0.6250
95% CI:
[0.3057, 0.8632]

FPR:
0.0714
95% CI:
[0.0127, 0.3147]

FNR:
0.3750
95% CI:
[0.1368, 0.6943]

F1:
0.7143
95% CI:
[0.3636, 0.9333]

Dimension B correlation accuracy:

1.0000
95% CI:
[0.2065, 1.0000]

Dimension C endpoint match accuracy:

1.0000
95% CI:
[0.5101, 1.0000]

---

# 24. PHASE 7.2 MODE COMPARISON

CORRELATED vs SPEC_ONLY:

F1:
+0.2143

Precision:
+0.3333

Recall:
+0.1250

FPR:
-0.2143

CORRELATED vs SOURCE_ONLY:

F1:
+0.1261

Precision:
+0.2778

Recall:
0.0000

FPR:
-0.2143

IMPORTANT RESEARCH INTERPRETATION:

The correlated mode shows better point estimates, especially precision and false-positive rate.

However:

DO NOT claim statistical significance.

The benchmark contains only 22 Dimension-A propositions.

The confidence intervals are broad.

The project should explicitly describe the result as an observed experimental improvement rather than
a statistically proven general improvement.

---

# 25. CORRELATION EFFECT TRANSITIONS

The Phase 7 statistical layer tracks proposition transitions between modes.

False positives removed:

PROP-AUTH-003
PROP-AUTH-004
PROP-AUTHZ-001

Total:
3 FP removed

False negatives recovered:

PROP-AUTH-002
PROP-DATA-002

Total:
2 FN removed

Source secret excluded / FN introduced:

PROP-SECRET-001

Reason:
AWS_SECRET_KEY exists in source without a corresponding OpenAPI counterpart.

This is considered a known CORRELATED-mode tradeoff.

---

# 26. ERROR TAXONOMY

Phase 7 classifies errors into:

SPECIFICATION

SOURCE

CORRELATION

SOURCE_INTRINSIC_NON_ENDPOINT

Current breakdown:

SPECIFICATION:
8 errors

SOURCE:
7 errors

CORRELATION:
1 error

SOURCE_INTRINSIC_NON_ENDPOINT:
3 errors

The taxonomy exists to distinguish errors originating from individual analysis layers versus the
correlation layer.

---

# 27. PHASE 7 ARTIFACTS

Directory:

evaluation/reports/phase7/

Artifacts:

confidence_intervals.json
mode_comparison.json
correlation_effects.json
error_analysis.json
statistical_analysis.json
statistical_analysis.md
phase7_research_report.html

These are deterministic research artifacts.

---

# 28. PHASE 7 CLI

Primary command:

uv run evaluate --phase7-statistics

This performs:

1. Phase 6 evaluation
2. Phase 7 statistical analysis
3. confidence interval generation
4. mode comparison
5. transition analysis
6. error taxonomy
7. report generation

Successful output includes:

Phase 7 artifacts generated in:

evaluation/reports/phase7

and:

Phase 7 HTML Report:

evaluation/reports/phase7/phase7_research_report.html

---

# 29. QUALITY GATES

The project currently has the following quality gates.

## Tests

Command:

uv run pytest

Latest verified result:

174 passed
0 failed

Earlier baseline:

167 passed

The increase is due to Phase 7 statistical tests.

---

## Ruff

Command:

uv run ruff check .

Expected:

All checks passed!

---

## Formatting

Command:

uv run ruff format --check .

Latest verified:

121 files already formatted

---

## Mypy

Command:

uv run mypy backend

Latest verified:

Success: no issues found in 110 source files

Strict mode is enabled.

---

## Alembic

Command:

uv run alembic check

Expected:

No new upgrade operations detected.

---

## Docker

Command:

docker compose config

Expected:

Valid compose configuration.

Current PostgreSQL service:

image:
postgres:18

Database:

api_security

User:

analyzer

Password:

analyzer

Development/test environment only.

---

## Analyzer immutability

Command:

git diff 060e9a2 -- backend/app/analysis/

Expected:

EMPTY

This must remain empty unless an explicitly approved analyzer change is made.

---

# 30. CURRENT PYPROJECT PACKAGE CONFIGURATION

The project originally used:

[tool.uv]
package = false

This contributed to the module-resolution problem.

The Phase 7 remediation introduced package/build configuration using setuptools and package discovery from:

backend/

The project now exposes:

evaluate = "app.evaluation.cli:main"

Do not undo this packaging configuration.

---

# 31. DATABASE

Database technology:

PostgreSQL 18

Docker Compose service:

postgres

Port:

5432

Database:

api_security

Username:

analyzer

Password:

analyzer

Volume:

postgres_data

Alembic migrations exist under:

backend/alembic/

The latest checks show no pending migration drift.

---

# 32. CURRENT REPOSITORY STRUCTURE

Approximate important structure:

backend/
├── alembic/
├── app/
│   ├── analysis/
│   │   ├── context.py
│   │   ├── engine.py
│   │   └── findings.py
│   │
│   ├── api/
│   │   └── router.py
│   │
│   ├── core/
│   │   ├── config.py
│   │   └── exceptions.py
│   │
│   ├── db/
│   │   ├── base.py
│   │   ├── models.py
│   │   └── session.py
│   │
│   ├── evaluation/
│   │   ├── classifier.py
│   │   ├── cli.py
│   │   ├── loader.py
│   │   ├── metrics.py
│   │   ├── models.py
│   │   ├── reporter.py
│   │   ├── runner.py
│   │   └── statistics.py
│   │
│   ├── jobs/
│   │   └── runner.py
│   │
│   ├── repositories/
│   │   └── scan.py
│   │
│   ├── schemas/
│   │   ├── scan.py
│   │   └── worker.py
│   │
│   ├── services/
│   │   ├── analysis_worker.py
│   │   ├── archive.py
│   │   ├── report.py
│   │   └── scan_service.py
│   │
│   └── main.py
│
└── tests/
    ├── test_phase6_evaluation.py
    ├── test_phase7_statistics.py
    └── many analyzer/unit/integration tests

evaluation/
├── dataset/
│   ├── cases/
│   └── ground_truth.yaml
│
└── reports/
    ├── classifications.json
    ├── endpoint_matching.json
    ├── evidence_completeness.json
    ├── explainability.json
    ├── full_report.json
    ├── metrics.json
    ├── report.html
    └── phase7/
        ├── confidence_intervals.json
        ├── mode_comparison.json
        ├── correlation_effects.json
        ├── error_analysis.json
        ├── statistical_analysis.json
        ├── statistical_analysis.md
        └── phase7_research_report.html

---

# 33. UI / UX STATUS

IMPORTANT:

The backend/research architecture is significantly more mature than the UI/UX implementation.

The project has focused primarily on:

- analyzer architecture
- security rules
- evidence correlation
- backend reliability
- benchmark evaluation
- statistical research

A complete production-grade UI/UX implementation has NOT yet been established as a completed phase.

Therefore:

DO NOT claim that the UI is complete.

The UI should be treated as a future implementation track.

Potential future UI should expose:

1. Dashboard
2. Scan creation
3. OpenAPI upload
4. Source-code upload
5. Scan progress
6. Findings
7. Severity
8. Evidence
9. Endpoint mapping
10. Correlation explanation
11. Reports
12. Research/evaluation dashboard

The UI must display evidence rather than merely displaying "vulnerability detected".

---

# 34. DATASET STATUS

A later project discussion identified the need to investigate larger external datasets, including Kaggle
and other public sources.

IMPORTANT:

Do NOT claim that an external dataset has already been integrated.

The existing Phase 6 benchmark is the project's current controlled research dataset.

The benchmark contains 24 cases and 22 Dimension-A propositions.

Potential future work:

- search Kaggle
- search GitHub security datasets
- search OWASP datasets/resources
- search public API vulnerability datasets
- investigate real-world OpenAPI repositories
- evaluate whether external data can be transformed into the project's ground-truth format

Any external dataset must be evaluated for:

- licensing
- reproducibility
- ground-truth quality
- API specification availability
- source-code availability
- endpoint mapping
- vulnerability labeling quality
- compatibility with the project's deterministic rules
- train/test contamination
- synthetic vs real-world status

Do not blindly merge external data into the frozen Phase 6 benchmark.

---

# 35. RESEARCH LIMITATIONS

Current limitations must be explicitly acknowledged.

1. Small benchmark size.

Only 22 Dimension-A propositions.

2. Wide confidence intervals.

The observed improvements have substantial uncertainty.

3. Statistical significance is NOT established.

Do not use language such as:

"proven statistically superior"

Instead use:

"observed improvement"

"higher point estimate"

"lower observed false-positive rate"

4. Synthetic benchmark composition.

The current benchmark is controlled and designed for evaluation.

It should not automatically be presented as representative of all production APIs.

5. Endpoint/security-rule coverage.

The current rule set does not represent every OWASP/API security vulnerability.

6. Correlation tradeoffs.

CORRELATED mode may suppress source-only findings where there is no corresponding specification evidence.

SECRET-001 is a known example.

7. No production-scale performance study has yet been established.

8. External dataset validation remains future work.

---

# 36. CRITICAL RESEARCH RULE

Never optimize the analyzer against the benchmark simply to increase:

Precision
Recall
F1

Doing so would undermine the validity of the research.

The benchmark is an evaluation instrument.

The analyzer should remain independently designed and frozen when measuring research effects.

If an analyzer rule needs to change, that should constitute a controlled new analyzer version/baseline rather than silently modifying the Phase 6 baseline.

---

# 37. REPRODUCIBILITY RULES

Every research experiment should record:

- dataset version
- analyzer version / commit
- experiment mode
- random seed
- bootstrap count
- statistical methodology
- generated artifacts
- execution environment where relevant

Deterministic baseline:

uv run evaluate

Phase 7 statistical baseline:

uv run evaluate --phase7-statistics

Dynamic run:

uv run evaluate --dynamic --output-dir evaluation/runs

---

# 38. GIT STATUS / BASELINE

At the Phase 6 completion point:

21d2b2c
Add complete Phase 6 evaluation artifacts

Then Phase 7 remediation and statistical implementation introduced additional changes.

The important invariant is:

backend/app/analysis/

remains unchanged relative to:

060e9a2

Before making any major new change:

git status

git log --oneline -10

git diff -- backend/app/analysis/

should be checked.

---

# 39. DEVELOPMENT WORKFLOW

Before modifying anything:

1. Inspect git status.
2. Inspect current branch.
3. Run tests.
4. Identify whether requested change belongs to:
   - analyzer
   - API
   - evaluation
   - research/statistics
   - UI
5. Avoid modifying frozen components unless explicitly authorized.
6. Add tests before or alongside implementation.
7. Run quality gates.
8. Generate reports.
9. Inspect git diff.
10. Commit only after verification.

---

# 40. STANDARD VERIFICATION SEQUENCE

Run:

uv run pytest

uv run ruff check .

uv run ruff format --check .

uv run mypy backend

uv run alembic check

docker compose config

Then:

uv run evaluate --phase7-statistics

Then:

git diff -- backend/app/analysis/

Then:

git status

---

# 41. CURRENT VERIFIED STATE

At the latest Phase 7.2 implementation verification:

Tests:
174 passed

Ruff:
PASS

Formatting:
PASS

Mypy:
PASS

Alembic:
PASS

Docker Compose:
PASS

Evaluation CLI:
PASS

Phase 6 baseline:
PRESERVED

Phase 7 statistics:
GENERATED

Core analyzer:
IMMUTABLE

This is the current trusted project state.

---

# 42. WHAT HAS NOT BEEN DONE YET

The following should NOT be falsely marked complete:

- full production UI/UX
- external Kaggle dataset integration
- large-scale real-world benchmark validation
- statistically significant superiority claim
- production-scale performance benchmarking
- comprehensive OWASP API Top 10 coverage validation
- human expert validation study
- full research paper
- final dissertation/thesis
- final deployment architecture
- production security audit

---

# 43. RECOMMENDED NEXT PHASES

After Phase 7.2, possible research/engineering tracks are:

## Phase 7.3 — Dataset Expansion

Investigate external datasets.

Potential sources:

- Kaggle
- GitHub
- OWASP
- public vulnerable API repositories
- OpenAPI repositories
- security benchmark datasets

Goal:

Expand evaluation while preserving the controlled Phase 6 benchmark.

---

## Phase 7.4 — Statistical Robustness

Potential additions:

- paired bootstrap comparisons
- permutation tests
- effect sizes
- confidence intervals for mode differences
- McNemar's test where appropriate
- multiple-run stability analysis
- sensitivity analysis
- stratified analysis by vulnerability class

Do not add tests simply because they sound statistically advanced.
Every statistical method must be justified by the experimental design.

---

## Phase 8 — UI / UX

Build the actual analyst-facing interface.

Potential architecture:

                  ┌────────────────────┐
                  │      Frontend      │
                  │                    │
                  │ Dashboard          │
                  │ Scan UI            │
                  │ Findings           │
                  │ Evidence           │
                  │ Reports            │
                  └─────────┬──────────┘
                            │
                            ▼
                  ┌────────────────────┐
                  │      FastAPI       │
                  │      Backend       │
                  └─────────┬──────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
         ┌──────────────┐       ┌──────────────┐
         │ Analyzer     │       │ PostgreSQL   │
         │ Engine       │       │              │
         └──────────────┘       └──────────────┘

The UI should make evidence and reasoning visible.

---

# 44. POTENTIAL UI SCREENS

Recommended eventual screens:

1. Landing / Dashboard

2. New Scan

Inputs:
- OpenAPI file
- source repository
- framework
- scan configuration

3. Scan Progress

Show:
- specification processing
- source processing
- endpoint extraction
- correlation
- finding generation

4. Findings Dashboard

Columns:
- Rule
- Severity
- Endpoint
- Source
- Evidence
- Confidence/quality indicators

5. Finding Detail

Show:

Finding
↓
Rule
↓
Specification evidence
↓
Source evidence
↓
Correlation result
↓
Explanation
↓
Remediation guidance

6. Endpoint Correlation View

Show:

OpenAPI endpoint
↕
matched source route
↕
evidence
↕
security findings

7. Reports

Export:

- JSON
- HTML
- PDF (future)

8. Research Dashboard

Show:

SPEC_ONLY
SOURCE_ONLY
CORRELATED

with:

- Precision
- Recall
- F1
- FPR
- FNR
- confidence intervals
- error taxonomy
- transition analysis

---

# 45. IMPORTANT DESIGN DECISIONS

Do not:

- introduce LLM-based vulnerability classification
- randomly change the rule engine
- modify analyzer code to improve benchmark scores
- delete synthetic secrets from benchmark fixtures without understanding their purpose
- overwrite frozen baseline reports with dynamic experiments
- claim statistical significance from current data
- claim external dataset validation before it is actually performed
- claim UI completion without implementation evidence

Do:

- preserve deterministic behavior
- preserve explainability
- preserve evidence
- preserve reproducibility
- add tests
- maintain analyzer immutability
- maintain statistical transparency
- document limitations
- separate research artifacts from production artifacts

---

# 46. CURRENT PROJECT RESEARCH CLAIM

The current evidence supports the following carefully worded research observation:

"Within the controlled Phase 6 benchmark, correlating OpenAPI specification evidence with source-code evidence produced a higher observed precision and F1 score and a lower observed false-positive rate than either specification-only or source-only analysis."

The current data does NOT justify:

"Correlation is statistically proven to outperform the other modes."

The second statement must not be used.

---

# 47. CORE RESEARCH HYPOTHESIS

Primary hypothesis:

H1:
Evidence correlation between API specifications and source-code implementation improves the quality of
REST API security analysis compared with independent specification-only or source-only analysis.

Observed Phase 6 result:

CORRELATED:
Precision = 0.8333
F1 = 0.7143
FPR = 0.0714

SPEC_ONLY:
Precision = 0.5000
F1 = 0.5000
FPR = 0.2857

SOURCE_ONLY:
Precision = 0.5556
F1 = 0.5882
FPR = 0.2857

Phase 7 adds uncertainty estimates around these values.

---

# 48. AGENT INSTRUCTIONS

If another coding agent reads this file, follow these rules:

1. First inspect the repository rather than assuming this document is perfectly synchronized.
2. Verify claims against actual files and commands.
3. Preserve the frozen analyzer.
4. Treat Phase 6 metrics as the published baseline.
5. Treat Phase 7 statistical artifacts as research outputs.
6. Do not overwrite baseline artifacts with dynamic runs.
7. Add tests for every new statistical or evaluation behavior.
8. Run all quality gates before declaring completion.
9. Clearly separate:
   - implementation facts
   - experimental observations
   - hypotheses
   - limitations
10. Never fabricate results.

If a requested change conflicts with the frozen architecture, explicitly identify the conflict before implementation.

---

# 49. FIRST COMMANDS FOR A NEW CODING SESSION

Run these first:

git status

git log --oneline -10

git branch --show-current

git diff -- backend/app/analysis/

uv run pytest

uv run ruff check .

uv run mypy backend

Then:

uv run evaluate --phase7-statistics

Only after verifying the baseline should implementation begin.

---

# 50. IMMEDIATE PROJECT STATE

CURRENT PHASE:

Phase 7.2 — Statistical Implementation & Research Hardening

STATUS:

COMPLETE & VERIFIED

NEXT LIKELY TASK:

Phase 7.3 — External Dataset Investigation / Dataset Expansion

Before implementing 7.3:

1. Search and evaluate candidate datasets.
2. Determine whether they contain:
   - OpenAPI specs
   - source code
   - vulnerability labels
   - endpoint mappings
3. Check licensing.
4. Determine whether labels are reliable.
5. Design an ingestion/conversion format.
6. Keep the original Phase 6 benchmark untouched.
7. Create an independent external-dataset benchmark.
8. Do not change analyzer behavior merely to accommodate the new dataset.

ALTERNATIVE PARALLEL TRACK:

Phase 8 UI/UX implementation.

The backend/research system is currently considerably more mature than the UI.

---

# 51. FINAL CONTEXT SUMMARY

The project has progressed through:

Phase 1
Foundation
↓
Phase 2
OpenAPI Specification Analyzer
↓
Phase 3
Source-Code Static Analyzer
↓
Phase 4
Evidence Correlation Engine
↓
Phase 5
Operational / Failure-Path Hardening
↓
Phase 6
Controlled Research Evaluation
↓
Phase 7.1
Research Hardening / Pre-flight Remediation
↓
Phase 7.2
Statistical Analysis & Confidence Intervals
↓
NEXT:
Phase 7.3 Dataset Expansion / External Validation
and/or
Phase 8 UI/UX

The central analyzer is frozen.

The current research baseline is reproducible.

The Phase 6 benchmark is controlled.

Phase 7.2 provides statistical uncertainty and error analysis.

The next major research challenge is increasing external validity without compromising reproducibility.

The next major engineering challenge is building the analyst-facing UI/UX layer.

END OF PROJECT BRAIN