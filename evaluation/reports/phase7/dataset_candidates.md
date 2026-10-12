# Phase 7.3 External Dataset Candidates & Suitability Evaluation

## 1. Executive Summary

This report provides the formal evaluation of candidate external API security datasets for **Phase 7.3: External Dataset Expansion & Benchmark Validation** of the Intelligent API Security Analyzer.

The goal of Phase 7.3 is to evaluate the external validity and generalizability of the static, OpenAPI-aware, and cross-layer correlation rules developed in Phases 1–5 and statistically analyzed in Phase 7.2. 

In accordance with core project constraints:
1. **The analyzer implementation under `backend/app/analysis/` is FROZEN and will NOT be modified.**
2. **The original 24-case Phase 6 synthetic benchmark is preserved completely unchanged.**
3. **No dataset will be selected merely to inflate performance metrics.**
4. **Datasets failing provenance, licensing, OpenAPI availability, or Python source compatibility criteria are rejected.**

---

## 2. Evaluation Criteria (8-Point Quality Gate)

Every candidate dataset was audited against eight specific criteria:

| Criterion | Description | Pass Threshold |
| :--- | :--- | :--- |
| **C1: API Security Relevance** | Focuses on REST API vulnerabilities (OWASP API Security Top 10: BOLA, Broken Auth, Mass Assignment, Injection, Rate Limiting). | Must feature documented API security weaknesses. |
| **C2: OpenAPI Compatibility** | Provides valid OpenAPI 3.0 / Swagger 2.0 specifications defining paths, methods, parameters, and schemas. | Full schema available and parseable by standard validators. |
| **C3: Source Code Availability** | Source code implementation is available in **Python** (FastAPI or Flask). | Compatible with `PythonSourceAnalyzer` AST/Tree-sitter visitors. |
| **C4: Ground-Truth Labels** | Ground-truth vulnerability labels are verifiable, unambiguous, and documented. | Clear positive/negative vulnerability designations. |
| **C5: Endpoint-Level Mapping** | Vulnerabilities can be mapped to specific `(path, method, proposition)` tuples. | Direct binding to endpoint routes possible. |
| **C6: Provenance & Licensing** | Clear author/organizational provenance with a permissive open-source license. | MIT, Apache 2.0, or BSD license. |
| **C7: Reproducibility** | Self-contained, runnable locally without proprietary external cloud dependencies. | 100% offline reproducible. |
| **C8: Multi-Layer Suitability** | Capable of independent evaluation in `SPEC_ONLY`, `SOURCE_ONLY`, and `CORRELATED` modes. | Supports specification and implementation cross-analysis. |

---

## 3. Candidate Dataset Evaluations

### Candidate 1: VAmPI (Vulnerable REST API)
- **Repository**: `https://github.com/erev0s/VAmPI`
- **Author / Provenance**: Dimitrios Vlachos (Erev0s) — OWASP contributor and security researcher.
- **License**: Apache License 2.0
- **Technology Stack**: Python 3, Flask, Connexion
- **OpenAPI Specification**: Native OpenAPI 3.0 specification (`openapi_specs/openapi3.json` / `openapi3.yaml`).
- **Covered Vulnerability Classes**:
  - OWASP API1:2019 / API1:2023: Broken Object Level Authorization (BOLA/IDOR on `/users/v1/{username}`)
  - OWASP API2:2019 / API2:2023: Broken Authentication / Weak JWT signing key (`/users/v1/login`)
  - OWASP API3:2019 / API3:2023: Excessive Data Exposure (`/users/v1/_debug`)
  - OWASP API4:2019 / API4:2023: Lack of Resources & Rate Limiting (`/users/v1/login`)
  - OWASP API6:2019 / API3:2023: Mass Assignment (`/users/v1/register`)
  - Injection: SQL Injection (`/users/v1/{username}/email`)
- **Key Feature**: Contains an explicit **vulnerability toggle** switch (`alive` vs `secure` modes), enabling paired evaluation of true positive vulnerabilities and true negative mitigations.
- **Assessment against Criteria**:
  - C1 (Relevance): **PASS** (Direct OWASP API Security Top 10 focus)
  - C2 (OpenAPI): **PASS** (High-quality OpenAPI 3.0 specification)
  - C3 (Source Code): **PASS** (Python Flask / Connexion routes)
  - C4 (Ground Truth): **PASS** (Documented in official writeup and test cases)
  - C5 (Mapping): **PASS** (Direct mapping to endpoints and HTTP methods)
  - C6 (License): **PASS** (Apache 2.0, fully permissive)
  - C7 (Reproducibility): **PASS** (Self-contained repository)
  - C8 (Multi-Layer): **PASS** (Enables SPEC, SOURCE, and CORRELATED analysis)
- **Suitability Score**: **9.5 / 10**
- **Recommendation**: **PRIMARY CANDIDATE (ACCEPTED)**.

---

### Candidate 2: c{api}tal (Checkmarx Vulnerable API)
- **Repository**: `https://github.com/Checkmarx/capital`
- **Author / Provenance**: Checkmarx Security Research Team.
- **License**: MIT License
- **Technology Stack**: Python 3, FastAPI, SQLAlchemy
- **OpenAPI Specification**: Auto-generated OpenAPI 3.0 via FastAPI (`/openapi.json`).
- **Covered Vulnerability Classes**:
  - OWASP API1: BOLA / IDOR in bank account endpoints
  - OWASP API2: Broken Authentication / password reset flaws
  - OWASP API3: Excessive Data Exposure in profile API
  - OWASP API5: Broken Function Level Authorization in admin dashboard
  - OWASP API6: Mass Assignment on user registration
- **Assessment against Criteria**:
  - C1 (Relevance): **PASS** (OWASP API Top 10 challenges)
  - C2 (OpenAPI): **PASS** (Standard FastAPI OpenAPI schema)
  - C3 (Source Code): **PASS** (Python FastAPI code structure)
  - C4 (Ground Truth): **PASS** (Documented challenge solutions)
  - C5 (Mapping): **PASS** (Clear route bindings)
  - C6 (License): **PASS** (MIT License, permissive)
  - C7 (Reproducibility): **PASS** (Self-contained)
  - C8 (Multi-Layer): **PASS** (Supports full multi-layer evaluation)
- **Suitability Score**: **9.2 / 10**
- **Recommendation**: **SECONDARY CANDIDATE (ACCEPTED for multi-target expansion)**.

---

### Candidate 3: vAPI (Vulnerable Adversely Programmed Interface)
- **Repository**: `https://github.com/jorritfolmer/vulnerable-api`
- **Author / Provenance**: Jorrit Folmer
- **License**: GNU General Public License v3.0 (GPL-3.0)
- **Technology Stack**: Python, Flask, Connexion
- **OpenAPI Specification**: OpenAPI 3.0 specification available.
- **Covered Vulnerabilities**: SQLi, Auth bypass, Token validation flaws, Command Injection.
- **Assessment against Criteria**:
  - C1 (Relevance): **PASS**
  - C2 (OpenAPI): **PASS**
  - C3 (Source Code): **PASS** (Python Flask)
  - C4 (Ground Truth): **PASS** (Workshop notes)
  - C5 (Mapping): **PASS**
  - C6 (License): **CONDITIONAL** (GPL-3.0 is a strong copyleft license; Apache 2.0 / MIT are strongly preferred for academic/commercial benchmarks)
  - C7 (Reproducibility): **CONDITIONAL** (Heavily integrated with Splunk logging and Docker workshop setup)
  - C8 (Multi-Layer): **PASS**
- **Suitability Score**: **7.2 / 10**
- **Recommendation**: **HELD IN RESERVE** (VAmPI and c{api}tal are superior in licensing and simplicity).

---

### Candidate 4: OWASP crAPI (Completely Ridiculous API)
- **Repository**: `https://github.com/OWASP/crAPI`
- **Author / Provenance**: OWASP Foundation (Community project led by Levo.ai & 42Crunch)
- **License**: MIT License
- **Technology Stack**: Polyglot microservices:
  - `identity-service`: Java (Spring Boot)
  - `workshop-service`: Java (Spring Boot)
  - `community-service`: Python
  - `web`: React
- **OpenAPI Specification**: `crapi-openapi-spec.json` (OpenAPI 3.0)
- **Vulnerabilities**: Industry standard for OWASP API Security Top 10.
- **Assessment against Criteria**:
  - C1 (Relevance): **PASS**
  - C2 (OpenAPI): **PASS**
  - C3 (Source Code): **FAIL** — Core vulnerabilities (BOLA, Broken Auth, User Management) are implemented in **Java Spring Boot**. The analyzer's `PythonSourceAnalyzer` is strictly a Python AST/Tree-sitter parser. Because modifying the analyzer to support Java is forbidden by the frozen constraint, crAPI cannot be evaluated across source or correlation layers.
  - C4 (Ground Truth): **PASS**
  - C5 (Mapping): **PASS**
  - C6 (License): **PASS**
  - C7 (Reproducibility): **CONDITIONAL** (Requires multi-container microservice mesh)
  - C8 (Multi-Layer): **FAIL** (Cannot evaluate Python source layer on Java services)
- **Suitability Score**: **4.5 / 10**
- **Recommendation**: **REJECTED** (Incompatible implementation language for frozen source static analyzer).

---

### Candidate 5: OWASP Juice Shop
- **Repository**: `https://github.com/juice-shop/juice-shop`
- **Author / Provenance**: OWASP Foundation (Björn Kimminich)
- **License**: MIT License
- **Technology Stack**: Node.js, Express, Angular
- **Assessment against Criteria**:
  - C1 (Relevance): **PASS**
  - C2 (OpenAPI): **CONDITIONAL** (Swagger available, but not natively maintained)
  - C3 (Source Code): **FAIL** (Written in JavaScript/TypeScript; analyzer only supports Python)
  - C8 (Multi-Layer): **FAIL** (Source analysis cannot run)
- **Suitability Score**: **3.0 / 10**
- **Recommendation**: **REJECTED** (Language mismatch).

---

### Candidate 6: Network Traffic / PCAP Datasets (CSIC 2010, CIC-IDS-2017, Kaggle API Datasets)
- **Sources**: Kaggle / Academic IDS datasets
- **Data Modality**: HTTP raw traffic dumps, PCAP network captures, CSV network telemetry.
- **Assessment against Criteria**:
  - C2 (OpenAPI): **FAIL** (No OpenAPI specifications)
  - C3 (Source Code): **FAIL** (No source code repositories)
  - C8 (Multi-Layer): **FAIL** (Designed for runtime ML classifiers, completely unsuitable for static/correlation analysis)
- **Suitability Score**: **1.0 / 10**
- **Recommendation**: **REJECTED** (Incompatible data modality).

---

### Candidate 7: NSA / NIST Juliet Test Suite for Python
- **Repository**: NIST Software Assurance Reference Dataset (SARD)
- **Content**: Synthetic Python test cases for CWEs (CWE-89, CWE-78, etc.).
- **Assessment against Criteria**:
  - C1 (Relevance): **FAIL** (General software CWEs, not REST API security)
  - C2 (OpenAPI): **FAIL** (No OpenAPI specifications)
  - C5 (Mapping): **FAIL** (CLI scripts, no HTTP endpoints or route decorators)
- **Suitability Score**: **2.0 / 10**
- **Recommendation**: **REJECTED** (Not a REST API).

---

## 4. Summary Matrix

| Candidate | Tech Stack | OpenAPI | Python AST | License | Ground Truth | Recommendation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **VAmPI** | Python / Flask | Yes (3.0) | **Yes** | Apache 2.0 | High (Toggle) | **ACCEPTED (Primary)** |
| **c{api}tal** | Python / FastAPI | Yes (3.0) | **Yes** | MIT | High (Challenges) | **ACCEPTED (Secondary)** |
| **vAPI** | Python / Flask | Yes (3.0) | **Yes** | GPL-3.0 | Medium | **RESERVE** |
| **crAPI** | Java / Python / Go| Yes (3.0) | **No (Java core)** | MIT | High | **REJECTED (Language)** |
| **Juice Shop** | Node.js / Express | Partial | **No (Node.js)** | MIT | High | **REJECTED (Language)** |
| **Kaggle PCAP** | Network Traffic | No | **No** | Various | N/A | **REJECTED (Modality)** |
| **Juliet Suite**| Python Scripts | No | Yes (CLI only) | Public Domain | High | **REJECTED (Not API)** |

---

## 5. Architectural Design for External Benchmark Integration

To preserve academic integrity and prevent baseline contamination:

1. **Namespace Isolation**:
   - The Phase 6 baseline benchmark remains untouched in `evaluation/dataset/` (24 cases).
   - The external benchmark will be placed in `evaluation/external_dataset/` with its own `external_ground_truth.yaml`.
2. **Schema Compatibility**:
   - The external dataset will conform strictly to the existing schema (`CaseGroundTruth`, `SecurityProposition`, `ExpectedEndpointPair`, `ExpectedCorrelationState`).
3. **Partitioned Reporting**:
   - The evaluation CLI (`uv run evaluate`) will support partitioned target execution:
     - `--benchmark baseline` (Default: original 24 synthetic cases)
     - `--benchmark external` (External benchmark cases)
     - `--benchmark all` (Combined cross-dataset analysis)
4. **Frozen Engine Compliance**:
   - The frozen analyzer will be run with zero modifications. If the analyzer fails to detect certain complex or framework-specific vulnerabilities in VAmPI, that will be documented as an empirical research finding rather than prompting rule modifications.
