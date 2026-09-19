# Rule Authoring Guide & Security Analysis Standards

This guide defines the engineering standard for authoring deterministic, evidence-backed security rules for the Intelligent API Security Analyzer.

---

## 1. Core Principles

1. **Deterministic & Evidence-Backed**: Rules must produce identical results given identical inputs. An LLM must **never** be used as a vulnerability oracle.
2. **Strict Boundary Isolation**:
   - Security rules must **never** import or interact with FastAPI route objects, HTTP request/response models, or database sessions.
   - Rules interact exclusively with the immutable `AnalysisContext`.
3. **Normalized Input Consumption**:
   - Specification-level rules consume `NormalizedOpenAPI` (endpoints, operations, parameters, schemas).
   - Source-level rules consume `NormalizedSourceTree` (AST nodes, tree-sitter syntax trees).
   - Correlation rules compare normalized specification entities with normalized source entities.
4. **Severity vs. Confidence**:
   - **Severity** (`Severity.LOW`, `MEDIUM`, `HIGH`, `CRITICAL`): Represents the architectural impact if exploited.
   - **Confidence** (`0.0` to `1.0`): Represents the certainty of the static evidence. If runtime exploitability cannot be proven from static source code, confidence must reflect the potential nature of the finding.
5. **Mandatory Evidence Retention**:
   - Every `Finding` must contain at least one `Evidence` item.
   - Evidence records the `kind`, `message`, optional `file`, `line`, `column`, `source_hash`, and `provenance`.

---

## 2. Rule Implementation Template

```python
from app.analysis.context import AnalysisContext
from app.analysis.findings import Evidence, Finding, Severity
from app.analysis.rules.base import SecurityRule


class ExampleMissingAuthRule(SecurityRule):
    rule_id = "API-SEC-001"
    rule_version = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []

        if not context.specification:
            return findings

        for endpoint in context.specification.endpoints:
            for op in endpoint.operations:
                # Deterministic check: sensitive mutation without security requirement
                if op.method in ("post", "put", "delete") and not op.security_requirements:
                    ev = Evidence(
                        kind="specification_operation",
                        message=f"Operation {op.method.upper()} {op.path} lacks security requirements.",
                        file=op.location.file if op.location else None,
                        line=op.location.line if op.location else None,
                        provenance=f"spec:{op.path}#{op.method}",
                    )
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            rule_version=self.rule_version,
                            title=f"Unauthenticated {op.method.upper()} Operation",
                            severity=Severity.HIGH,
                            confidence=0.9,
                            rationale="State-changing operations must require client authentication.",
                            remediation="Add security schemes to the operation in OpenAPI and enforce via FastAPI dependencies.",
                            evidence=(ev,),
                        )
                    )

        return findings
```

---

## 3. Mandatory 4-Part Testing Contract

Every authored security rule must be accompanied by comprehensive tests fulfilling the four-part contract:

1. **Positive Vulnerable Case**: Verifies that a known vulnerable pattern generates the expected finding, correct severity, and confidence.
2. **Negative Secure Case**: Verifies that a properly secured or patched endpoint produces zero false positives.
3. **Edge Case**: Verifies rule behavior against degenerate inputs (e.g. missing sections, empty endpoints, malformed types) without raising unhandled exceptions.
4. **Evidence Location Test**: Verifies that the emitted `Evidence` retains exact source or specification coordinates (`file`, `line`, `column`, `provenance`).

---

## 4. Implemented Specification-Level Rules (Phase 2 Baseline)

### `API-AUTH-001`: Potential Missing Authentication Requirement
- **Scope**: Evaluates explicit OpenAPI security semantics (operation-level `security`, global `security`, defined security schemes).
- **Mandatory Semantics**: Path names (e.g. `/login`, `/health`, `/docs`) must **never** be used as authoritative exemptions. Path hints are only recorded as secondary, non-authoritative contextual metadata. State-changing operations (`POST`, `PUT`, `DELETE`, `PATCH`) without effective security schemes receive `Severity.HIGH`; read operations receive `Severity.MEDIUM`.
- **Default Severity / Confidence**: `HIGH` / `0.85` (mutations), `MEDIUM` / `0.70` (reads).

### `API-AUTH-002`: Potential Inconsistent Authentication Coverage
- **Scope**: Examines sibling operations on the same resource path where authenticated operations co-exist with unauthenticated operations.
- **Mandatory Semantics**: Does **not** flag every difference as a vulnerability; reports only where sibling operations on the same resource provide baseline evidence of an intended security boundary.
- **Finding Title**: "Potential Inconsistent Authentication Coverage (`{METHOD} {PATH}`)" (qualified wording, never confirmed vulnerability).
- **Default Severity / Confidence**: `HIGH` / `0.80` (mutations), `MEDIUM` / `0.70` (reads).

### `API-INPUT-001`: Potential Missing Input Constraints
- **Scope**: Narrow, evidence-backed inspection of well-defined security-relevant parameters:
  1. *Pagination limits*: missing `maximum` (risking denial-of-service / memory exhaustion).
  2. *Redirect destinations / callbacks*: missing `format: uri`, `pattern`, or `enum` (risking open redirects).
  3. *File / filesystem paths*: missing `pattern`, `maxLength`, or `enum` (risking path traversal).
- **Mandatory Semantics**: Does not demand arbitrary constraints on generic strings; requires a defensible reason for every flagged parameter.
- **Default Severity / Confidence**: `MEDIUM` / `0.75`.

### `API-DATA-001`: Potential Sensitive-Data Exposure in Response Schema
- **Scope**: Scans response schemas across HTTP success codes (`200`, `201`, `204`) for sensitive properties.
- **Indicators**:
  - *Strong Indicators*: `password`, `secret`, `private_key`, `api_key`, `access_token`, `refresh_token`.
  - *Moderate Indicators*: `credential`, `auth_token`, `ssn`.
- **Mandatory Semantics**: Qualified finding title ("Potential Sensitive-Data Exposure in Response '{property}'"). Explicitly states that OpenAPI models contracts, not runtime byte streams.
- **Default Severity / Confidence**: `HIGH` / `0.85` (strong), `MEDIUM` / `0.70` (moderate).

### `API-AUTHZ-001`: Potential Broken Object Level Authorization (BOLA/IDOR) Architectural Indicator
- **Scope**: Evaluates endpoints exposing direct resource/object identifiers in their path templates (e.g. `/{id}`, `/{accountId}`) paired with state access methods (`GET`, `PUT`, `DELETE`, `PATCH`).
- **Mandatory Semantics**: Reports strictly as an architectural indicator. The presence of bearer authentication does not prove authorization, nor does missing scopes prove exploitability.
- **Finding Title**: "Potential Broken Object Level Authorization (BOLA/IDOR) architectural indicator (`{METHOD} {PATH}`)".
- **Default Severity / Confidence**: `HIGH` / `0.65`.

---

## 5. Implemented Source-Level Rules (Phase 3 Baseline)

### `API-SECRET-001`: Potential Hardcoded Secret or Sensitive Credential in Source
- **Scope**: Evaluates module and function-level variable assignments for hardcoded secrets, private keys, and API tokens.
- **Mandatory Semantics**: Uses multi-signal deterministic classification. Assignments loading values via `os.getenv`, `os.environ.get`, or application settings generate safe `CONFIGURATION` evidence and **never** produce a finding. Values containing test/placeholder keywords (`dummy`, `test`, `example`) are categorized as `WEAK` and suppressed from high-severity findings.
- **Redaction**: Full secret values are **never** exposed in findings; values are masked deterministically (`prefix...suffix`).
- **Default Severity / Confidence**: `HIGH` / `0.85` (strong / recognized token format), `MEDIUM` / `0.70` (general credential variable).

### `API-SOURCE-AUTH-001`: Potential Missing Recognizable Authentication Evidence
- **Scope**: Inspects source handlers and router declarations for recognizable authentication decorators and dependency injection.
- **Mandatory Semantics**: The absence of recognizable source evidence must **never** be equated with absence of authentication. Authentication state is partitioned into `AUTH_PRESENT`, `AUTH_ABSENT_IN_ANALYZABLE_SCOPE`, and `AUTH_UNKNOWN`. A finding is generated only for endpoints where authentication is absent within the analyzable scope.
- **Finding Title**: "Potential Missing Recognizable Authentication Evidence (`{METHOD} {PATH}`)".
- **Default Severity / Confidence**: `HIGH` / `0.75` (mutations), `MEDIUM` / `0.65` (reads).

### `API-SOURCE-AUTHZ-001`: Potential Missing Object-Level Authorization Evidence
- **Scope**: Evaluates endpoints accepting user-controlled path parameters that reach data store lookup calls without recognizable authorization checks.
- **Mandatory Semantics**: Models explicit evidence relationships: `endpoint parameter -> identifier usage -> object lookup -> authorization evidence`. Recognizable authorization evidence includes ownership checks (`caller.id == obj.owner_id`), role checks (`user.role == 'admin'`), and tenant isolation checks (`obj.tenant_id == caller.tenant_id`). A finding is emitted only when a user-controlled parameter reaches an object lookup and zero authorization evidence is recovered within the handler scope.
- **Finding Title**: "Potential Missing Object-Level Authorization Evidence (`{METHOD} {PATH}`)".
- **Default Severity / Confidence**: `HIGH` / `0.70`.

---

## 6. Severity and Confidence Calibration

Initial severity and confidence values (e.g., HIGH / 0.85) are implementation baseline defaults and must **not** be interpreted as empirically validated probabilities. Empirical calibration of precision, recall, and confidence scores will be conducted during the research evaluation phase against ground-truth benchmarks. Severity and confidence are maintained as distinct metrics and are never collapsed into a single scalar.


