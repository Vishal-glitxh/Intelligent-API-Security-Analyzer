# Phase 3 — Source-Code Static Analysis Architecture & Specification

## 1. Overview & Objective

The **Source-Code Analyzer** is a defensive, deterministic, evidence-based static analysis engine designed to extract security-relevant implementation evidence from Python REST API source trees (FastAPI and Flask).

The engine adheres strictly to an **evidence-first** methodology:

```
source code
  → safe parsing
  → normalized source model
  → security evidence extraction
  → source security rules
  → structured findings
```

Security rules do **not** depend directly on raw, unstable AST nodes. Instead, rules operate on immutable, normalized domain representations (`NormalizedSourceTree`, `NormalizedSourceEndpoint`, `SourceSecurityEvidence`) preserving end-to-end source provenance.

---

## 2. Strict Static-Only Security Boundary

Target source code submitted for analysis is treated as untrusted data:

* **NEVER imported** into the Python runtime
* **NEVER executed**, instantiated, or eval'd
* **NEVER run via subprocess**
* **NEVER connected** to databases, filesystems outside the sandbox, or network interfaces

The analyzer operates exclusively on raw source bytes and parsed syntactic structures (Python standard library `ast` and tree-sitter C grammar bindings).

An explicit test verification in `backend/tests/test_source_parser.py` (`test_target_code_is_never_executed`) executes hostile source code containing runtime `sys.exit()` and process mutation side-effects, verifying that static ingestion parses the file cleanly without triggering any runtime side-effects.

---

## 3. Defensive Ingestion & Deterministic Hashing

The source loader (`backend/app/analysis/source/loader.py`) implements deterministic bounds to defend against denial-of-service, zip bombs, and unbounded recursion:

| Bound | Threshold | Action on Exceeded |
|---|---|---|
| **Max File Size** | 1,048,576 bytes (1 MB) | Log diagnostic warning and skip file |
| **Max Total Size** | 10,485,760 bytes (10 MB) | Abort scan (`SourceLoadingError`) |
| **Max File Count** | 500 files | Abort scan (`SourceLoadingError`) |
| **Ignored Paths** | `.git`, `__pycache__`, `.venv`, `node_modules`, `tests` | Silently skipped |

### Deterministic Tree Hashing
All ingested files are sorted lexicographically by normalized relative POSIX path. The overall source tree hash is computed as:

$$\text{Tree Hash} = \text{SHA-256}\left(\sum_{i=1}^N \text{path}_i \parallel \text{file\_hash}_i\right)$$

This guarantees that identical source trees yield identical hashes regardless of underlying filesystem traversal order.

---

## 4. Parser Strategy: Python AST & Tree-Sitter

The parsing engine (`backend/app/analysis/source/parser.py`) combines:
1. **Python Standard Library `ast`**: Extracts high-fidelity lexical information, typed assignments, decorator structures, function signatures, and control flow.
2. **Tree-Sitter (`tree-sitter` + `tree-sitter-python`)**: Provides resilient concrete syntax tree (CST) parsing capable of recovering from syntax errors and malformed source fragments.

### Resilience & 1-Indexed Coordinate Model
* Python AST `col_offset` is 0-indexed; the analyzer automatically normalizes all coordinates to **1-indexed lines and columns** (`column = col_offset + 1`), ensuring strict schema alignment with `Evidence` and `SourceLocation`.
* Syntax errors do not crash the pipeline; they are recorded as `SourceDiagnostic(severity="error")` and remaining valid files continue through analysis.

---

## 5. Framework Extraction & Canonical Endpoint Representation

The analyzer currently supports:
* **FastAPI** (`backend/app/analysis/source/fastapi.py`)
* **Flask** (`backend/app/analysis/source/flask.py`)
* **Generic Python** (`backend/app/analysis/source/framework.py`)

### Endpoint Extraction Details

#### FastAPI
* Detects `@app.get()`, `@router.post()`, `@api_route()`, etc.
* Resolves `APIRouter(prefix="/...")` declarations and prepends prefixes to canonical paths.
* Recovers router-level dependencies: `APIRouter(dependencies=[Depends(verify_token)])`.
* Detects handler parameter dependencies: `current_user: User = Depends(get_current_user)`.

#### Flask
* Detects `@app.route(...)` and Blueprint routes `@bp.route(...)`.
* Resolves `Blueprint("api", __name__, url_prefix="/...")` prefixes.
* Normalizes Flask-style route parameters (`/users/<int:user_id>` or `/users/<user_id>`) into canonical OpenAPI-compatible bracket notation (`/users/{user_id}`).
* Detects `@login_required` authentication decorators.

### Deterministic Endpoint Mapping (Preparation for Phase 4)
Each extracted endpoint maintains a bidirectional, deterministic mapping:

$$\text{Canonical Spec Path } (\{param\}) \longleftrightarrow \text{Source Endpoint} \longleftrightarrow \text{Handler Function} \longleftrightarrow \text{File} \longleftrightarrow \text{Source Location}$$

---

## 6. Structured Security Evidence Model

Security evidence is modeled as immutable, structured records:

```python
@dataclass(frozen=True)
class SourceSecurityEvidence:
    category: EvidenceCategory  # AUTHENTICATION, AUTHORIZATION, OBJECT_ACCESS, TENANT_ISOLATION, INPUT_VALIDATION, DATABASE_ACCESS, SECRET, CONFIGURATION
    strength: EvidenceStrength  # STRONG, MEDIUM, WEAK
    message: str
    location: SourceLocation | None
    symbol: str | None
    endpoint_path: str | None
    endpoint_method: str | None
    handler_name: str | None
    extracted_value: str | None
    rationale: str
```

### Evidence Categories
* `AUTHENTICATION`: Recovered authentication dependencies (`Depends()`, `@login_required`).
* `AUTHORIZATION`: Role checks, permission checks, ownership comparisons.
* `OBJECT_ACCESS`: Data store lookups (`db.query().get()`, `find_one()`, etc.) driven by user-controlled path parameters.
* `TENANT_ISOLATION`: Scoped queries constraining data access by `tenant_id` or `organization_id`.
* `INPUT_VALIDATION`: Explicit parameter validation checks (`if not param: raise ...`).
* `DATABASE_ACCESS`: SQL execution patterns, raw query concatenation, or ORM method invocations.
* `SECRET`: String literals assigned to credential-like variable names or recognizable API token patterns.
* `CONFIGURATION`: Safe environment or configuration lookups (e.g. `os.getenv()`, `settings.key`).

---

## 7. Authentication State Classification (`API-SOURCE-AUTH-001`)

In accordance with scientific rigor, the analyzer **never equates missing static evidence with missing authentication**.

Authentication state on every endpoint is classified into one of three distinct categories:
1. `AUTH_PRESENT`: Statically recognizable authentication evidence was recovered (via handler dependency, route decorator, or parent router dependency).
2. `AUTH_ABSENT_IN_ANALYZABLE_SCOPE`: No recognizable authentication was found within the analyzable AST scope. (Authentication may still be provided upstream by an API gateway, ingress controller, or unanalyzable middleware).
3. `AUTH_UNKNOWN`: Endpoint construction or handler dispatch is too dynamic to resolve deterministically.

### Finding Title & Wording
* **Title**: `Potential Missing Recognizable Authentication Evidence ({METHOD} {PATH})`
* **Rationale**: Explicitly documents that absence of evidence in the static AST does not prove absence of runtime security.

---

## 8. Authorization Flow Model (`API-SOURCE-AUTHZ-001`)

To prevent arbitrary heuristics, authorization analysis models explicit data-flow relationships:

$$\text{Endpoint Parameter} \longrightarrow \text{Identifier Usage} \longrightarrow \text{Object / Resource Lookup} \longrightarrow \text{Authorization Check}$$

A potential BOLA/IDOR finding is emitted **only** when all three conditions hold:
1. A user-controlled path parameter is identified (`{user_id}`, `{account_id}`, etc.).
2. The parameter reaches a recognizable object lookup method (`find_one()`, `filter_by()`, `get()`, `query()`, `select()`).
3. No recognizable authorization evidence (ownership check `caller.id == obj.owner_id`, role check `user.role == 'admin'`, or tenant isolation `obj.tenant_id == caller.tenant_id`) is recovered within the handler or enclosing scope.

### Finding Title & Wording
* **Title**: `Potential Missing Object-Level Authorization Evidence ({METHOD} {PATH})`
* Never asserts confirmed BOLA; explicitly advises verification of authorization logic.

---

## 9. Deterministic Hardcoded-Secret Classification (`API-SECRET-001`)

The secret detection engine (`backend/app/analysis/source/secrets.py`) uses multi-signal deterministic classification:

1. **Safe Configuration Classification**:
   * Assignments invoking `os.getenv()`, `os.environ.get()`, or `settings.*` emit `EvidenceCategory.CONFIGURATION` with `EvidenceStrength.STRONG`.
   * These **never** generate a secret finding.
2. **Placeholder / Test Value Detection**:
   * String literals containing `dummy`, `test`, `example`, `placeholder`, `changeme`, `123456` are classified as `EvidenceStrength.WEAK` and suppressed from high-severity findings.
3. **Recognizable Token Patterns**:
   * Deterministic regular expressions detect:
     * AWS Access Keys (`AKIA[0-9A-Z]{16}`)
     * GitHub Personal Access Tokens (`ghp_[a-zA-Z0-9]{36}`)
     * Slack Tokens (`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}`)
     * Private Key Headers (`-----BEGIN ... PRIVATE KEY-----`)
4. **Secret Redaction**:
   * All extracted secret values are masked: `AKIA...7XYZ`. Complete secret values are **never** stored or emitted.

---

## 10. Research Calibration Disclaimer

Severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and confidence (`0.60` - `0.90`) assigned to findings are **initial baseline implementation metadata**. They reflect static evidence certainty within the current engineering model and are **not** statistically validated real-world probabilities.

Formal calibration and empirical validation will be conducted during experimental evaluation on benchmark API corpora.

---

## 11. Known Limitations

1. **Dynamic Route Registration**: Dynamic loops calling `app.add_api_route()` or dynamic decorator wrapping are not resolved. The analyzer flags them as unextractable rather than guessing.
2. **Global / Ingress Authentication**: Gateway-level authentication (Kong, Envoy, Cloudflare Access) cannot be recovered from source code alone. This is an intentional design boundary to be addressed via Phase 4 cross-layer correlation.
3. **Inter-Procedural Data Flow**: Complex multi-hop pointer aliasing and dependency injection across remote microservices are outside static AST scope.

---

## 12. Recommended Phase 4 Correlation Architecture

Phase 4 will ingest both `NormalizedOpenAPI` (Phase 2) and `NormalizedSourceTree` (Phase 3) into a unified correlation engine:

```
NormalizedOpenAPI (spec)          NormalizedSourceTree (source)
           \                                   /
            \                                 /
             ▼                               ▼
       [Canonical Endpoint & Parameter Matching Engine]
                             │
                             ▼
                  [Correlated Entity Model]
                   ├── Spec Security Requirements
                   ├── Source Authentication Evidence
                   ├── Spec Path Parameters & Types
                   ├── Source Data Lookups & Authz Checks
                   └── Configured Secrets vs. Spec Schemes
                             │
                             ▼
          [Deterministic Cross-Layer Correlation Rules]
           ├── Spec claims auth, but source lacks evidence
           ├── Source enforces auth, but spec documents public
           ├── Spec defines ID parameter, source queries DB without authz check
           └── Correlated Confidence Boost / False-Positive Suppression
```
