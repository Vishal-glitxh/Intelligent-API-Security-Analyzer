# Phase 7.3 External Benchmark Dataset — VAmPI Integration

## 1. Provenance and Licensing
- **Upstream Repository**: [`erev0s/VAmPI`](https://github.com/erev0s/VAmPI)
- **Author**: Dimitrios Vlachos (Erev0s) — Security Researcher & OWASP Contributor
- **Pinned Commit**: `f16052dce83f05847133ec98f01c5193a41de7d8`
- **Commit Date**: 2026-04-07T20:02:39Z
- **Upstream License**: MIT License (`LICENSE` included in this directory)
- **Framework & Technology Stack**: Python 3, Flask, Connexion, SQLAlchemy
- **Specification Format**: Native OpenAPI 3.0 specification (`openapi_specs/openapi3.yml`)

---

## 2. Benchmark Design and Quality Principles
1. **Zero Contamination**: The external benchmark is strictly isolated from the 24-case Phase 6 synthetic baseline (`evaluation/dataset/`). Baseline reports and metrics are never overwritten.
2. **Frozen Analyzer**: Analysis is executed against the frozen Phase 1–5 engine (`backend/app/analysis/`). Zero rule modifications or parser additions were introduced.
3. **Independently Verifiable Ground Truth**: Ground truth labels represent static security conditions (e.g., absence of security schemes, sensitive property names, coarse scoping), not runtime exploitability assumptions.
4. **Decoupled Ground Truth**: Ground truth is established independently from analyzer outputs. Analyzer findings are never used to define ground truth.

---

## 3. Curated Benchmark Cases (12 Cases)

| Case ID | Endpoint | Method | Category | Label | Expected Condition | OpenAPI Evidence | Source Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `VAMPI-001` | `/createdb` | GET | `authentication` | `SECURITY_CONDITION_PRESENT` | `missing_authentication` = True | No security requirements in spec | `api_views/main.py:populate_db()` drops and seeds DB with no auth |
| `VAMPI-002` | `/` | GET | `authentication` | `INTENTIONAL_PUBLIC` | `missing_authentication` = False | No security requirements; public help response | `api_views/main.py:basic()` returns public help message dictionary |
| `VAMPI-003` | `/users/v1` | GET | `authentication` | `SECURITY_CONDITION_PRESENT` | `missing_authentication` = True | No security requirements in spec | `api_views/users.py:get_all_users()` returns all user records without auth |
| `VAMPI-004` | `/users/v1/_debug` | GET | `sensitive_data` | `SECURITY_CONDITION_PRESENT` | `sensitive_data_exposure` = True | Response 200 schema includes `password` property | `models/user_model.py:User.json_debug()` serializes plaintext password |
| `VAMPI-005` | `/users/v1/login` | POST | `authentication` | `INTENTIONAL_PUBLIC` | `missing_authentication` = False | Login credentials submission endpoint | `api_views/users.py:login_user()` authenticates user and mints JWT |
| `VAMPI-006` | `/me` | GET | `authentication` | `SECURITY_CONDITION_ABSENT` | `missing_authentication` = False | `security: [bearerAuth: []]` | `api_views/users.py:me()` validates token via `token_validator()` |
| `VAMPI-007` | `/users/v1/{username}` | GET | `authentication` | `SECURITY_CONDITION_PRESENT` | `missing_authentication` = True | Sibling DELETE has auth; GET has no security (inconsistent auth) | `api_views/users.py:get_by_username()` does not authenticate caller |
| `VAMPI-008` | `/users/v1/{username}` | DELETE | `authentication` | `SECURITY_CONDITION_ABSENT` | `missing_authentication` = False | `security: [bearerAuth: []]` | `api_views/users.py:delete_user()` enforces token and admin check |
| `VAMPI-009` | `/users/v1/{username}/password` | PUT | `authorization` | `SECURITY_CONDITION_PRESENT` | `missing_object_level_authorization` = True | Path param `{username}` with coarse Bearer auth | `api_views/users.py:update_password()` allows updating other user password |
| `VAMPI-010` | `/books/v1` | GET | `authentication` | `SECURITY_CONDITION_PRESENT` | `missing_authentication` = True | Sibling POST has auth; GET has no security (inconsistent auth) | `api_views/books.py:get_all_books()` returns catalog without token check |
| `VAMPI-011` | `/books/v1` | POST | `authentication` | `SECURITY_CONDITION_ABSENT` | `missing_authentication` = False | `security: [bearerAuth: []]` | `api_views/books.py:add_new_book()` validates caller token |
| `VAMPI-012` | `/books/v1/{book_title}` | GET | `authorization` | `SECURITY_CONDITION_PRESENT` | `missing_object_level_authorization` = True | Path param `{book_title}` with coarse Bearer auth | `api_views/books.py:get_by_title()` leaks book secrets to any authenticated user |

---

## 4. Excluded Cases and Rationale

| Case / Endpoint | Intended / Proposed Flaw | Reason for Exclusion |
| :--- | :--- | :--- |
| `PUT /users/v1/{username}/email` | ReDoS / BOLA | **Contract/Implementation Discrepancy & Unsupported Category**: The endpoint path specifies `{username}`, but the code ignores it and updates `User.query.filter_by(username=resp['sub'])` (the token subject). The author's stated vulnerability is ReDoS on regex parsing (`if vuln: # Regex DoS`), which is outside the static OpenAPI/AST taxonomy. |
| `POST /users/v1/register` | Mass Assignment | **Undeclared Contract Surface**: The mass assignment flaw relies on the backend accepting an undeclared `admin` boolean field. The OpenAPI 3.0 specification does not declare `admin` in `requestBody.properties`, meaning the specification layer has no evidence surface for mass assignment. |
| `GET /users/v1/{username}` (SQLi) | SQL Injection | **Taxonomy Boundary**: While `GET /users/v1/{username}` is included under `authentication` (inconsistent auth), SQL injection cannot be tracked as an independent proposition because `injection` is not in the frozen rule taxonomy (`CATEGORY_RULE_MAP`). Classifying it as a false negative would violate taxonomy alignment. |
| `POST /users/v1/login` (Enumeration) | Username / Password Enumeration | **Response Nuance / Non-Contract**: Differentiating error messages between "Username does not exist" and "Password is not correct" is runtime message formatting, not represented in OpenAPI contract structures or static AST extraction. |

---

## 5. Architectural Execution
The external benchmark is executed via:
```bash
uv run evaluate --benchmark external
```
Artifacts are emitted to `evaluation/reports/external/` and `evaluation/runs/external/`, ensuring total partition isolation.
