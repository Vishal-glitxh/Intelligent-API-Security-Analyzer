# Threat Model & Defensive Baseline

The Intelligent API Security Analyzer statically inspects untrusted OpenAPI specification documents and source code repositories. Because uploaded payloads may originate from untrusted or adversarial parties, the system treats all user-supplied inputs as potentially malicious.

---

## 1. System Assets

1. **Host & Platform Integrity**: Underlying worker processes, host OS, containers, and database infrastructure.
2. **Platform Credentials & Secrets**: `SESSION_SECRET`, database passwords, internal API keys.
3. **Customer Intellectual Property**: Uploaded source code repositories and API specifications.
4. **Security Findings & Evidence**: Proprietary security audit results and vulnerability evidence.
5. **Audit Logs & System Metadata**: Tamper-resistant trail of scans, actions, and administrative operations.

---

## 2. Trust Boundaries & Data Flow

```
[Untrusted Client / User]
          │  (Archive Upload / OpenAPI Spec)
          ▼
┌──────────────────────────────────────────────┐
│ HTTP / API Gateway (FastAPI)                 │
│  - Enforce streaming upload size limits      │
│  - Require an API access token               │
│  - Rate-limit scan submissions               │
└──────────────────────┬───────────────────────┘
                       │ Picklable Context / Path
                       ▼
┌──────────────────────────────────────────────┐
│ Application Services & Job Runner            │
│  - Safe archive unpacking & path traversal   │
│  - Quota enforcement (files, sizes)          │
│  - Ephemeral workspace allocation            │
└──────────────────────┬───────────────────────┘
                       │ Process Isolation Boundary (Pickled IPC)
                       ▼
┌──────────────────────────────────────────────┐
│ Analysis Worker (LocalProcessJobRunner)      │
│  - ZERO uploaded code execution              │
│  - Tree-sitter & AST static parsing only     │
│  - Memory ceiling and execution timeout      │
│  - No network-dependent analysis operations  │
└──────────────────────────────────────────────┘
```

---

## 3. Specific Threats & Defensive Controls

### 3.1 Malicious Archives & Decompression Bombs
- **Threat**: Uploading zip/tar archives containing compression bombs (e.g. 42.zip) or millions of nested files designed to exhaust storage, memory, or inodes.
- **Controls**:
- `MAX_SPEC_BYTES` (default 5 MB) and `MAX_ARCHIVE_BYTES` (default 25 MB):
  streaming request limits enforced before oversized data is retained.
- `MAX_FILES_PER_SCAN` (default 2,000 files): Maximum permitted file count during extraction.
- `MAX_UNCOMPRESSED_BYTES` (default 50 MB): Cumulative uncompressed byte counter aborted immediately if threshold exceeded.

### 3.2 Path Traversal & Zip Slip
- **Threat**: Archive entries containing `../`, absolute paths (`/etc/passwd`), or relative paths intended to escape the target extraction folder.
- **Controls**:
  - Every extracted archive entry path is resolved and validated to ensure `os.path.commonpath([target_dir, resolved_path]) == target_dir`.
  - Rejection of paths starting with path separators or containing directory traversal tokens.

### 3.3 Symlink & Hardlink Attacks
- **Threat**: Archives containing symlinks targeting `/etc/shadow`, `/proc`, or external directories to trick the analyzer into reading host files.
- **Controls**:
  - Immediate rejection and abort if any archive entry is identified as a symbolic link (`is_sym()`) or hardlink.

### 3.4 Arbitrary Code Execution
- **Threat**: Adversary embeds malicious Python code in `__init__.py`, decorators, or top-level module statements hoping the analyzer executes or imports them.
- **Controls**:
  - **Zero Execution Guarantee**: Uploaded source code is **never imported, run, or evaluated**.
  - All source parsing is conducted strictly via AST parsers (`ast.parse`) and concrete syntax tree parsers (`tree-sitter-python`).

### 3.5 Workspace Lifecycle & Storage Leakage
- **Threat**: Residual source files or temporary extraction folders consuming disk space or enabling cross-project data leakage.
- **Controls**:
  - All archive operations occur inside uniquely named temporary directories (`tempfile.TemporaryDirectory`).
  - Strict cleanup guaranteed via `try...finally` context managers upon scan completion, failure, or timeout.

### 3.6 Worker Resource Quotas, Concurrency & Infrastructure Boundaries
- **Threat**: Static analysis rules encountering deeply recursive syntax or catastrophic backtracking in regular expressions causing worker denial of service, memory exhaustion, or unconstrained concurrency.
- **Application-Level Controls**:
  - Global queue capacity limit (`MAX_ACTIVE_SCANS`) preventing unbounded job accumulation.
  - Per-client concurrent scan limit (`MAX_CONCURRENT_SCANS_PER_CLIENT`).
  - Worker concurrency bound via shared `LocalProcessJobRunner` process pool (`MAX_WORKER_PROCESSES`).
  - Application-level execution timeout (`SCAN_TIMEOUT_SECONDS`).
  - POSIX address-space ceiling via `resource.setrlimit(RLIMIT_AS)` where supported.
- **Deployment-Level Infrastructure Requirements**:
  - Python-level timeouts and address-space hints do **not** replace OS-level CPU and memory isolation.
  - In production deployments, container runtimes (Docker/Kubernetes) MUST enforce hard cgroup limits (`limits.memory`, `limits.cpu`).
  - Network egress policies (Kubernetes NetworkPolicies or Docker internal networks) must isolate worker processes from internal intranet assets.

### 3.7 Authentication & Authorization Boundary
- **Threat**: Unauthenticated scan submissions, arbitrary scan report access, or cross-tenant scan tampering.
- **Controls**:
  - Mandatory token authentication (`X-API-Key` or `Authorization: Bearer <token>`) on all scan endpoints.
  - Per-scan client identity persistence (`client_id` on Scan model).
  - Explicit multi-tenant authorization boundary: clients are restricted to viewing only their own scan status, findings, and reports; cross-client access is rejected with `403 Forbidden`.

### 3.8 Secret & Credential Leakage
- **Threat**: Sensitive configuration secrets (`SESSION_SECRET`, database connection strings) appearing in scan reports or logs.
- **Controls**:
  - In production mode, `SESSION_SECRET` and `API_ACCESS_TOKEN` must be at least 32 characters and cannot use default placeholders.
  - All database queries and logging scrub sensitive variables.

### 3.9 External OpenAPI Reference Retrieval
- **Threat**: Third-party OpenAPI validation can follow external references, allowing an
  uploaded specification to request internal network resources or local files.
- **Worker-boundary control**: `guard_specification_references` safely parses the document
  before the frozen analyzer's loader and validator run. It checks nested mappings and
  sequences, including YAML aliases and merge keys, without resolving references.
  `$ref`, `$dynamicRef`, and `$recursiveRef` must be valid in-document URI fragments:
  root references, JSON Pointers, or JSON Schema anchors. HTTP(S), file, relative-file,
  absolute-path, and other external references are rejected, including in unused components.
  The policy conservatively checks these keywords wherever they occur, including examples.
- **Parser resource budgets**: The worker preflight retains the frozen loader's 10 MiB
  document ceiling and enforces composition-time limits of 50,000 YAML nodes, 128 nested
  nodes, and 1,024 alias references. Limit violations use the stable sanitized error
  `OPENAPI_PARSING_ERROR: YAML exceeds supported complexity limits.` The bounds apply
  before object construction; byte size also bounds scanning of scalar content.
- **Aliases and merges**: Ordinary aliases are accepted within the alias and node budgets.
  Shared objects are checked once with an iterative traversal, and cyclic aliases are
  rejected before reaching the frozen recursive location walker. YAML `<<` merge keys are
  rejected during construction before PyYAML's merge flattener runs, since nested repeated
  merges can expand mapping entries exponentially. This is a compatibility trade-off for
  uploaded specifications using PyYAML's YAML 1.1 merge extension; project fixtures and
  benchmark specifications do not use merge keys.
- **Errors**: Rejections use stable `OPENAPI_PARSING_ERROR` messages without reference
  values, URLs, parser excerpts, source contents, or filesystem paths.
- **Compatibility and scope**: The frozen analyzer, rule semantics, ground truth, and
  published evaluation artifacts are unchanged. Internal reference resolution remains the
  validator/analyzer's responsibility; admission is not a guarantee that a reference exists.
  Trusted evaluation and direct calls to the frozen validator do not pass through this
  worker guard and must not be used to process untrusted uploads. Network egress isolation
  remains required as defense in depth. These budgets bound parser input and structural
  work but do not provide a hard wall-clock deadline or replace operating-system memory
  limits. This guard is not a general YAML resource sandbox and does not fix upload
  admission, process termination, or other outstanding controls.

### 3.10 Multipart Scan Upload Boundary
- **Threat**: Multipart parsing can spool uploaded file parts before endpoint dependencies run,
  allowing unauthenticated or concurrent callers to consume temporary storage and memory.
- **Authentication and parsing**: The scan endpoint has no automatic `File`/`Form` body
  parameters. FastAPI resolves its authentication dependencies first; the endpoint then
  parses multipart data with a two-file, one-field limit and closes the form context on exit.
  The existing multipart field names remain `openapi_file`, `source_archive`, and optional
  `project_name`.
- **Request and file budgets**: An ASGI receive wrapper counts actual request bytes as
  multipart parsing consumes them and returns 413 above `MAX_UPLOAD_BYTES`; declared lengths
  above the limit are rejected before parsing. `UPLOAD_READ_TIMEOUT_SECONDS` is one total
  deadline for receiving a request body, so a client cannot keep a slot by sending occasional
  bytes indefinitely. Existing 64 KiB reads and per-file spec/archive limits remain. The installed
  Starlette parser does not enforce individual file sizes while spooling, so the total request
  limit and upload admission bound that temporary-spool exposure; file-specific rejection still
  occurs while reading the already bounded form upload.
- **Upload admission**: Finite `MAX_CONCURRENT_UPLOADS` and
  `MAX_CONCURRENT_UPLOADS_PER_CLIENT` reservations are acquired after authentication and before
  multipart parsing, then released in `finally` paths. These counters are process-local. The
  checked-in Docker and Uvicorn commands start one API process and the Compose file defines one
  API service; deployments with multiple workers or replicas need an external admission limit
  or shared coordination to obtain a deployment-wide cap.
- **Cleanup and recovery**: Form uploads are closed on normal, exceptional, cancellation, and
  disconnect exits. Scan workspace cleanup does not follow a workspace symlink and startup
  recovery removes workspaces for scan records it marks interrupted. Current recovery assumes the
  configured single API process; multi-process deployments must coordinate startup recovery so
  one instance cannot recover another's active scans. OS/container temporary-storage quotas
  remain an infrastructure control.

### 3.11 Health Checks and Startup Recovery
- **Liveness**: `/health/live` (and the compatibility path `/health`) reports only that the API
  process is serving requests. It does not prove database connectivity or successful scan recovery.
- **Readiness**: `/health/ready` reports ready only after startup recovery marks interrupted scans
  failed, removes their per-scan workspaces, and a database `SELECT 1` succeeds. Database errors
  and incomplete startup recovery return HTTP 503 with a generic reason; credentials and driver
  details are not returned. Compose uses readiness for its API health check.
- **Recovery failure**: The process remains live to aid diagnosis, but readiness remains false for
  that process lifetime. Fix the database or workspace issue and restart the API so recovery runs
  again. Recovery and admission remain single-process controls; this health contract does not
  establish multi-worker or multi-replica safety.

### 3.12 Scan Submission Rate Limiting
- **Identity and availability**: `POST /api/v1/scans` uses a fixed-window limit of
  `SCAN_RATE_LIMIT_REQUESTS` submissions per `SCAN_RATE_LIMIT_WINDOW_SECONDS` for each
  authenticated `client_id`. API-key and Bearer forms for the same client share one bucket.
  Missing or invalid credentials share one anonymous bucket, so rotating attacker-controlled
  tokens or peer addresses cannot allocate buckets or avoid throttling. Anonymous traffic cannot
  consume the independent quota of a valid client.
- **Memory bounds and expiry**: The process stores buckets only for configured client IDs and one
  anonymous identity. Expired timestamps and empty buckets are removed on each scan submission;
  traffic from unknown credentials cannot grow the map. Adding very many client IDs through
  trusted configuration increases the possible bucket count accordingly.
- **Deployment limitation**: Buckets are in process memory, reset on restart, and are not shared
  across workers or replicas. The deployment remains single-process; multi-worker or multi-replica
  deployments need a shared rate-limit coordinator for a deployment-wide limit.

### 3.13 Optional local AI and retrieval
- **Trust boundary**: Scan evidence and user questions may be sent only to the configured local
  Ollama HTTP endpoint. The application calls `/api/tags` for status, `/api/embed` when an
  explicitly configured local embedding model is available, and `/api/generate` for an optional
  explanation. Requests bypass system HTTP proxies. Embedding requests include the question and at
  most 128 candidate texts truncated to 1,200 characters each; generation receives the selected
  sources under the context budget. Both paths apply secret-pattern redaction. The provider
  rejects HTTP redirects to prevent request bodies from being forwarded by a redirect response.
  The bundled OWASP API Top 10 2023
  guidance is paraphrased with per-source URLs and CC BY-SA 4.0 attribution metadata.
- **Local service exposure**: The default endpoint is loopback. Operators can configure Ollama
  independently to listen on other interfaces; they must restrict that network path and protect
  it appropriately. `host.docker.internal` is permitted for the documented local Compose setup.
- **Fallback**: Deterministic scanning and lexical/hashed-vector retrieval do not require Ollama.
  Ollama unavailability or invalid responses produce a deterministic fallback, not a changed scan
  finding. Optional AI status does not determine liveness or database readiness.
- **Index lifecycle and bounds**: An optional local JSON index is rebuilt only through the
  explicit `app.services.rag_index_cli` command; startup and request handling never fetch sources,
  download models, or rebuild it. Manifest input is capped at 8 MiB, each source field and total
  corpus are bounded, document count and chunk count are capped, and the serialized index is capped
  at 64 MiB, with embedding payloads separately capped at 32 MiB. Chunks carry stable IDs, source
  metadata/location, hashes, chunking metadata and—when explicitly generated by the configured local
  model—normalized vectors plus model name, Ollama model digest, and dimension
  metadata. Runtime retrieval checks that identity and the advertised embedding capability and
  dimensions; an incompatible model version or dimension disables semantic retrieval and leaves
  lexical/hash fallback available. The file is written with owner-only permissions and atomically replaced after a
  successful build; failed embedding or validation preserves the prior index. Common secret
  patterns are redacted from indexed titles, content, and provenance locations/URLs. Stale model or
  chunking metadata disables semantic retrieval; lexical/hash fallback remains available. The local
  integrity hash detects
  accidental corruption, not malicious replacement by a process with write access to the index.
- **Source trust and provenance**: Custom manifest documents are operator-supplied and are not
  fetched from their `source_url`; URLs are attribution metadata only. Treat their text as
  untrusted prompt context. The index is a local single-file store, not a multi-user or shared
  coordination service. Protect its directory and back it up under the same controls as other
  locally retained project data.
- **Evaluation and limitations**: `hybrid-rag-retrieval-v1` remains the historical fixed protocol
  for retrieval and deterministic response templates. `hybrid-rag-retrieval-v2` is separately
  versioned, uses a small manually reviewed query set, reports per-query relevance outcomes and
  false positives, and does not change deterministic scanner benchmarks. The separate
  `hybrid-rag-precision-experiment-v1` compared lexical, semantic, hybrid, and conservative
  threshold policies on those same unchanged labels. The current live-semantic candidate requires
  cosine similarity of at least 0.50 before returning a result. This floor applies only when the
  configured model digest and dimensions match a persistent semantic index; it is not applied to
  lexical/hash fallback. On the 17-query set it reduced returned and false-positive source counts
  and improved abstention on three of four zero-relevance controls, while fixed-k macro Precision@5
  remained unchanged and one relevant source was still missed. The adversarial control still
  returned security documents. The value is provisional for the tested embedding model and index;
  model, index, corpus, or query distribution changes require re-evaluation. These observed
  results are a limited experiment, not broad retrieval-quality evidence. Claim groundedness is
  unmeasured until a reviewer completes the separate `hybrid-rag-groundedness-v1` draft and
  supplies an answer-hash-bound review file; citation existence alone is not a support judgment.
  The groundedness protocol records claim support, unsupported claims, citation correctness,
  evidence-to-claim relevance and abstention behavior. Its review input records an answer hash,
  reports citations outside the retrieved-source set as invalid, and counts a support citation only
  when the cited source is also a human-adjudicated support source. Reviewer independence and
  adjudication quality remain external requirements. Neither RAG protocol establishes detection
  performance.
  Local inference is not a guarantee of privacy if the operator exposes Ollama to an untrusted
  network.
