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
│  - Enforce upload size limits                │
│  - Reject unauthenticated requests           │
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
│  - Restricted network egress                 │
│  - CPU, memory, and timeout bounds           │
└──────────────────────────────────────────────┘
```

---

## 3. Specific Threats & Defensive Controls

### 3.1 Malicious Archives & Decompression Bombs
- **Threat**: Uploading zip/tar archives containing compression bombs (e.g. 42.zip) or millions of nested files designed to exhaust storage, memory, or inodes.
- **Controls**:
  - `MAX_UPLOAD_BYTES` (default 50 MB): Rejection of archives exceeding initial HTTP stream quota.
  - `MAX_FILES_PER_SCAN` (default 10,000 files): Maximum permitted file count during streaming extraction.
  - `MAX_UNCOMPRESSED_BYTES` (default 500 MB): Cumulative uncompressed byte counter aborted immediately if threshold exceeded.

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

### 3.6 Worker Resource Quotas & Process Sandboxing
- **Threat**: Static analysis rules encountering deeply recursive syntax or catastrophic backtracking in regular expressions causing worker denial of service.
- **Controls**:
  - Execution occurs in dedicated sub-processes via `LocalProcessJobRunner` (never in the main FastAPI async loop).
  - Explicit timeouts enforced on job execution.
  - Workers run with restricted system privileges and blocked network egress.

### 3.7 Secret & Credential Leakage
- **Threat**: Sensitive configuration secrets (`SESSION_SECRET`, database connection strings) appearing in scan reports or logs.
- **Controls**:
  - In production mode, `SESSION_SECRET` must be at least 32 characters and cannot use default placeholders.
  - All database queries and logging scrub sensitive variables.

