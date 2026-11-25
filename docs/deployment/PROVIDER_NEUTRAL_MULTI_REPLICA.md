# Provider-Neutral Multi-Replica Deployment Baseline

## Status

This document describes the architecture implemented in the application and points to the
Kubernetes/Kustomize deployment bundle at `deploy/kubernetes/`. It is a deployment baseline, not
evidence that a cloud environment has been provisioned, load-tested, security-reviewed, or approved
for production. The repository Compose file remains local-development-only.

## Topology

```text
Browser / reverse proxy
        |
        +---- API replica 1 ---- PostgreSQL (shared coordination and scan state)
        |          |             S3-compatible object storage (shared upload artifacts)
        |          +-- bounded scan worker loops and isolated child processes
        |
        +---- API replica N ---- PostgreSQL and the same object bucket
                   +-- bounded scan worker loops and isolated child processes
```

Each API replica can claim durable jobs. PostgreSQL serializes global upload/scan admission and
rate-limit buckets; `FOR UPDATE SKIP LOCKED` distributes queued scans. A worker receives a
database-time lease and unique fencing token. Heartbeats extend that lease. Results are committed
only while the same lease token remains current, so a delayed worker cannot overwrite a later
attempt. Expired jobs are retried up to `SCAN_JOB_MAX_ATTEMPTS`; startup does not fail all active
scans. Upload objects use generated scan UUID keys and are deleted after terminal outcomes. A crash
between object upload and scan-row insertion can leave an orphan; configure a bucket lifecycle rule
to remove unreferenced objects after a retention period that exceeds the maximum scan duration.

Run one Uvicorn process per container initially. Set `SCAN_WORKER_COUNT` to a bounded number below
the container CPU and memory budget; child scans remain isolated by the existing process runner.
Replica count and worker count multiply total concurrency, so size the shared scan quotas and
PostgreSQL connection capacity for the aggregate fleet. Do not use local filesystem artifact
storage for multi-replica deployment.

## Required production configuration

Set `ENVIRONMENT=production`, an explicit PostgreSQL `DATABASE_URL`, a strong `SESSION_SECRET`, a
strong `API_ACCESS_TOKEN`, and `LOCAL_DEV_AUTH_BYPASS=false`. Use the same authentication identity
configuration across replicas. Inject credentials through the platform secret manager or workload
identity; never bake credentials into an image or checked-in files.

Configure `ARTIFACT_STORAGE_BACKEND=s3`, `ARTIFACT_STORAGE_BUCKET`, `ARTIFACT_STORAGE_PREFIX`, and
`ARTIFACT_STORAGE_REGION` as applicable. The AWS SDK credential chain is used; do not put access
keys in application settings. For S3-compatible services, set a credential-free HTTPS
`ARTIFACT_STORAGE_ENDPOINT_URL`. Grant the service identity only the required object get/put/delete
permissions for the configured prefix. Verify encryption, versioning, retention, public-access
blocking, and lifecycle policies with the chosen provider.

Set `SCAN_WORKERS_ENABLED=true`, `SCAN_WORKER_COUNT`, `SCAN_TIMEOUT_SECONDS`,
`SCAN_LEASE_GRACE_SECONDS`, `SCAN_JOB_MAX_ATTEMPTS`, `UPLOAD_RESERVATION_TTL_SECONDS`, and the
global/per-client upload and scan limits deliberately. The reservation TTL must exceed the maximum
bounded upload read time. Keep inbound API traffic behind TLS termination and a trusted proxy;
configure exact allowed frontend origins. Keep PostgreSQL and object storage private.

The local Ollama integration is optional and is not part of the deterministic scan path. If enabled
in a hosted deployment, its endpoint must be private, authenticated or network-restricted, and
reachable from every API replica that serves assistant requests. The bundled RAG index must be
shipped identically and mounted/read as immutable across replicas; do not rebuild it at startup.
Disable assistant generation if those conditions are not met. Scan upload content is not sent to
hosted AI services by this architecture.

## Database migration and rollout

1. Build and inspect the exact release image and dependency lock.
2. Back up PostgreSQL and verify restore procedures in a separate environment.
3. Drain and stop all replicas running the prior startup-recovery implementation. Do not overlap old
   processes with the new job lifecycle: the old version marks every queued/running scan failed at
   startup.
4. Run `uv run alembic upgrade head` once as a deployment migration job using the production
   database identity. Do not run migrations independently from each replica.
5. Verify one Alembic head and the new coordination tables, then deploy the new API image.
6. Verify `/health/live` and `/health/ready` separately. Readiness checks PostgreSQL and the
   expected migration revision; liveness only checks the process.
7. Verify two replicas claim separate scans, lease expiry/retry and stale-worker fencing, shared
   admission/rate limits, tenant isolation, report reads, and object cleanup before accepting user
   traffic.

The new migration is additive. Rolling back application code after it is applied is not an
automatic rollback plan; the prior application behavior is unsafe for active jobs. Prefer forward
repair and test any rollback procedure against a restored database first.

## Release gates still required

- Provider-specific private networking, TLS, identity, secret rotation, bucket policy, backup and
  restore reviews.
- Load and concurrency tests across multiple independent API processes against PostgreSQL and an
  S3-compatible service.
- Fault-injection tests for worker termination before/after result commit, object-store outages,
  database failover, lease expiry, deployment shutdown, and orphan cleanup.
- Operational metrics and alerts for queue age/depth, expired leases, retries, worker capacity,
  database pool saturation, upload reservations, object cleanup failures, and rate-limit outcomes.
- A reviewed retention/deletion policy for uploaded source archives and OpenAPI specifications.
- Repeatable image build, migration, readiness, authenticated scan/report, tenant-isolation, and
  local-AI behavior checks in the actual target environment.
- Completion of the independent RAG groundedness review. Model citation validation is not a human
  groundedness result.

Until these checks are complete in the selected hosting environment, this architecture is
**implementation-ready for isolated verification only**, not production-approved.

The Kubernetes bundle is a concrete, provider-neutral deployment scaffold. Its database, bucket,
secrets, ingress, network policy, workload identity, image registry, and runtime behavior must be
configured and verified in the chosen environment before deployment approval.
