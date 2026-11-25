# Kubernetes multi-replica deployment bundle

This bundle is a provider-neutral starting point for the PostgreSQL-leased scan architecture.
It is **not a production approval or a provider-tested deployment**. It keeps the API Service
private (`ClusterIP`) and does not create an internet-facing Ingress. The selected cloud platform
must provide private networking, TLS termination, secret delivery, PostgreSQL, S3-compatible object
storage, identity, monitoring, backup, and restore.

## Included resources

- `config/`: the `iasa` namespace, a non-secret application ConfigMap, and API service account.
- `runtime/`: two API replicas, one scan worker loop per replica, a private Service, and a Pod
  Disruption Budget. The rolling update keeps both replicas available where cluster capacity allows.
- `migration/job.yaml`: a separate one-shot migration Job. It is intentionally excluded from the
  runtime Kustomize bundle so migrations are never started once per replica.

The API uses one Uvicorn process per pod. Each replica starts one bounded scan worker loop; each
loop uses the existing isolated child-process runner. The shared PostgreSQL queue uses leases and
fencing tokens, and all upload artifacts use the configured shared S3-compatible bucket. Local
artifact storage is rejected by production settings. Local AI starts disabled in this template.

## Required operator inputs

Before applying anything, provide:

1. An immutable API image reference in the runtime Kustomize image configuration and the migration
   Kustomize image configuration.
2. An externally managed Kubernetes Secret named `iasa-api-secrets`, with `DATABASE_URL`,
   `SESSION_SECRET`, and `API_ACCESS_TOKEN` keys. `API_CLIENT_TOKENS` is optional. Do not put
   credentials in this repository or a ConfigMap.
3. A secret-manager or workload-identity mechanism for object storage. The AWS SDK credential chain
   can use the selected platform's workload identity; alternatively, the optional Secret
   `iasa-object-storage-credentials` can provide `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and
   `AWS_SESSION_TOKEN`. Grant only the required object operations under the configured prefix.
4. A private PostgreSQL endpoint and a private S3-compatible bucket with encryption, public access
   blocked, backups/retention, and a lifecycle policy for orphaned uploads.
5. The real browser origin in `CORS_ORIGINS` and the bucket and region in `config/configmap.yaml`.
   The checked-in `.invalid` origin and empty bucket are deliberate placeholders; readiness will not
   make an incorrectly configured deployment usable.
6. Provider-specific network policy/firewall rules that allow browser gateway traffic to the API,
   and API egress only to DNS, PostgreSQL, object storage, and any explicitly approved private AI
   endpoint. Keep the database and object store off public ingress.

The application currently uses fixed PostgreSQL pool defaults. Budget up to 15 SQLAlchemy
connections per API process plus migration/operations connections until pool sizing is made
configurable and measured. Size database capacity for all replicas and worker activity.

## Image build and local validation

Build from the reviewed source tree and use the resulting digest when publishing through the
organization's approved private registry:

```bash
docker build -t iasa-api:multi-replica-candidate .
docker image inspect --format '{{.Id}}' iasa-api:multi-replica-candidate
kubectl kustomize deploy/kubernetes/config
kubectl kustomize deploy/kubernetes/runtime
kubectl kustomize deploy/kubernetes/migration
```

The image tag above is local-only. Do not deploy a mutable tag: publish to the approved private
registry, record the image digest, and set the same immutable image in
`runtime/kustomization.yaml` and `migration/kustomization.yaml` before rollout.

## First deployment sequence

1. Review and fill the placeholders; have the platform secret manager create `iasa-api-secrets`.
2. Apply configuration only: `kubectl apply -k deploy/kubernetes/config`.
3. Rename the migration Job with a unique release identifier and set its immutable image.
4. Apply that Job once. Wait for `Complete`, then inspect its logs and verify one Alembic head and
   the expected revision `2af81c6e9b40` using a read-only database connection.
5. Apply `deploy/kubernetes/runtime` with the same immutable image digest.
6. Verify two ready pods, `/health/live`, `/health/ready`, authenticated scan creation, completion,
   findings/report retrieval, tenant isolation, and shared quota behavior through the private
   gateway.

Do not copy a production database to a test cluster or run a migration against the wrong context.
Confirm cluster, namespace, database identity, and backup/restore evidence before the migration.

## Subsequent upgrade sequence

The older application startup path marks active scans failed. Before a release that crosses that
behavior boundary, stop accepting uploads and drain or suspend old replicas, then verify no old
workers remain. Back up and verify recovery, run the uniquely named migration Job once, verify its
revision, and only then deploy the new immutable image. Do not run migrations in API startup or in
parallel from each replica. Rollback after the additive migration is not automatic; prefer a tested
forward repair.

## Operational caveats

- Two replicas and one worker loop per replica are initial sample settings, not measured capacity.
  Global/per-client limits apply fleet-wide and must be sized with model, CPU, memory, pool, and
  database constraints.
- The PDB protects one pod during voluntary disruptions; it does not protect against zone failure,
  database failure, object-store failure, or a bad rollout.
- `emptyDir` is scratch only. It is not a source-of-truth for uploads, scans, or reports.
- Add metrics and alerts for queue age/depth, lease expiry/retries, worker capacity, database pool
  saturation, admission reservations, object deletion failures, and rate-limit outcomes.
- This bundle does not configure ingress, DNS, TLS certificates, network policies, workload
  identity annotations, database provisioning, bucket policy, or autoscaling. Those are provider
  and organization decisions that must be reviewed and verified before production.
- The groundedness human review remains a separate release gate. This deployment bundle does not
  change or validate RAG evaluation results.
