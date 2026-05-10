# AuthService Operations Runbook

This runbook captures the minimum operational controls expected for a self-hosted authentication service. Adapt names, retention windows, and storage locations to your infrastructure.

## Evidence Checklist

| Control | Evidence |
|---|---|
| Service availability | `GET /healthz`, uptime checks, deployment logs |
| Service metrics | `GET /metrics` or `GET /api/admin/metrics`, alert history |
| Database recoverability | Last successful `pg_dump`, restore drill timestamp, tested RPO/RTO notes |
| Audit evidence | `GET /api/admin/audit-events/export?format=csv|jsonl`, chain verification, legal-hold records, signed webhook delivery logs |
| Secret rotation | Admin key, client API key, JWT signing key, service-account key, SCIM token, webhook signing secret rotation records |
| Access review | Client list, service accounts, SSO connections, SCIM directories, organization admins |

## Backup Runbook

Target: production backup jobs must meet **RPO <= 15 minutes** when WAL archiving or managed point-in-time recovery is enabled, and **RPO <= 24 hours** for the fallback logical dump path. The tested restore target is **RTO <= 60 minutes** for databases up to the current production size class; record any larger-data exception beside the drill result.

1. Run PostgreSQL backups continuously with WAL/PITR where available, at least daily logical `pg_dump` for portability, and before every migration.
2. Store backups in an encrypted bucket or volume outside the primary host.
3. Retain at least 7 daily, 4 weekly, and 3 monthly restore points unless your policy requires more.
4. Include `clients`, `users`, `sessions`, `oauth_accounts`, `webauthn_credentials`, `verification_tokens`, `login_audit_log`, organization, M2M, SSO, SCIM, and recovery-code tables.
5. Record backup job status in your monitoring system and alert on the first missed run or WAL lag over 15 minutes.

Example logical backup:

```bash
pg_dump "$DATABASE_URL" --format=custom --file "authservice-$(date +%Y%m%d%H%M%S).dump"
```

The repository also includes `scripts/backup-postgres.sh` for this workflow.

## Restore Drill

Run a restore drill at least quarterly and after material schema changes. The drill passes only when both RPO and RTO are recorded with the restored database timestamp and wall-clock recovery duration.

1. Provision a clean PostgreSQL database in an isolated environment.
2. Restore the most recent backup:

```bash
pg_restore --clean --if-exists --dbname "$RESTORE_DATABASE_URL" authservice-YYYYMMDDHHMMSS.dump
```

The repository also includes `scripts/restore-postgres.sh`.

3. Start AuthService against the restored database with non-production `BASE_URL`, `ADMIN_API_KEY`, and email/OAuth secrets disabled.
4. Validate `/healthz`, `GET /api/admin/clients`, `GET /api/admin/audit-events`, `GET /api/admin/audit-events/chain/verify`, `GET /.well-known/jwks.json`, and one login plus refresh-token rotation path.
5. Record restore duration, backup/WAL timestamp, estimated data loss, failed checks, and follow-up fixes.

## Migration Runbook

1. Read every new SQL migration before deploy.
2. Take a database backup.
3. Deploy one AuthService instance first and let startup migrations run.
4. Watch migration logs and `/healthz`.
5. Run smoke tests: signup/login in a test client, refresh rotation, JWKS, audit query, and SSO/SCIM endpoints if enabled.
6. Roll forward with a corrective migration when possible. If a restore is required, stop writers first and follow the restore drill.

## Import/Export Runbook

Use CSV/NDJSON audit exports for evidence requests:

```bash
curl "$BASE_URL/api/admin/audit-events/export?client_id=$CLIENT_ID&format=jsonl&limit=500" \
  -H "X-Admin-Key: $ADMIN_API_KEY" \
  -o authservice-audit-events.jsonl
```

The repository also includes `scripts/export-audit.sh`.

Each CSV/NDJSON export includes retention, legal-hold, `previous_hash`, `event_hash`, `hash_algorithm`, and actor/target fields. Verify a tenant chain before sharing evidence:

```bash
curl "$BASE_URL/api/admin/audit-events/chain/verify?client_id=$CLIENT_ID&limit=10000" \
  -H "X-Admin-Key: $ADMIN_API_KEY"
```

For tenant migration, export users, organizations, memberships, SSO, SCIM, and service-account metadata from PostgreSQL using read-only credentials. Do not export raw refresh tokens, API keys, recovery codes, or service-account secrets; rotate them in the destination environment.

## Webhook Verification

When `WEBHOOK_SIGNING_SECRET` is set, AuthService sends `audit.event` deliveries to each client's `webhook_url`.

Verify `X-AuthService-Signature` by computing:

```text
HMAC-SHA256(WEBHOOK_SIGNING_SECRET, X-AuthService-Timestamp + "." + raw_request_body)
```

Compare the result to the `v1=<hex>` signature header with a constant-time comparison. Reject stale timestamps according to your replay policy.

## Incident Runbook

1. Triage with `GET /api/admin/audit-events?client_id=<id>&limit=500`.
2. Export relevant audit evidence and verify the chain before retention jobs or manual cleanup.
3. Rotate affected client API keys, JWT signing keys, service-account keys, SCIM tokens, and webhook signing secret.
4. Revoke user sessions with password reset, password change, or `DELETE /api/auth/sessions` for impacted users.
5. Disable compromised SSO/SCIM/service-account connections.
6. Document timeline, affected tenants/users, containment actions, and follow-up controls.

## Audit Retention

AuthService assigns `retention_until` to new audit events using `AUDIT_RETENTION_DAYS` (default 2555 days, roughly seven years). Legal holds are mutable operational metadata and do not invalidate the tamper-evident event hash.

Enable legal hold for specific events:

```bash
curl -X POST "$BASE_URL/api/admin/audit-events/legal-hold" \
  -H "X-Admin-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"event_ids":[123,124],"legal_hold":true,"reason":"litigation hold CASE-2026-001"}'
```

Dry-run and execute retention purge:

```bash
curl -X POST "$BASE_URL/api/admin/audit-events/retention/purge" \
  -H "X-Admin-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"dry_run":true}'
```

Only purge after exports and chain verification are complete. Purge skips `legal_hold=true` rows.

## Metrics And Alerts

Scrape `GET /metrics` from a trusted network path or `GET /api/admin/metrics` with admin authentication. Required alert inputs are:

| Metric | Purpose |
|---|---|
| `authservice_login_total{result}` | Login success/failure rate |
| `authservice_mfa_challenge_total{method}` | MFA challenge rate |
| `authservice_sso_errors_total{stage,reason}` | SSO setup/callback failures |
| `authservice_scim_sync_lag_seconds{client_id,directory_id}` | IdP-to-AuthService SCIM lag |
| `authservice_webhook_delivery_total{result}` | Audit webhook delivery health |
| `authservice_token_refresh_reuse_total{client_id}` | Refresh-token replay/reuse detections |
| `authservice_http_request_latency_seconds_sum/count` | API latency by method/path/status |
| `authservice_audit_stream_delivery_total{provider,result}` | SIEM/log stream delivery health |

Minimum production alerts: login failure spike, any token refresh reuse, webhook or audit-stream failure rate above 1% for 10 minutes, SCIM lag above the customer SLA, p95 API latency above SLO, and no metrics scrape for 5 minutes.

## SIEM And Log Streams

Set `AUDIT_STREAMS` to a comma-separated list of `datadog,splunk,elastic,s3,cloudwatch,gcp,azure,stdout`. Streams receive the same audit envelope stored in PostgreSQL, including actor/target metadata and hash-chain fields.

Provider variables:

| Provider | Required variables |
|---|---|
| Datadog | `DATADOG_API_KEY`, optional `DATADOG_LOGS_URL` |
| Splunk HEC | `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN` |
| Elastic | `ELASTIC_BULK_URL`, `ELASTIC_INDEX`, optional `ELASTIC_API_KEY` |
| S3 | `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AUDIT_S3_BUCKET`, optional `AUDIT_S3_PREFIX` |
| CloudWatch Logs | AWS credentials plus `AUDIT_CLOUDWATCH_LOG_GROUP`, `AUDIT_CLOUDWATCH_LOG_STREAM` |
| Google Cloud Logging | `GCP_PROJECT_ID`, `GCP_ACCESS_TOKEN`, optional `GCP_LOG_ID`, `GCP_LOGGING_URL` |
| Azure Monitor | `AZURE_MONITOR_INGEST_URL`, `AZURE_MONITOR_BEARER_TOKEN` |

Use `AUDIT_STREAM_TIMEOUT` and `AUDIT_STREAM_RETRY_ATTEMPTS` to bound provider latency. Alert on `authservice_audit_stream_delivery_total{result="failure"}`.

## Deployment Guidance

Multi-region and JWKS edge-cache guidance lives in `docs/multi-region-deployment.md`. Compliance readiness, subprocessors, and customer evidence mapping live in `docs/compliance-readiness.md`.
