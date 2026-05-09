# AuthService Operations Runbook

This runbook captures the minimum operational controls expected for a self-hosted authentication service. Adapt names, retention windows, and storage locations to your infrastructure.

## Evidence Checklist

| Control | Evidence |
|---|---|
| Service availability | `GET /healthz`, uptime checks, deployment logs |
| Database recoverability | Last successful `pg_dump`, restore drill timestamp, RPO/RTO notes |
| Audit evidence | `GET /api/admin/audit-events/export?format=csv|jsonl`, signed webhook delivery logs |
| Secret rotation | Admin key, client API key, JWT signing key, service-account key, SCIM token, webhook signing secret rotation records |
| Access review | Client list, service accounts, SSO connections, SCIM directories, organization admins |

## Backup Runbook

1. Run PostgreSQL backups at least daily for production and before every migration.
2. Store backups in an encrypted bucket or volume outside the primary host.
3. Retain at least 7 daily, 4 weekly, and 3 monthly restore points unless your policy requires more.
4. Include `clients`, `users`, `sessions`, `oauth_accounts`, `webauthn_credentials`, `verification_tokens`, `login_audit_log`, organization, M2M, SSO, SCIM, and recovery-code tables.
5. Record backup job status in your monitoring system and alert on the first missed run.

Example logical backup:

```bash
pg_dump "$DATABASE_URL" --format=custom --file "authservice-$(date +%Y%m%d%H%M%S).dump"
```

The repository also includes `scripts/backup-postgres.sh` for this workflow.

## Restore Drill

1. Provision a clean PostgreSQL database in an isolated environment.
2. Restore the most recent backup:

```bash
pg_restore --clean --if-exists --dbname "$RESTORE_DATABASE_URL" authservice-YYYYMMDDHHMMSS.dump
```

The repository also includes `scripts/restore-postgres.sh`.

3. Start AuthService against the restored database with non-production `BASE_URL`, `ADMIN_API_KEY`, and email/OAuth secrets disabled.
4. Validate `/healthz`, `GET /api/admin/clients`, `GET /api/admin/audit-events`, and one token validation path.
5. Record restore duration, data timestamp, failed checks, and follow-up fixes.

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
2. Export relevant audit evidence before retention jobs or manual cleanup.
3. Rotate affected client API keys, JWT signing keys, service-account keys, SCIM tokens, and webhook signing secret.
4. Revoke user sessions with password reset, password change, or `DELETE /api/auth/sessions` for impacted users.
5. Disable compromised SSO/SCIM/service-account connections.
6. Document timeline, affected tenants/users, containment actions, and follow-up controls.

## Audit Retention

The service exposes query and export APIs but does not enforce deletion policy by default. Define a retention job for `login_audit_log` after evidence export and legal-hold checks. Keep retention long enough for SOC 2, customer contracts, and incident investigations.
