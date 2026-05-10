# Multi-Region Deployment And JWKS Edge Cache

AuthService is safest to operate as a stateless service tier in multiple regions with one authoritative PostgreSQL writer. Redis is optional but should be regional and treated as ephemeral cache/rate-limit state.

## Recommended Topology

| Layer | Recommendation |
|---|---|
| HTTP/gRPC service | Run at least two instances per region behind a regional load balancer. |
| PostgreSQL | Use managed PITR, cross-zone HA, and cross-region read replica or warm standby. Keep one writer unless you have tested conflict-free multi-writer semantics. |
| Redis | Use regional Redis for rate limits, OAuth/SSO state, passkey ceremonies, and short-lived challenges. Do not replicate Redis as the source of truth. |
| Secrets | Replicate through the cloud secret manager, not through environment files. Rotate admin, webhook, OAuth, SSO, SCIM, and JWT signing material with audit evidence. |
| Audit streams | Send to at least one durable sink outside the primary region, such as S3 or CloudWatch/Google/Azure regional logging. |

## Region Modes

| Mode | Use when | Notes |
|---|---|---|
| Active/passive | Most production teams | Primary region serves writes; passive region has warm service capacity and database replica. Promote database on failover. |
| Active/active read-mostly | Global API latency matters | Route login, refresh, signup, SCIM, and admin writes to the writer region. Allow JWKS, health, docs, and token validation helpers at the edge. |
| Active/active write | Only after a formal design review | Requires database conflict strategy, globally consistent sessions, monotonic audit chain ordering, and tested replay behavior. |

## Failover Runbook

1. Freeze deployments and announce the incident channel.
2. Confirm primary-region health, database replication lag, Redis availability, and audit-stream delivery.
3. If the database writer is unavailable, promote the standby according to the database provider runbook.
4. Point `DATABASE_URL`, `BASE_URL`, OAuth callback URLs, and SSO ACS/metadata URLs at the recovery region.
5. Restart AuthService and validate `/healthz`, `/metrics`, `/.well-known/jwks.json`, login, refresh, audit export, and SSO/SCIM paths.
6. Record failover start/end time, estimated RPO from replica lag, observed RTO, and any customer impact.

## JWKS Edge Cache

`/.well-known/jwks.json` returns `Cache-Control: public, max-age=300, stale-while-revalidate=60`. Edge caches may cache issuer-level JWKS or tenant-scoped JWKS with `?client_id=<client_id>`.

Rules:

1. Cache JWKS for no more than 5 minutes at CDN/edge layers.
2. Preserve query strings so tenant-scoped `client_id` responses do not mix.
3. On signing-key rotation, wait at least one access-token TTL plus JWKS cache TTL before disabling the old key.
4. If a key compromise is suspected, purge CDN cache immediately, rotate the active signing key, revoke sessions for affected clients, and export/verify audit evidence.
5. Downstream services should cache keys with background refresh and retry validation once after a key miss.

## Smoke Tests

Run these after regional deploys and failovers:

```bash
curl -fsS "$BASE_URL/healthz"
curl -fsS "$BASE_URL/.well-known/jwks.json?client_id=$CLIENT_ID" >/tmp/jwks.json
curl -fsS "$BASE_URL/metrics" | grep authservice_http_requests_total
curl -fsS "$BASE_URL/api/admin/audit-events/chain/verify?client_id=$CLIENT_ID" \
  -H "X-Admin-Key: $ADMIN_API_KEY"
```

Then complete one synthetic signup/login/refresh/logout flow and one SCIM or SSO smoke path if those features are enabled for the tenant.
