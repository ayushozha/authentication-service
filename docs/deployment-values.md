# Deployment Values Template

> This file is intentionally sanitized. Use your secret manager or deployment platform variables for real credentials.

---

## Service Endpoint

| Item | Value |
|------|-------|
| URL | `https://<auth-domain>` |
| Health Check | `GET https://<auth-domain>/healthz` |
| HTTP Port | 8080 (internal) |
| gRPC Port | 9090 (internal) |

## Admin Credentials

| Item | Value |
|------|-------|
| Admin API Key | `<admin-api-key>` |
| Admin Header | `X-Admin-Key: <admin-api-key>` |
| Audit Webhook Signing Secret | `<webhook-signing-secret>` |
| Audit Retention Days | `2555` |

## Infrastructure

| Item | Value |
|------|-------|
| VPS IP | `<vps-ip>` |
| Coolify UI | `https://<coolify-domain>` |
| Coolify App UUID | `<coolify-app-uuid>` |
| Database | `postgres://<db_user>:<db_password>@<db-host>:5432/auth_service` |
| Redis | `redis://<redis_user>:<redis_password>@<redis-host>:6379/0` |
| Redis Key Prefix | `auth:` |
| Docker Network | `coolify` |

## Operations And Observability

| Item | Value |
|------|-------|
| Metrics Endpoint | `GET https://<auth-domain>/metrics` or admin `GET /api/admin/metrics` |
| Audit Streams | `<datadog,splunk,elastic,s3,cloudwatch,gcp,azure,stdout>` |
| Stream Timeout | `AUDIT_STREAM_TIMEOUT=5s` |
| Stream Retries | `AUDIT_STREAM_RETRY_ATTEMPTS=3` |
| RPO Target | `<=15m with PITR/WAL; <=24h logical fallback` |
| RTO Target | `<=60m tested restore` |

### SIEM Values

| Provider | Values |
|---|---|
| Datadog | `DATADOG_API_KEY`, optional `DATADOG_LOGS_URL` |
| Splunk | `SPLUNK_HEC_URL`, `SPLUNK_HEC_TOKEN` |
| Elastic | `ELASTIC_BULK_URL`, `ELASTIC_INDEX`, optional `ELASTIC_API_KEY` |
| S3 | `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AUDIT_S3_BUCKET`, optional `AUDIT_S3_PREFIX` |
| CloudWatch | AWS credentials plus `AUDIT_CLOUDWATCH_LOG_GROUP`, `AUDIT_CLOUDWATCH_LOG_STREAM` |
| Google Cloud Logging | `GCP_PROJECT_ID`, `GCP_ACCESS_TOKEN`, optional `GCP_LOG_ID` |
| Azure Monitor | `AZURE_MONITOR_INGEST_URL`, `AZURE_MONITOR_BEARER_TOKEN` |

## Registered Clients

### Example Client

| Item | Value |
|------|-------|
| Client ID | `<client-id>` |
| API Key | `<client-api-key>` |
| JWT Secret | `<client-jwt-secret>` |
| Slug | `<client-slug>` |
| Allowed Origins | `https://<app-domain>` |
| Status | `active` |
| Registered | `<yyyy-mm-dd>` |

### Example Usage

**Frontend**:
```javascript
const AUTH_BASE_URL = 'https://<auth-domain>';
const AUTH_API_KEY = '<client-api-key>';
```

**Backend**:
```bash
AUTH_JWT_SECRET=<client-jwt-secret>
```

## Registering a New Client

```bash
curl -X POST https://<auth-domain>/api/admin/clients \
  -H "X-Admin-Key: <admin-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Project Name",
    "slug": "project-slug",
    "allowed_origins": ["https://project.com"],
    "webhook_url": ""
  }'
```

## Rotating Credentials

```bash
# Rotate JWT secret
curl -X POST https://<auth-domain>/api/admin/clients/<client-id>/rotate-secret \
  -H "X-Admin-Key: <admin-api-key>"

# Rotate API key
curl -X POST https://<auth-domain>/api/admin/clients/<client-id>/rotate-api-key \
  -H "X-Admin-Key: <admin-api-key>"
```
