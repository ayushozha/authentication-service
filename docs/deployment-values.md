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
