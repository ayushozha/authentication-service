# Deployment Values & Credentials

> **IMPORTANT:** This file contains sensitive credentials. It is tracked in a private repo.
> Never commit this to a public repository.

---

## Service Endpoint

| Item | Value |
|------|-------|
| URL | `https://authservice.ayushojha.com` |
| Health Check | `GET https://authservice.ayushojha.com/healthz` |
| HTTP Port | 8080 (internal) |
| gRPC Port | 9090 (internal) |

## Admin Credentials

| Item | Value |
|------|-------|
| Admin API Key | `7d775744acb33aa1df87902f6ab64f737183de0c727ce08dbca1821515cef40a` |
| Admin Header | `X-Admin-Key: <admin_api_key>` |

## Infrastructure

| Item | Value |
|------|-------|
| VPS IP | `72.62.82.57` |
| Coolify UI | `https://coolify.ayushojha.com` |
| Coolify App UUID | `y0sgo0c88wsw4c408ogog0co` |
| Database | `postgres://admin:i87RfJUBx5HZJuykZt4v9u3zaq10wAqV@projects-db:5432/auth_service` |
| Redis | `redis://tapdue_user:BhUK71tUxASNZqOoQGMGJoQjLjhuv5WW@projects-redis:6379/0` |
| Redis Key Prefix | `auth:` |
| Docker Network | `coolify` |

## Registered Clients

### TapDue

| Item | Value |
|------|-------|
| Client ID | `fe24972b-68fd-4670-904c-55496033d079` |
| API Key | `77f61b0b47df7c7ac2a0bfc6366f8f677b3151c3605859bfd34e0a9c5823855b` |
| JWT Secret | `f41deb9c14768611d607cb3bbca38960dbe378cdd1b0a517627971f7c0b79f2f` |
| Slug | `tapdue` |
| Allowed Origins | `https://tapdue.com`, `https://www.tapdue.com` |
| Status | `active` |
| Registered | `2026-02-01` |

### How TapDue uses these values:

**Frontend** (browser JS):
```javascript
const AUTH_BASE_URL = 'https://authservice.ayushojha.com';
const AUTH_API_KEY = '77f61b0b47df7c7ac2a0bfc6366f8f677b3151c3605859bfd34e0a9c5823855b';

// Login example
fetch(`${AUTH_BASE_URL}/api/auth/login`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': AUTH_API_KEY,
  },
  credentials: 'include',
  body: JSON.stringify({ email, password }),
});
```

**Backend** (Go env var):
```bash
AUTH_JWT_SECRET=f41deb9c14768611d607cb3bbca38960dbe378cdd1b0a517627971f7c0b79f2f
```

---

## Registering a New Client

```bash
curl -X POST https://authservice.ayushojha.com/api/admin/clients \
  -H "X-Admin-Key: 7d775744acb33aa1df87902f6ab64f737183de0c727ce08dbca1821515cef40a" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Project Name",
    "slug": "project-slug",
    "allowed_origins": ["https://project.com"],
    "webhook_url": ""
  }'
```

**Save the response** -- it contains `api_key` and `jwt_secret` which are only shown once at creation time.

## Rotating Credentials

**Rotate JWT Secret** (invalidates all existing tokens for this client):
```bash
curl -X POST https://authservice.ayushojha.com/api/admin/clients/<client-id>/rotate-jwt \
  -H "X-Admin-Key: 7d775744acb33aa1df87902f6ab64f737183de0c727ce08dbca1821515cef40a"
```

**Rotate API Key** (frontend must update to new key):
```bash
curl -X POST https://authservice.ayushojha.com/api/admin/clients/<client-id>/rotate-key \
  -H "X-Admin-Key: 7d775744acb33aa1df87902f6ab64f737183de0c727ce08dbca1821515cef40a"
```
