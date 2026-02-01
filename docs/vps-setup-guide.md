# VPS Setup Guide: Authentication Microservice

This guide covers deploying the authentication microservice on a VPS using Coolify + Traefik, and integrating it with any client project. Follow these steps in order.

---

## Architecture Overview

```
Internet
  │
  ├── project-a.com ───────► Traefik ──► project-a-api
  │                                         │  validates JWTs locally
  │                                         │  via pkg/jwtvalidator
  │
  ├── project-b.com ───────► Traefik ──► project-b-api
  │                                         │  validates JWTs locally
  │
  └── authservice.ayushojha.com ──► Traefik ──► auth-service (port 8080/9090)
                                                  │
                                      ┌───────────┼───────────┐
                                      │           │           │
                                  PostgreSQL    Redis     Resend
                                (auth_service)  (auth:)   (email)
```

**Key Points:**
- Auth service runs at `authservice.ayushojha.com` as a shared microservice for all projects
- Any project's frontend sends auth requests to `authservice.ayushojha.com` with its unique `X-API-Key`
- Each project's backend validates JWTs locally using `pkg/jwtvalidator` -- no network call needed
- All services share the same PostgreSQL instance (different databases) and Redis instance (different key prefixes)
- Each project is registered as a "client" via the admin API, with fully isolated user namespaces

---

## Step 1: Create the `auth_service` Database

SSH into the VPS and create the database:

```bash
ssh ayush@72.62.82.57

# Create auth_service database
PGPASSWORD='i87RfJUBx5HZJuykZt4v9u3zaq10wAqV' psql -h 127.0.0.1 -p 5433 -U admin -d postgres -c "CREATE DATABASE auth_service;"
```

Verify it was created:

```bash
PGPASSWORD='i87RfJUBx5HZJuykZt4v9u3zaq10wAqV' psql -h 127.0.0.1 -p 5433 -U admin -d postgres -c "\l" | grep auth_service
```

---

## Step 2: Create Redis ACL User for Auth Service

The auth service needs its own Redis ACL user with the `auth:` key prefix. SSH into the VPS and configure Redis:

```bash
ssh ayush@72.62.82.57

# Connect to Redis as admin
redis-cli -p 6379 --user admin --pass P0UnWC3CC7fsxV0Dsz2CgyDra19aL5iK

# Inside redis-cli, create the auth user:
ACL SETUSER auth_user on >AuthService2026SecureKey ~auth:* +@all
ACL SAVE

# Verify
ACL LIST
```

**Auth Redis credentials:**
- Username: `auth_user`
- Password: `AuthService2026SecureKey` (change this to a strong random password)
- Key prefix: `auth:`

> **Note:** The current docker-compose.yml uses the `tapdue_user` Redis credentials. Update it to use the dedicated `auth_user` once created, or keep using `tapdue_user` since both share the same Redis instance and the key prefix `auth:` prevents collisions.

---

## Step 3: Deploy the Auth Service via Coolify

### Option A: Deploy from GitHub (Recommended)

1. In Coolify, create a new service
2. Source: GitHub → `https://github.com/Ayush10/authentication-service.git`
3. Branch: `main`
4. Build: Dockerfile (auto-detected)
5. Network: `coolify` (same as TapDue)

### Option B: Manual Docker Compose

Copy the repo to the VPS and use the existing `docker-compose.yml`:

```bash
# On VPS
cd /opt/apps
git clone https://github.com/Ayush10/authentication-service.git
cd authentication-service
```

### Environment Variables to Set in Coolify

```bash
# Required
DATABASE_URL=postgres://admin:i87RfJUBx5HZJuykZt4v9u3zaq10wAqV@projects-db:5432/auth_service?sslmode=disable
REDIS_URL=redis://tapdue_user:BhUK71tUxASNZqOoQGMGJoQjLjhuv5WW@projects-redis:6379/0
ADMIN_API_KEY=<generate-a-strong-random-key>
BASE_URL=https://authservice.ayushojha.com

# JWT (defaults are fine)
JWT_ACCESS_TTL=15m
JWT_REFRESH_TTL=168h
BCRYPT_COST=12

# Email
RESEND_API_KEY=<your-resend-api-key>
EMAIL_FROM=Auth Service <noreply@ayushojha.com>

# OAuth (same credentials as TapDue, but with authservice.ayushojha.com callbacks)
GOOGLE_CLIENT_ID=<same-as-tapdue>
GOOGLE_CLIENT_SECRET=<same-as-tapdue>
GOOGLE_REDIRECT_URL=https://authservice.ayushojha.com/api/auth/oauth/google/callback

GITHUB_CLIENT_ID=<same-as-tapdue>
GITHUB_CLIENT_SECRET=<same-as-tapdue>
GITHUB_REDIRECT_URL=https://authservice.ayushojha.com/api/auth/oauth/github/callback

MICROSOFT_CLIENT_ID=<same-as-tapdue>
MICROSOFT_CLIENT_SECRET=<same-as-tapdue>
MICROSOFT_TENANT_ID=common
MICROSOFT_REDIRECT_URL=https://authservice.ayushojha.com/api/auth/oauth/microsoft/callback

APPLE_CLIENT_ID=<same-as-tapdue>
APPLE_REDIRECT_URL=https://authservice.ayushojha.com/api/auth/oauth/apple/callback

# WebAuthn
WEBAUTHN_RP_ID=tapdue.com
WEBAUTHN_RP_ORIGIN=https://tapdue.com
WEBAUTHN_DISPLAY_NAME=TapDue

# CORS
ALLOW_ORIGIN=https://tapdue.com

# Frontend
SERVE_FRONTEND=true
PUBLIC_DIR=/app/public
```

> **Important:** Generate `ADMIN_API_KEY` with: `openssl rand -hex 32`

### OAuth Redirect URLs

You must update your OAuth provider configurations to add the new callback URLs:

| Provider  | New Callback URL |
|-----------|-----------------|
| Google    | `https://authservice.ayushojha.com/api/auth/oauth/google/callback` |
| GitHub    | `https://authservice.ayushojha.com/api/auth/oauth/github/callback` |
| Microsoft | `https://authservice.ayushojha.com/api/auth/oauth/microsoft/callback` |
| Apple     | `https://authservice.ayushojha.com/api/auth/oauth/apple/callback` |

---

## Step 4: Verify Auth Service is Running

```bash
# Health check
curl https://authservice.ayushojha.com/healthz
# Expected: {"status":"ok"}
```

---

## Step 5: Register a Project as a Client

Once the auth service is running, register any project as a client tenant. Example:

```bash
curl -X POST https://authservice.ayushojha.com/api/admin/clients \
  -H "X-Admin-Key: <your-ADMIN_API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Project",
    "slug": "my-project",
    "allowed_origins": ["https://myproject.com", "https://www.myproject.com"],
    "webhook_url": ""
  }'
```

**SAVE THE RESPONSE.** It contains:
- `client.id` -- The client UUID
- `client.jwt_secret` -- The per-client JWT signing secret (needed by TapDue backend)
- `api_key` -- The raw API key (only shown once, needed by TapDue frontend)

Example response:
```json
{
  "client": {
    "id": "abc123-...",
    "name": "TapDue",
    "slug": "tapdue",
    "jwt_secret": "a1b2c3d4e5...",
    "allowed_origins": ["https://tapdue.com", "https://www.tapdue.com"],
    "status": "active",
    "created_at": "2026-02-01T..."
  },
  "api_key": "raw-api-key-save-this-now"
}
```

---

## Step 6: Refactor TapDue Backend

### What to Remove from TapDue

Delete these auth-related files from `cmd/server/`:

```
# Auth handlers (all replaced by auth service)
auth_handlers.go
auth_jwt.go
auth_verify.go
auth_magic_link.go
auth_otp.go
auth_oauth.go
auth_passkey.go
auth_password.go
auth_email.go

# Auth data stores (data now in auth_service database)
user_store.go
session_store.go
token_store.go
oauth_store.go
webauthn_store.go
audit_store.go

# Auth infrastructure
rate_limit.go

# Auth migration files
migrations/002_create_users.sql
migrations/003_create_sessions.sql
migrations/004_create_oauth_accounts.sql
migrations/005_create_webauthn_credentials.sql
migrations/006_create_verification_tokens.sql
migrations/007_create_login_audit_log.sql (if it exists)
```

**Keep these files** (non-auth, TapDue business logic):
```
main.go           (will be modified)
config.go         (will be simplified)
database.go       (keep for TapDue's own tables)
redis.go          (keep for TapDue's own Redis usage)
helpers.go        (keep writeJSON, CORS helpers)
middleware.go     (keep secureHeaders, logRequests)
admin_handlers.go (keep admin dashboard)
waitlist_handlers.go
waitlist_store.go
```

### What to Add to TapDue

**1. Add `pkg/jwtvalidator` dependency to TapDue's `go.mod`:**

```bash
cd /path/to/tapdue/backend/go
go get github.com/Ayush10/authentication-service/pkg/jwtvalidator
```

**2. Replace `auth_jwt.go` with a thin wrapper using jwtvalidator:**

Create `cmd/server/auth_middleware.go`:

```go
package main

import (
    "net/http"
    "github.com/Ayush10/authentication-service/pkg/jwtvalidator"
)

var jwtValidator *jwtvalidator.Validator

func initJWTValidator(secret string) {
    jwtValidator = jwtvalidator.New(jwtvalidator.Config{
        Secret: secret,
    })
}

// requireAuth protects endpoints that need an authenticated user.
// Validates JWTs issued by the auth service using the client's JWT secret.
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        claims, err := jwtValidator.ValidateFromRequest(r)
        if err != nil {
            writeJSON(w, http.StatusUnauthorized, map[string]string{
                "error": "invalid or expired token",
            })
            return
        }
        ctx := jwtvalidator.WithClaims(r.Context(), claims)
        next(w, r.WithContext(ctx))
    }
}

// getUser extracts the authenticated user from the request context.
func getUser(r *http.Request) *jwtvalidator.Claims {
    return jwtvalidator.GetClaims(r.Context())
}
```

**3. Update `config.go`:**

Remove all auth-related config fields. Add `AUTH_JWT_SECRET`:

```go
type Config struct {
    Port          string
    PublicDir     string
    DatabaseURL   string
    RedisURL      string
    RedisPrefix   string
    AllowOrigin   string
    AdminPassword string
    BaseURL       string

    // Auth service integration
    AuthJWTSecret string // JWT secret from auth service client registration
}

func loadConfig() Config {
    return Config{
        Port:          envStr("PORT", "8080"),
        PublicDir:     envStr("PUBLIC_DIR", "."),
        DatabaseURL:   envStr("DATABASE_URL", ""),
        RedisURL:      envStr("REDIS_URL", ""),
        RedisPrefix:   envStr("REDIS_KEY_PREFIX", "tapdue:"),
        AllowOrigin:   envStr("ALLOW_ORIGIN", "*"),
        AdminPassword: envStr("ADMIN_PASSWORD", ""),
        BaseURL:       envStr("BASE_URL", "https://tapdue.com"),
        AuthJWTSecret: envStr("AUTH_JWT_SECRET", ""),
    }
}
```

**4. Update `main.go`:**

```go
func main() {
    cfg := loadConfig()

    if cfg.DatabaseURL == "" {
        log.Fatal("DATABASE_URL is required")
    }
    if cfg.AuthJWTSecret == "" {
        log.Fatal("AUTH_JWT_SECRET is required")
    }

    // Initialize JWT validator for auth service tokens
    initJWTValidator(cfg.AuthJWTSecret)

    // Database (TapDue's own database for business data)
    db, err := openDB(cfg.DatabaseURL)
    if err != nil {
        log.Fatalf("database: %v", err)
    }
    if err := runMigrations(db); err != nil {
        log.Fatalf("migrations: %v", err)
    }

    // Redis (optional, for TapDue business logic caching)
    rdb, err := openRedis(cfg.RedisURL, cfg.RedisPrefix)
    if err != nil {
        log.Printf("WARNING: Redis unavailable: %v", err)
    }
    _ = rdb // use for future TapDue features

    // Stores (TapDue business data only)
    wlStore := newWaitlistStore(db)

    // Router
    mux := http.NewServeMux()

    registerWaitlistRoutes(mux, wlStore, cfg.AllowOrigin)
    registerAdminRoutes(mux, wlStore, cfg)

    // Protected routes example:
    // mux.HandleFunc("GET /api/invoices", requireAuth(handleListInvoices))
    // mux.HandleFunc("POST /api/invoices", requireAuth(handleCreateInvoice))

    // Health check
    mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
        writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
    })

    // Static files
    fileServer := http.FileServer(http.Dir(cfg.PublicDir))
    mux.Handle("/", fileServer)

    server := &http.Server{
        Addr:              ":" + cfg.Port,
        Handler:           secureHeaders(logRequests(mux)),
        ReadHeaderTimeout: 5 * time.Second,
        ReadTimeout:       10 * time.Second,
        WriteTimeout:      15 * time.Second,
        IdleTimeout:       60 * time.Second,
    }

    log.Printf("TapDue server listening on :%s", cfg.Port)
    log.Fatal(server.ListenAndServe())
}
```

### How TapDue Handlers Use Auth Claims

In any protected handler, get the authenticated user like this:

```go
func handleListInvoices(w http.ResponseWriter, r *http.Request) {
    claims := getUser(r)
    if claims == nil {
        writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
        return
    }

    userID := claims.UserID()    // UUID from auth service
    email := claims.Email        // user's email
    role := claims.Role          // "user" or "admin"
    verified := claims.EmailVerified

    // Use userID as foreign key in TapDue's business tables
    // e.g., SELECT * FROM invoices WHERE user_id = $1
    _ = email
    _ = role
    _ = verified

    // ... business logic
}
```

---

## Step 7: Update TapDue's docker-compose.yml

Remove all auth-related environment variables and add `AUTH_JWT_SECRET`:

```yaml
services:
  tapdue-api:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: tapdue-api
    restart: unless-stopped
    expose:
      - "8080"
    environment:
      PORT: "8080"
      PUBLIC_DIR: "/app/public"
      ALLOW_ORIGIN: "${ALLOW_ORIGIN:-https://tapdue.com}"
      DATABASE_URL: "${DATABASE_URL:-postgres://admin:i87RfJUBx5HZJuykZt4v9u3zaq10wAqV@projects-db:5432/tapdue?sslmode=disable}"
      REDIS_URL: "${REDIS_URL:-redis://tapdue_user:BhUK71tUxASNZqOoQGMGJoQjLjhuv5WW@projects-redis:6379/0}"
      REDIS_KEY_PREFIX: "tapdue:"
      ADMIN_PASSWORD: "${ADMIN_PASSWORD}"
      BASE_URL: "${BASE_URL:-https://tapdue.com}"
      AUTH_JWT_SECRET: "${AUTH_JWT_SECRET}"
    networks:
      - coolify
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:8080/healthz"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s
    labels:
      - traefik.enable=true
      - traefik.docker.network=coolify
      - traefik.http.middlewares.gzip-tapdue.compress=true
      - traefik.http.middlewares.redirect-to-https-tapdue.redirectscheme.scheme=https
      - traefik.http.routers.http-tapdue.entryPoints=http
      - traefik.http.routers.http-tapdue.middlewares=redirect-to-https-tapdue
      - "traefik.http.routers.http-tapdue.rule=Host(`tapdue.com`) || Host(`www.tapdue.com`)"
      - traefik.http.routers.https-tapdue.entryPoints=https
      - traefik.http.routers.https-tapdue.middlewares=gzip-tapdue
      - "traefik.http.routers.https-tapdue.rule=Host(`tapdue.com`) || Host(`www.tapdue.com`)"
      - traefik.http.routers.https-tapdue.tls=true
      - traefik.http.routers.https-tapdue.tls.certresolver=letsencrypt
      - traefik.http.services.tapdue.loadbalancer.server.port=8080

networks:
  coolify:
    external: true
```

Set `AUTH_JWT_SECRET` in Coolify to the `jwt_secret` value from Step 5.

---

## Step 8: Update TapDue Frontend

The TapDue frontend needs to point auth-related requests to `authservice.ayushojha.com` instead of `tapdue.com`:

### Changes Required

1. **Login/Signup pages** -- Change form actions and fetch URLs:
   ```javascript
   // Before
   fetch('/api/auth/login', { ... })

   // After
   fetch('https://authservice.ayushojha.com/api/auth/login', {
     headers: {
       'Content-Type': 'application/json',
       'X-API-Key': 'your-client-api-key'
     },
     credentials: 'include',  // for refresh token cookie
     ...
   })
   ```

2. **Store the API key** in the frontend config (it's not secret -- it identifies the client):
   ```javascript
   const AUTH_BASE_URL = 'https://authservice.ayushojha.com';
   const AUTH_API_KEY = 'your-client-api-key-from-step-5';
   ```

3. **Token handling** -- Access tokens from the auth service work identically. Store in `localStorage` and send as `Authorization: Bearer {token}` to both `authservice.ayushojha.com` (for auth endpoints) and `tapdue.com` (for business endpoints).

4. **Or use auth service's frontend pages** -- Instead of maintaining separate login/signup pages in TapDue, redirect to `authservice.ayushojha.com/login.html?api_key=YOUR_API_KEY`. The auth service already has polished login, signup, verify-email, forgot-password, reset-password, and 2FA pages.

### Redirect-Based Flow (Simpler)

```javascript
// In TapDue frontend, redirect to auth service for login
function login() {
  window.location.href = 'https://authservice.ayushojha.com/login.html?api_key=YOUR_API_KEY';
}

// Auth service redirects back with access_token after successful login
// Handle the callback on TapDue:
const params = new URLSearchParams(window.location.search);
const token = params.get('access_token');
if (token) {
  localStorage.setItem('access_token', token);
  // User is now logged in
}
```

---

## Step 9: Data Migration (Users from TapDue to Auth Service)

If TapDue already has users in its database, you need to migrate them.

### Export Users from TapDue Database

```bash
# Via SSH tunnel
PGPASSWORD='i87RfJUBx5HZJuykZt4v9u3zaq10wAqV' psql -h localhost -p 5433 -U admin -d tapdue -c "
  COPY (
    SELECT id, email, email_verified, password_hash, display_name, avatar_url,
           timezone, locale, role, status, totp_secret, totp_enabled,
           last_login_at, created_at, updated_at
    FROM users
    WHERE status != 'deleted'
  ) TO STDOUT WITH CSV HEADER
" > /tmp/tapdue_users.csv
```

### Import Users into Auth Service Database

```bash
# First, get the TapDue client_id from Step 5
CLIENT_ID="<client-id-from-step-5>"

# Import into auth_service database
PGPASSWORD='i87RfJUBx5HZJuykZt4v9u3zaq10wAqV' psql -h localhost -p 5433 -U admin -d auth_service -c "
  -- Create temp table
  CREATE TEMP TABLE tmp_users (LIKE users INCLUDING DEFAULTS);
  ALTER TABLE tmp_users DROP COLUMN client_id;

  -- Load CSV
  \COPY tmp_users(id, email, email_verified, password_hash, display_name, avatar_url, timezone, locale, role, status, totp_secret, totp_enabled, last_login_at, created_at, updated_at) FROM '/tmp/tapdue_users.csv' CSV HEADER;

  -- Insert with client_id
  INSERT INTO users (id, client_id, email, email_verified, password_hash, display_name, avatar_url, timezone, locale, role, status, totp_secret, totp_enabled, last_login_at, created_at, updated_at)
  SELECT id, '$CLIENT_ID', email, email_verified, password_hash, display_name, avatar_url, timezone, locale, role, status, totp_secret, totp_enabled, last_login_at, created_at, updated_at
  FROM tmp_users
  ON CONFLICT DO NOTHING;
"
```

Also migrate sessions, oauth_accounts, webauthn_credentials, and verification_tokens following the same pattern (adding the `client_id` column).

---

## Step 10: DNS Setup

Ensure `authservice.ayushojha.com` DNS record points to your VPS:

```
Type: A
Name: authservice
Value: <your-vps-ip>
TTL: 300
```

Traefik will automatically provision a Let's Encrypt certificate for `authservice.ayushojha.com`.

---

## Step 11: Verify the Full Flow

### 1. Health check
```bash
curl https://authservice.ayushojha.com/healthz
# {"status":"ok"}
```

### 2. Signup a test user
```bash
curl -X POST https://authservice.ayushojha.com/api/auth/signup \
  -H "X-API-Key: <tapdue-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123!","display_name":"Test User"}'
```

### 3. Login
```bash
curl -X POST https://authservice.ayushojha.com/api/auth/login \
  -H "X-API-Key: <tapdue-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123!"}'
```

### 4. Use access token on TapDue
```bash
curl https://tapdue.com/api/invoices \
  -H "Authorization: Bearer <access-token-from-step-3>"
```

### 5. Validate token reaches TapDue correctly
The `requireAuth` middleware in TapDue validates the JWT using the same secret, extracts `userID`, `email`, `role`, `emailVerified`, and `clientID` claims.

---

## Troubleshooting

### "invalid API key" on auth service
- Verify the `X-API-Key` header matches the raw key from Step 5
- Check the client status is "active" (not "suspended")

### "invalid or expired token" on TapDue
- Verify `AUTH_JWT_SECRET` in TapDue matches the `jwt_secret` from client registration (Step 5)
- Check token hasn't expired (15 min default)
- Ensure the token was issued by the auth service (not TapDue's old JWT system)

### Auth service can't connect to database
- Verify `projects-db` hostname resolves within the `coolify` Docker network
- Check database `auth_service` exists
- Verify credentials

### CORS errors
- Ensure `ALLOW_ORIGIN=https://tapdue.com` is set on the auth service
- The `allowed_origins` on the client registration should include `https://tapdue.com`

### Refresh token cookie not working cross-domain
- The auth service sets the refresh cookie on `authservice.ayushojha.com`
- TapDue at `tapdue.com` cannot read this cookie
- Solution: Use the auth service's `/api/auth/refresh` endpoint directly from the frontend, or implement a proxy endpoint on TapDue

---

## Quick Reference

| Item | Value |
|------|-------|
| Auth service URL | `https://authservice.ayushojha.com` |
| Auth REST port | 8080 |
| Auth gRPC port | 9090 |
| Auth database | `auth_service` on `projects-db:5432` |
| Auth Redis prefix | `auth:` |
| TapDue database | `tapdue` on `projects-db:5432` |
| TapDue Redis prefix | `tapdue:` |
| Health endpoint | `GET /healthz` |
| Admin header | `X-Admin-Key: <ADMIN_API_KEY>` |
| Client header | `X-API-Key: <client-api-key>` |
| Auth header | `Authorization: Bearer <access-token>` |
| TapDue env var | `AUTH_JWT_SECRET=<jwt_secret from client registration>` |
