# Authentication Service

A multi-tenant authentication microservice built with Go, providing email/password login, OAuth2 social sign-in, magic links, passkeys (WebAuthn), TOTP two-factor authentication, and JWT-based session management. Designed for deployment behind Traefik on Coolify, serving multiple client applications from a single instance.

## Features

- **Multi-tenancy** -- Register multiple client applications with tenant-scoped users, sessions, refresh tokens, and JWT claims enforcement
- **Email/password authentication** -- Signup and login with bcrypt-hashed passwords (cost 12)
- **OAuth2 social login** -- Google, GitHub, Microsoft, and Apple identity providers
- **Magic links** -- Passwordless email-based authentication
- **Passkeys (WebAuthn/FIDO2)** -- Browser-native passwordless login with hardware or platform authenticators
- **TOTP two-factor authentication** -- Time-based one-time password support with setup/enable/verify/disable lifecycle
- **JWT access tokens** -- Per-client token modes (`v1_hs256` legacy and `v2_jwks` RS256), short-lived (15 min default)
- **JWKS support** -- Issuer-level JWKS endpoint for RS256 verification with optional client-scoped lookup (`/.well-known/jwks.json`)
- **Refresh token rotation** -- Single-use refresh tokens stored as SHA-256 hashes with hybrid delivery (HttpOnly cookie or explicit token mode)
- **Email verification** -- Token-based email address verification via Resend
- **Password reset** -- Secure token-based password reset flow
- **Rate limiting** -- Redis-backed sliding window rate limits and account lockout
- **Queryable audit logging** -- Every authentication event is logged with IP, user agent, metadata, and an admin API for filtered audit review
- **REST + gRPC** -- Dual protocol support for flexibility
- **JWT Validator package** -- Importable Go package (`pkg/jwtvalidator`) for downstream services
- **Security hardening** -- Client ownership checks across auth flows, password-change/reset session revocation, stricter CORS/origin behavior, and secret scanning hooks

## Major Updates (Latest Hardening Pass)

- Enforced stricter tenant isolation:
  - Refresh/logout/session validation is now client-bound.
  - JWT middleware rejects tokens whose `client_id` does not match request client context.
  - Magic link, TOTP verification, and passkey login/operations enforce client ownership.
- Restructured route middleware so browser/email/provider redirect flows work without impossible headers:
  - Public routes now include verify-email, reset-password, magic-link verify, and OAuth callbacks.
  - App-initiated routes still require `X-API-Key`.
- Added cross-site session controls:
  - `COOKIE_SECURE`, `COOKIE_SAMESITE`, `COOKIE_DOMAIN`.
  - `session_mode=token` support to return `refresh_token` in response JSON.
- Completed passkey service orchestration in the application layer:
  - Registration and login begin/finish flows are Redis-backed and client-scoped.
  - Canonical delete endpoint `DELETE /api/auth/passkeys/{id}` added, with root-delete backward compatibility.
  - Per-client WebAuthn overrides supported via client settings.
- Hardened OAuth:
  - PKCE + signed/encoded state payload includes `client_id`, `provider`, nonce, verifier.
  - Callback validates cached state and fails safely if state is missing/invalid.
  - Apple flow validates `id_token`; GitHub fallback fetches verified primary email.
- Added JWKS migration foundation:
  - New signing-key persistence (`client_signing_keys`) and per-client `token_mode`.
  - RS256 issuance/validation and JWKS publishing are implemented while preserving HS256 compatibility.
- Improved operations/security hygiene:
  - Sanitized committed sample secrets in docs/env templates.
  - Added CI secret scanning and pre-commit gitleaks hook.

## Quick Start (Docker Compose)

```bash
# Clone the repository
git clone https://github.com/Ayush10/authentication-service.git
cd authentication-service

# Copy and configure environment variables
cp .env.example .env
# Edit .env with your DATABASE_URL, REDIS_URL, ADMIN_API_KEY, etc.

# Build and run
docker compose up -d

# Verify it is running
curl http://localhost:8080/healthz
# {"status":"ok"}
```

## Local Development

### Prerequisites

- Go 1.24+
- PostgreSQL (local or remote)
- Redis (optional for basic email/password login, but required for OAuth state, magic links, passkeys, 2FA, and rate limiting)

### Setup

```bash
# Install dependencies
go mod download

# Copy environment file
cp .env.example .env
# Edit .env to point DATABASE_URL and REDIS_URL to your instances

# Run the server
go run ./cmd/server

# Server starts on :8080 (REST) and :9090 (gRPC)
```

Database migrations run automatically on startup.

### Running with SSH Tunnels (Remote DB)

If using a remote PostgreSQL/Redis, establish SSH tunnels first:

```bash
# PostgreSQL tunnel (port 5433)
ssh -L 5433:127.0.0.1:5433 ayush@<vps-ip> -N &

# Redis tunnel (port 6380)
ssh -L 6380:127.0.0.1:6380 ayush@<vps-ip> -N &

# Then run the server
go run ./cmd/server
```

## Environment Variables

| Variable | Default | Required | Description |
|---|---|---|---|
| `PORT` | `8080` | No | HTTP server port |
| `GRPC_PORT` | `9090` | No | gRPC server port |
| `PUBLIC_DIR` | `./public` | No | Directory for static frontend files |
| `SERVE_FRONTEND` | `true` | No | Serve static files from `PUBLIC_DIR` |
| `ALLOW_ORIGIN` | `*` | No | Default CORS allowed origin (single origin or comma-separated origins) |
| `DATABASE_URL` | -- | **Yes** | PostgreSQL connection string |
| `REDIS_URL` | -- | No | Redis connection string (required for OAuth, magic links, passkeys, 2FA, rate limiting) |
| `REDIS_KEY_PREFIX` | `auth:` | No | Prefix for all Redis keys |
| `ADMIN_API_KEY` | -- | **Yes** | Master admin API key for client management endpoints |
| `BASE_URL` | `http://localhost:8080` | No | Public base URL (used in email links) |
| `JWT_ACCESS_TTL` | `15m` | No | Access token time-to-live |
| `JWT_REFRESH_TTL` | `168h` | No | Refresh token time-to-live (default 7 days) |
| `COOKIE_SECURE` | `false` | No | Set refresh cookie `Secure` flag (`true` in production HTTPS) |
| `COOKIE_SAMESITE` | `lax` | No | Refresh cookie SameSite policy (`lax`, `strict`, `none`) |
| `COOKIE_DOMAIN` | -- | No | Optional cookie domain override for refresh cookie |
| `BCRYPT_COST` | `12` | No | bcrypt cost factor (range 10-16) |
| `RESEND_API_KEY` | -- | No | Resend API key for transactional emails |
| `EMAIL_FROM` | `Auth Service <noreply@example.com>` | No | Sender address for emails |
| `GOOGLE_CLIENT_ID` | -- | No | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | -- | No | Google OAuth client secret |
| `GOOGLE_REDIRECT_URL` | -- | No | Google OAuth callback URL |
| `GITHUB_CLIENT_ID` | -- | No | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | -- | No | GitHub OAuth client secret |
| `GITHUB_REDIRECT_URL` | -- | No | GitHub OAuth callback URL |
| `MICROSOFT_CLIENT_ID` | -- | No | Microsoft OAuth client ID |
| `MICROSOFT_CLIENT_SECRET` | -- | No | Microsoft OAuth client secret |
| `MICROSOFT_TENANT_ID` | `common` | No | Microsoft tenant ID |
| `MICROSOFT_REDIRECT_URL` | -- | No | Microsoft OAuth callback URL |
| `APPLE_CLIENT_ID` | -- | No | Apple OAuth client ID |
| `APPLE_REDIRECT_URL` | -- | No | Apple OAuth callback URL |
| `WEBAUTHN_RP_ID` | `localhost` | No | WebAuthn relying party ID (your domain) |
| `WEBAUTHN_RP_ORIGIN` | `http://localhost:8080` | No | WebAuthn relying party origin |
| `WEBAUTHN_DISPLAY_NAME` | `Auth Service` | No | WebAuthn display name shown to users |

Per-client WebAuthn overrides can be set in `client.settings` (if present): `webauthn_display_name`, `webauthn_rp_id`, `webauthn_rp_origin`.

## API Reference

Live docs:

- Production reference: <https://authservice.ayushojha.com/docs>
- OpenAPI spec: <https://authservice.ayushojha.com/docs/openapi.yaml>

Integration flow for companies/products:

1. Create one client per product, environment, or tenant boundary using `POST /api/admin/clients`.
2. Store the returned `api_key` securely and send it as `X-API-Key` on app-initiated auth requests.
3. Use cookie mode for browser products or `session_mode=token` for mobile, CLI, SSR, desktop, and API-only clients.
4. Authenticate users with email/password, OAuth2, magic links, TOTP, or passkeys.
5. Validate JWTs in downstream services with `pkg/jwtvalidator`, RS256/JWKS, or the gRPC `TokenService`.
6. Operate the integration with audit-event queries, API key rotation, JWT signing rotation, health checks, and JWKS discovery.

Route access requirements:

- `X-API-Key` required for app-initiated auth routes under `/api/auth/*` (signup/login/refresh/logout/profile/totp setup+verify, magic-link send, OAuth begin, passkey begin/finish routes, etc.).
- Public auth routes (no API key): `POST /api/auth/verify-email`, `POST /api/auth/reset-password`, `GET /api/auth/magic-link/verify`, `GET|POST /api/auth/oauth/{provider}/callback`.
- User-protected routes additionally require `Authorization: Bearer <access_token>`.
- Admin routes require `X-Admin-Key`.

### Authentication

```
POST /api/auth/signup              Register a new user
POST /api/auth/login               Login with email and password
POST /api/auth/refresh             Refresh access token (uses auth_refresh cookie)
POST /api/auth/logout              Revoke the current session (cookie or refresh_token body)
GET  /api/auth/me                  Get the authenticated user profile
PATCH /api/auth/me                 Update the authenticated user profile
POST /api/auth/change-password     Change password (requires current password)
```

### Email Verification and Password Reset

```
POST /api/auth/verify-email        Verify email address with token
POST /api/auth/resend-verification Resend verification email (requires auth)
POST /api/auth/forgot-password     Request a password reset email
POST /api/auth/reset-password      Reset password with token
```

`verify-email` and `reset-password` are public token endpoints (no `X-API-Key` required).

### Magic Links

```
POST /api/auth/magic-link/send     Send a magic link to an email address
GET  /api/auth/magic-link/verify   Verify magic link token and authenticate
```

`magic-link/verify` accepts `token` as a query parameter and supports browser redirect or JSON response.

### TOTP Two-Factor Authentication

```
POST /api/auth/totp/setup          Generate TOTP secret and QR code URI (requires auth)
POST /api/auth/totp/enable         Confirm TOTP setup with a valid code (requires auth)
POST /api/auth/totp/verify         Complete 2FA login with TOTP code
POST /api/auth/totp/disable        Disable TOTP on the account (requires auth)
```

### OAuth2 Social Login

```
GET  /api/auth/oauth/{provider}           Begin OAuth flow (redirects to provider)
GET  /api/auth/oauth/{provider}/callback   OAuth callback handler
POST /api/auth/oauth/{provider}/callback   OAuth callback handler (provider form-post compatible)
```

Supported providers: `google`, `github`, `microsoft`, `apple`

`oauth/{provider}` begin requires `X-API-Key` so tenant context is known. Callback routes are public and tenant is recovered from validated OAuth state.

### Passkeys (WebAuthn)

```
POST   /api/auth/passkey/register/begin    Begin passkey registration (requires auth)
POST   /api/auth/passkey/register/finish   Complete passkey registration (requires auth)
POST   /api/auth/passkey/login/begin       Begin passkey login
POST   /api/auth/passkey/login/finish      Complete passkey login
GET    /api/auth/passkeys                  List user passkeys (requires auth)
DELETE /api/auth/passkeys                  Delete a passkey (requires auth)
DELETE /api/auth/passkeys/{id}             Delete a passkey by ID (canonical path)
```

`passkey/login/finish` requires `session_id` query param from login begin response.

### Admin (Client Management)

```
POST /api/admin/clients                       Create a new client (tenant)
GET  /api/admin/clients                       List all clients
GET  /api/admin/clients/{id}                  Get client by ID
POST /api/admin/clients/{id}/rotate-secret    Rotate client JWT secret
POST /api/admin/clients/{id}/rotate-api-key   Rotate client API key
POST /api/admin/clients/{id}/rotate-jwt       Alias for rotate-secret
POST /api/admin/clients/{id}/rotate-key       Alias for rotate-api-key
GET  /api/admin/audit-events                  Query audit events
```

`GET /api/admin/audit-events` supports `client_id`, `user_id`, `event_type`, and `limit` query parameters. The limit defaults to 50 and is capped at 500.

### Health

```
GET /healthz    Health check (returns {"status": "ok"})
GET /.well-known/jwks.json    Public issuer JWKS (`X-API-Key` or `client_id` optionally narrows to one client)
```

Hybrid session mode:

- Default: refresh token is stored in HttpOnly `auth_refresh` cookie.
- Token mode: use `session_mode=token` to receive `refresh_token` in JSON instead of cookie.
- Supported endpoints:
  - Body/query: `POST /api/auth/login`, `POST /api/auth/refresh`, `POST /api/auth/totp/verify`
  - Query only: `GET /api/auth/magic-link/verify`, `POST /api/auth/passkey/login/finish`

## Multi-Tenancy Guide

### Registering a Client

Create a new client (tenant) using the admin API:

```bash
curl -X POST http://localhost:8080/api/admin/clients \
  -H "X-Admin-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "slug": "my-app",
    "allowed_origins": ["https://myapp.com"],
    "webhook_url": "https://myapp.com/webhooks/auth"
  }'
```

Response:

```json
{
  "client": {
    "id": "uuid-here",
    "name": "My App",
    "slug": "my-app",
    "allowed_origins": ["https://myapp.com"],
    "webhook_url": "https://myapp.com/webhooks/auth",
    "status": "active",
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z"
  },
  "api_key": "raw-api-key-save-this"
}
```

**Important:** The `api_key` is returned only once at creation time. Store it securely.

### Using API Keys

Client API key (`X-API-Key`) is required for app-initiated auth endpoints. Public token/callback endpoints are intentionally unauthenticated (verify/reset/magic-link verify/OAuth callback).

```bash
# Example: signup a user under your client
curl -X POST http://localhost:8080/api/auth/signup \
  -H "X-API-Key: raw-api-key-save-this" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword",
    "display_name": "Jane Doe",
    "session_mode": "token"
  }'
```

Use `session_mode=token` on signup/login/refresh when a non-browser client needs the refresh token in JSON. Browser clients can omit it and use the HttpOnly `auth_refresh` cookie.

### Key Rotation

Rotate the JWT signing secret (invalidates all existing access tokens for that client):

```bash
curl -X POST http://localhost:8080/api/admin/clients/{id}/rotate-secret \
  -H "X-Admin-Key: your-admin-api-key"
```

Alias route also supported:

```bash
curl -X POST http://localhost:8080/api/admin/clients/{id}/rotate-jwt \
  -H "X-Admin-Key: your-admin-api-key"
```

Rotate the API key (invalidates the current API key, returns a new one):

```bash
curl -X POST http://localhost:8080/api/admin/clients/{id}/rotate-api-key \
  -H "X-Admin-Key: your-admin-api-key"
```

Alias route also supported:

```bash
curl -X POST http://localhost:8080/api/admin/clients/{id}/rotate-key \
  -H "X-Admin-Key: your-admin-api-key"
```

## Testing

Run the full suite:

```bash
go test ./...
```

The REST E2E suite includes auth lifecycle, refresh rotation, logout, email verification, magic links, TOTP, OAuth state/PKCE, passkey route handling, audit queries, client admin, and Redis-required feature failures.

Browser-grade tests use Chrome/Chromium through Chrome DevTools Protocol. They drive real WebAuthn browser APIs for passkey registration/login and run the public auth pages across desktop, iOS mobile-web, and Android mobile-web profiles. Set `CHROME_BIN` if Chrome is not on the default path:

```bash
CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" go test ./internal/interfaces/rest -run 'TestBrowserGradePasskey|TestBrowserPublicAuthPages' -count=1 -v
```

## JWT Validator Package

The `pkg/jwtvalidator` package allows downstream Go services to validate access tokens issued by this authentication service.

- HS256 mode: validate with client secret.
- RS256/JWKS mode: validate with `JWKSURL` and optional `ClientID` match enforcement.

### Installation

```bash
go get github.com/Ayush10/authentication-service/pkg/jwtvalidator
```

### Usage

```go
package main

import (
    "fmt"
    "net/http"
    "os"

    "github.com/Ayush10/authentication-service/pkg/jwtvalidator"
)

func main() {
    // HS256 mode (legacy clients)
    validator := jwtvalidator.New(jwtvalidator.Config{
        Secret: os.Getenv("AUTH_JWT_SECRET"),
    })

    // Option 1: Validate a token string directly
    claims, err := validator.Validate(tokenString)
    if err != nil {
        fmt.Println("Invalid token:", err)
        return
    }
    fmt.Println("User ID:", claims.UserID())
    fmt.Println("Email:", claims.Email)
    fmt.Println("Role:", claims.Role)
    fmt.Println("Client ID:", claims.ClientID)
    fmt.Println("Email Verified:", claims.EmailVerified)

    // Option 2: Use as HTTP middleware
    mux := http.NewServeMux()
    mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
        claims := jwtvalidator.GetClaims(r.Context())
        fmt.Fprintf(w, "Hello, %s", claims.Email)
    })

    // Wrap your handler with the validator middleware
    http.ListenAndServe(":3000", validator.Middleware(mux))
}
```

JWKS/RS256 mode example:

```go
jwksValidator := jwtvalidator.New(jwtvalidator.Config{
    JWKSURL:         "https://auth.example.com/.well-known/jwks.json",
    ClientID:        "<client-id>", // optional but recommended
    RefreshInterval: 5 * time.Minute,
})
```

### Claims Structure

```go
type Claims struct {
    jwt.RegisteredClaims
    Email         string `json:"email"`
    Role          string `json:"role"`
    EmailVerified bool   `json:"email_verified"`
    ClientID      string `json:"client_id"`
}
```

The `UserID()` method returns the `sub` (Subject) claim, which is the user's UUID.

### Context Helpers

```go
// Store claims in context (done automatically by Middleware)
ctx = jwtvalidator.WithClaims(ctx, claims)

// Retrieve claims from context
claims := jwtvalidator.GetClaims(ctx)
```

## gRPC Usage

The service exposes gRPC services on port `9090` (configurable via `GRPC_PORT`). Proto definitions are located in `proto/auth/v1/`.

### Available Services

- **AuthService** -- User authentication operations (signup, login, refresh, logout, profile management, email verification, password reset, magic links)
- **TokenService** -- Token validation for service-to-service communication
- **AdminService** -- Client (tenant) management (create, list, rotate secrets/keys)

Passkey/WebAuthn operations are currently exposed via REST endpoints.

`AuthService.Logout` now requires `api_key` in addition to `refresh_token` to enforce client-bound session revocation.

### Token Validation (Service-to-Service)

Other microservices can validate tokens via gRPC without needing the JWT secret:

```protobuf
service TokenService {
  rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse);
}

message ValidateTokenRequest {
  string access_token = 1;
  string api_key = 2;
}

message ValidateTokenResponse {
  bool valid = 1;
  string user_id = 2;
  string email = 3;
  string role = 4;
  bool email_verified = 5;
  string client_id = 6;
  string error = 7;
}
```

## Architecture Overview

The service follows Clean Architecture (Hexagonal Architecture) with four layers:

```
internal/
  domain/           Entity definitions and domain errors (zero dependencies)
  application/      Use cases, business logic, port interfaces
  infrastructure/   PostgreSQL repos (including signing keys), Redis client, Resend email client
  interfaces/       REST handlers + gRPC handlers, middleware
pkg/
  jwtvalidator/     Public Go package for downstream JWT validation
```

Dependencies always point inward: interfaces -> application -> domain. Infrastructure implements application port interfaces.

For the full architecture documentation with Mermaid diagrams, database schema, sequence diagrams for all auth flows, and security model details, see **[docs/architecture.md](docs/architecture.md)**.

## Project Structure

```
authentication-service/
  cmd/server/                   Application entry point and config
    main.go                     Wiring and HTTP server setup
    config.go                   Environment variable loading
  internal/
    domain/                     Domain entities and errors
      client.go                 Client (tenant) entity
      signing_key.go            Per-client asymmetric signing key entity (JWKS)
      user.go                   User entity
      session.go                Session entity
      oauth_account.go          OAuth account entity
      webauthn_credential.go    WebAuthn credential entity
      verification_token.go     Verification token entity
      audit_event.go            Audit event entity
      errors.go                 Domain error definitions
    application/                Business logic and port interfaces
      ports.go                  Repository and service interfaces
      auth_service.go           Core auth logic (signup, login, refresh, logout)
      auth_tokens_test.go       Token mode/JWKS validation tests
      client_service.go         Client management logic
      email_verify_service.go   Email verification logic
      password_reset_service.go Password reset logic
      magic_link_service.go     Magic link logic
      totp_service.go           TOTP 2FA logic
      oauth_service.go          OAuth2 flow logic
      passkey_service.go        WebAuthn/passkey logic
    infrastructure/
      postgres/                 PostgreSQL repository implementations
        migrations/             SQL migration files (auto-run on startup)
          008_add_jwks_signing_keys.sql   token_mode + signing key tables
        signing_key_repo.go     Signing key persistence for JWKS/RS256
      redis/                    Redis client and rate limiter
      email/                    Resend email client
    interfaces/
      rest/                     HTTP REST handlers and middleware
        router.go               Route registration and middleware wiring
        middleware.go           API key, JWT auth, CORS, security middleware
        middleware_test.go      CORS/session mode tests
        auth_handler.go         Signup, login, refresh, logout, profile handlers
        verify_handler.go       Email verification and password reset handlers
        magic_link_handler.go   Magic link handlers
        totp_handler.go         TOTP 2FA handlers
        oauth_handler.go        OAuth2 handlers
        passkey_handler.go      WebAuthn/passkey handlers
        client_handler.go       Admin client management handlers
      grpc/                     gRPC server implementation
  pkg/
    jwtvalidator/               Public JWT validation package
      validator.go              Token parsing and HTTP middleware
      claims.go                 Claims type definition
      context.go                Context helpers for claims storage
  proto/auth/v1/                Protocol Buffer definitions
    auth.proto                  AuthService RPCs
    token.proto                 TokenService RPCs
    admin.proto                 AdminService RPCs
  docker-compose.yml            Production deployment configuration
  Dockerfile                    Multi-stage Docker build
  .env.example                  Environment variable template
  .github/workflows/secret-scan.yml   CI secret scanning (gitleaks)
  .pre-commit-config.yaml       Local secret scanning hook
```

## License

MIT
