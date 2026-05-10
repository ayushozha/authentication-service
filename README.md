# Authentication Service

A multi-tenant authentication microservice built with Go, providing email/password login, OAuth2 social sign-in, magic links, passkeys (WebAuthn), TOTP two-factor authentication, and JWT-based session management. Designed for deployment behind Traefik on Coolify, serving multiple client applications from a single instance.

## Features

- **Multi-tenancy** -- Register multiple client applications with tenant-scoped users, sessions, refresh tokens, and JWT claims enforcement
- **Organization authorization** -- B2B SaaS organizations with versioned resource/action policies, custom role templates, group-to-role mappings, policy simulator explanations, invitations, member management, and org-scoped access tokens
- **Machine-to-machine auth** -- OAuth2 client credentials for service accounts with scoped secrets, token introspection, key rotation, and revocation
- **Enterprise SSO** -- Per-client SAML 2.0 and generic OIDC connections with domain routing, SP metadata, signed SAML response validation, JIT user provisioning, and SSO identity linking
- **SCIM 2.0 directory sync** -- Inbound enterprise provisioning for users and groups with bearer tokens, deprovisioning, token rotation, and audit events
- **Hosted auth and account UI** -- Branded, localizable, accessible login/signup/MFA/passkey/magic-link/OAuth/SSO pages plus account, profile, security, org, SSO, SCIM, and audit views
- **Admin and customer portal** -- Static API-backed console for client operations, audit queries, M2M, SSO, SCIM, profile, MFA, passkeys, and organization workflows
- **SDKs and embeddable UI** -- Dependency-free browser, React/Next.js, Vue/Svelte, Node.js, Swift, and Android Java starters plus generated TypeScript, Python, Go, Java/Kotlin, C#, PHP, Ruby, and Rust SDK packages
- **Framework connectors** -- Official middleware adapters for Express, Fastify, NestJS, Next.js, Django, FastAPI, Flask, Spring Boot, ASP.NET Core, Laravel, Rails/Rack, Axum, Actix, Gin, Chi, Echo, and Fiber
- **CLI and Terraform** -- `cmd/authservice` automates login, token inspection, client/service-account/SSO/SCIM/audit/key workflows; `terraform-provider-authservice` provisions clients, organizations, SSO, SCIM, and service accounts
- **Native SDK starters** -- Swift Package and Android Gradle/JUnit starters for mobile signup/login/session/profile/organization workflows, secure token-store adapters, and deep-link integration patterns
- **Email/password authentication** -- Signup and login with bcrypt-hashed passwords (cost 12)
- **OAuth2 social login** -- Google, GitHub, Microsoft, and Apple identity providers
- **Magic links** -- Passwordless email-based authentication
- **Passkeys (WebAuthn/FIDO2)** -- Browser-native passwordless login with hardware/platform authenticators, resident credentials, and conditional UI/autofill support
- **TOTP two-factor authentication** -- Time-based one-time password support with setup/enable/verify/disable lifecycle and one-time recovery codes
- **Adaptive security and step-up** -- Per-client and per-org MFA/risk policies can allow, require, adaptively challenge, block, or notify for high-risk logins and sensitive actions
- **JWT access tokens** -- Per-client token modes (`v1_hs256` legacy and `v2_jwks` RS256), short-lived (15 min default), with optional org and service-account claims
- **JWKS support** -- Issuer-level JWKS endpoint for RS256 verification with optional client-scoped lookup (`/.well-known/jwks.json`)
- **Refresh token rotation** -- Single-use refresh tokens stored as SHA-256 hashes with hybrid delivery (HttpOnly cookie or explicit token mode)
- **Email verification** -- Token-based email address verification via Resend
- **Password reset** -- Secure token-based password reset flow
- **Rate limiting** -- Redis-backed sliding window rate limits and account lockout
- **Password risk controls** -- Configurable password policy with compromised/common-password, low-entropy, and user-info rejection plus audit events
- **Signup risk controls** -- Disposable/temporary email domain blocking with configurable denylist and audit events
- **Session and device visibility** -- Authenticated users can list/revoke active sessions, while password logins audit suspicious new IP/device combinations and surface adaptive MFA risk signals
- **Queryable audit logging and webhooks** -- Every authentication event is logged with IP, user agent, metadata, filtered admin review/export, and optional signed webhook delivery with retries
- **REST + gRPC** -- Dual protocol support for flexibility
- **JWT Validator package** -- Importable Go package (`pkg/jwtvalidator`) for downstream services
- **Security hardening** -- Client ownership checks across auth flows, one-time redirect auth codes for browser callbacks, enforced-domain SSO blocking for password flows, password-change/reset session revocation, constant-time admin key checks, stricter CORS/origin behavior, and secret scanning hooks

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
  - Browser callbacks now redirect with a short-lived `auth_code` exchanged by `/api/auth/redirect/exchange`, so access tokens are not placed in URLs.
  - Apple flow validates `id_token`; GitHub fallback fetches verified primary email.
- Enforced enterprise SSO domains:
  - `enforce_for_domains` blocks email/password signup, password login, social OAuth, magic links, password reset emails, and password changes for matching active SSO domains.
  - SSO enforcement decisions emit audit events for blocked interactive flows.
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
| `ADMIN_API_KEY` | -- | **Yes** | Break-glass master admin key; rate-limited and audited, use admin user tokens for daily operations |
| `ADMIN_TOKEN_SECRET` | `ADMIN_API_KEY` | No | HS256 signing secret for admin user access tokens |
| `ADMIN_ACCESS_TTL` | `8h` | No | Admin user access-token time-to-live |
| `BASE_URL` | `http://localhost:8080` | No | Public base URL (used in email links) |
| `JWT_ACCESS_TTL` | `15m` | No | Access token time-to-live |
| `JWT_REFRESH_TTL` | `168h` | No | Refresh token time-to-live (default 7 days) |
| `COOKIE_SECURE` | `false` | No | Set refresh cookie `Secure` flag (`true` in production HTTPS) |
| `COOKIE_SAMESITE` | `lax` | No | Refresh cookie SameSite policy (`lax`, `strict`, `none`) |
| `COOKIE_DOMAIN` | -- | No | Optional cookie domain override for refresh cookie |
| `BCRYPT_COST` | `12` | No | bcrypt cost factor (range 10-16) |
| `PASSWORD_MIN_LENGTH` | `8` | No | Minimum password length |
| `PASSWORD_MAX_LENGTH` | `72` | No | Maximum bcrypt-safe password length |
| `PASSWORD_MIN_UNIQUE` | `4` | No | Minimum number of unique non-space characters |
| `PASSWORD_BLOCK_COMMON` | `true` | No | Reject known common/compromised password patterns |
| `PASSWORD_BLOCK_USER_INFO` | `true` | No | Reject passwords containing the user's email name or display-name tokens |
| `BLOCKED_EMAIL_DOMAINS` | built-in disposable list | No | Comma-separated email domains to block at signup; set to your own list to override defaults |
| `WEBHOOK_SIGNING_SECRET` | -- | No | Enables per-client `webhook_url` audit-event delivery and signs payloads with HMAC-SHA256 |
| `WEBHOOK_RETRY_ATTEMPTS` | `3` | No | Number of audit webhook delivery attempts (1-10) |
| `WEBHOOK_TIMEOUT` | `5s` | No | Per-attempt audit webhook HTTP timeout |
| `AUDIT_RETENTION_DAYS` | `2555` | No | Default audit `retention_until` window for new events |
| `AUDIT_STREAMS` | -- | No | Comma-separated audit log streams: `datadog`, `splunk`, `elastic`, `s3`, `cloudwatch`, `gcp`, `azure`, `stdout` |
| `AUDIT_STREAM_TIMEOUT` | `5s` | No | Per-attempt SIEM/log stream timeout |
| `AUDIT_STREAM_RETRY_ATTEMPTS` | `3` | No | SIEM/log stream retries (1-10) |
| `CAPTCHA_PROVIDER` | -- | No | Optional bot verifier provider: `turnstile`, `hcaptcha`, or `recaptcha` |
| `CAPTCHA_SECRET` | -- | No | Secret key for the configured CAPTCHA/bot provider |
| `CAPTCHA_VERIFY_URL` | provider default | No | Override verification endpoint for custom providers or tests |
| `CAPTCHA_TIMEOUT` | `5s` | No | Per-attempt CAPTCHA verification timeout |
| `CAPTCHA_SIGNUP_REQUIRED` | `false` | No | Require `captcha_token` on signup |
| `CAPTCHA_LOGIN_REQUIRED` | `false` | No | Require `captcha_token` on password login |
| `RISK_PROVIDER_URL` | -- | No | Optional HTTP risk-signal provider called during login and protected actions |
| `RISK_PROVIDER_API_KEY` | -- | No | Bearer token sent to the risk provider |
| `RISK_PROVIDER_TIMEOUT` | `5s` | No | Per-request risk-provider timeout |
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

Per-client WebAuthn overrides can be set in `client.settings` (if present): `webauthn_display_name`, `webauthn_rp_id`, `webauthn_rp_origin`, `webauthn_attestation` (`none`, `indirect`, `direct`, `enterprise`), `webauthn_require_attestation`, and `webauthn_allowed_attestation_formats` (for example `packed,tpm,apple`).

## API Reference

Live docs:

- Production reference: <https://authservice.ayushojha.com/docs>
- OpenAPI spec: <https://authservice.ayushojha.com/docs/openapi.yaml>
- Admin/customer portal: <https://authservice.ayushojha.com/portal.html>
- Browser SDK: <https://authservice.ayushojha.com/authservice.js>
- SDK starters: `sdks/`
- Operations runbook: `docs/operations-runbook.md`
- Passkey QA checklist: `docs/passkey-qa.md`
- Enterprise provider roadmap: `docs/enterprise-auth-provider-roadmap.md`
- Enterprise strengthening goals: `docs/enterprise-strengthening-goals.md`

Integration flow for companies/products:

1. Create one client per product, environment, or tenant boundary using `POST /api/admin/clients`.
2. Store the returned `api_key` securely and send it as `X-API-Key` on app-initiated auth requests.
3. Use cookie mode for browser products or `session_mode=token` for mobile, CLI, SSR, desktop, and API-only clients.
4. Authenticate users with email/password, OAuth2, magic links, TOTP, or passkeys, either by calling the REST API directly, loading `/authservice.js`, or using the SDK starters under `sdks/`.
5. For B2B products, create organizations, invite users, and mint org-scoped access tokens before calling tenant-aware product APIs.
6. For backend automation, provision service accounts and call `/oauth/token` with the `client_credentials` grant.
7. For mobile apps, start from `sdks/ios/AuthServiceClient.swift` or `sdks/android/com/authservice/sdk/AuthServiceClient.java` and back the token-store protocol with Keychain or encrypted shared preferences.
8. Validate JWTs in downstream services with `pkg/jwtvalidator`, RS256/JWKS, token introspection, or the gRPC `TokenService`.
9. Operate the integration with audit-event queries/exports/webhooks, API key rotation, JWT signing rotation, health checks, and JWKS discovery.

Route access requirements:

- `X-API-Key` required for app-initiated auth routes under `/api/auth/*` (signup/login/refresh/logout/profile/totp setup+verify, magic-link send, OAuth begin, passkey begin/finish routes, etc.).
- Public auth routes (no API key): `POST /api/auth/verify-email`, `POST /api/auth/reset-password`, `GET /api/auth/magic-link/verify`, `GET|POST /api/auth/oauth/{provider}/callback`.
- User-protected routes additionally require `Authorization: Bearer <access_token>`.
- Step-up protected mutations accept `X-Step-Up-Token` or `step_up_token` after `POST /api/auth/step-up/verify`.
- Admin routes require `Authorization: Bearer <admin_access_token>` from `/api/admin/auth/login` or `/api/admin/auth/sso`; `X-Admin-Key` remains a rate-limited, audited break-glass fallback.
- Machine-to-machine token routes use service-account `client_id` and `client_secret` via JSON/form body or HTTP Basic auth.
- Static browser assets such as `/authservice.js`, `/auth-ui.js`, `/login.html`, `/signup.html`, `/account.html`, and `/portal.html` are public shells; protected operations still call the APIs with the admin key, client API key, or access token you provide.

### Authentication

```
POST /api/auth/signup              Register a new user
POST /api/auth/login               Login with email and password
POST /api/auth/refresh             Refresh access token (uses auth_refresh cookie)
POST /api/auth/logout              Revoke the current session (cookie or refresh_token body)
GET  /api/auth/me                  Get the authenticated user profile
PATCH /api/auth/me                 Update the authenticated user profile
POST /api/auth/change-password     Change password (requires current password)
GET  /api/auth/sessions            List active refresh sessions for the current user
DELETE /api/auth/sessions          Revoke all current-user sessions for this client
DELETE /api/auth/sessions/{id}     Revoke one current-user session
```

### Organizations and RBAC

```
GET    /api/auth/organizations                              List organizations for the current user
POST   /api/auth/organizations                              Create an organization; creator becomes owner
GET    /api/auth/organizations/{org_id}                     Get an organization and current membership
PATCH  /api/auth/organizations/{org_id}                     Update organization name or slug (requires org write permission)
GET    /api/auth/organizations/{org_id}/members             List active members (requires members read permission)
PATCH  /api/auth/organizations/{org_id}/members/{user_id}   Update member role/permissions (requires members write permission)
DELETE /api/auth/organizations/{org_id}/members/{user_id}   Remove a member (requires members write permission)
GET    /api/auth/organizations/{org_id}/invitations         List invitations (requires invitations read permission)
POST   /api/auth/organizations/{org_id}/invitations         Invite a user by email (requires invitations write permission)
POST   /api/auth/organizations/{org_id}/invitations/{id}/revoke
POST   /api/auth/organization-invitations/accept            Accept an invitation token as the invited user
POST   /api/auth/organizations/{org_id}/token               Mint an org-scoped access token
GET    /api/auth/organizations/{org_id}/security-policy     Get organization adaptive security policy
PUT    /api/auth/organizations/{org_id}/security-policy     Replace organization adaptive security policy
PATCH  /api/auth/organizations/{org_id}/security-policy     Replace organization adaptive security policy
```

Built-in roles are `owner`, `admin`, `member`, and `viewer`. Built-in permissions are `org:read`, `org:write`, `members:read`, `members:write`, `invitations:read`, and `invitations:write`. Custom lower-case role keys and namespaced permission keys such as `billing:manage` are supported for application-specific authorization.

### OIDC Provider

```
GET  /.well-known/openid-configuration      OIDC discovery
GET  /.well-known/jwks.json                 RS256 signing keys
GET  /authorize                             Authorization code + PKCE endpoint
POST /token                                 authorization_code, refresh_token, and client_credentials grants
GET  /userinfo                              OIDC userinfo endpoint
POST /revoke                                Refresh/access token revocation
POST /introspect                            Token introspection
GET  /logout                                RP-initiated logout
```

Configure OIDC apps through `client.settings`: `oidc_redirect_uris`, `oidc_post_logout_redirect_uris`, `oidc_allowed_scopes`, `oidc_audiences`, `oidc_trusted`, `oidc_require_consent`, `oidc_require_pkce`, and `oidc_public_client`. Public browser/mobile clients use PKCE with `client_id=<client UUID>`; confidential clients may authenticate to `/token`, `/revoke`, and `/introspect` with the raw client API key or JWT secret as `client_secret`.

### Machine-to-Machine Auth

```
POST /oauth/token                                      OAuth2 client credentials token endpoint
POST /oauth/introspect                                 Token introspection endpoint
GET  /api/admin/clients/{client_id}/service-accounts   List service accounts
POST /api/admin/clients/{client_id}/service-accounts   Create service account and initial secret
GET  /api/admin/clients/{client_id}/service-accounts/{service_account_id}
PATCH /api/admin/clients/{client_id}/service-accounts/{service_account_id}
DELETE /api/admin/clients/{client_id}/service-accounts/{service_account_id}
GET  /api/admin/clients/{client_id}/service-accounts/{service_account_id}/keys
POST /api/admin/clients/{client_id}/service-accounts/{service_account_id}/keys
DELETE /api/admin/clients/{client_id}/service-accounts/{service_account_id}/keys/{key_id}
POST /api/admin/clients/{client_id}/service-accounts/{service_account_id}/keys/{key_id}/rotate
```

Use the service account ID as OAuth `client_id` and the returned secret as `client_secret`. Secrets are shown once, stored as SHA-256 hashes, and can be revoked or rotated independently.

### Enterprise SSO

```
GET  /api/auth/sso?domain=acme.com                          Start SSO by verified email domain
GET  /api/auth/sso/{connection_id_or_slug}                   Start SSO by connection ID or slug
GET  /api/auth/sso/callback/{connection_id}                  OIDC redirect callback
POST /api/auth/sso/callback/{connection_id}                  SAML ACS callback
GET  /api/auth/sso/metadata/{connection_id}                  SAML service provider metadata
GET  /api/admin/clients/{client_id}/sso-connections          List enterprise SSO connections
POST /api/admin/clients/{client_id}/sso-connections          Create SAML or OIDC connection
GET  /api/admin/clients/{client_id}/sso-connections/{id}
PATCH /api/admin/clients/{client_id}/sso-connections/{id}
DELETE /api/admin/clients/{client_id}/sso-connections/{id}   Deactivate connection
```

OIDC connections use discovery from the configured issuer and verify ID tokens, audience, issuer, expiry, signature, and nonce. SAML connections expose SP metadata, generate HTTP-Redirect AuthnRequests, and validate signed SAML responses against IdP metadata or configured X.509 certificates.

### SCIM 2.0 Directory Sync

```
GET  /scim/v2/{directory_id}/ServiceProviderConfig
GET  /scim/v2/{directory_id}/ResourceTypes
GET  /scim/v2/{directory_id}/Schemas
GET  /scim/v2/{directory_id}/Users
POST /scim/v2/{directory_id}/Users
GET  /scim/v2/{directory_id}/Users/{scim_user_id}
PUT  /scim/v2/{directory_id}/Users/{scim_user_id}
PATCH /scim/v2/{directory_id}/Users/{scim_user_id}
DELETE /scim/v2/{directory_id}/Users/{scim_user_id}
GET  /scim/v2/{directory_id}/Groups
POST /scim/v2/{directory_id}/Groups
GET  /scim/v2/{directory_id}/Groups/{scim_group_id}
PUT  /scim/v2/{directory_id}/Groups/{scim_group_id}
PATCH /scim/v2/{directory_id}/Groups/{scim_group_id}
DELETE /scim/v2/{directory_id}/Groups/{scim_group_id}
GET  /api/admin/clients/{client_id}/scim-directories
POST /api/admin/clients/{client_id}/scim-directories
GET  /api/admin/clients/{client_id}/scim-directories/{directory_id}
PATCH /api/admin/clients/{client_id}/scim-directories/{directory_id}
POST /api/admin/clients/{client_id}/scim-directories/{directory_id}/rotate-token
```

SCIM endpoints use `Authorization: Bearer <directory_token>`. User `active=false` and `DELETE` deprovision the linked AuthService user by setting status to `suspended`.

### Admin and Customer Portal

```
GET /login.html                     Hosted sign-in with password, passkeys, magic links, OAuth, SSO discovery, and MFA challenges
GET /signup.html                    Hosted signup with password/social entry and post-signup passkey enrollment
GET /account.html                   Hosted account, MFA, passkeys, recovery codes, sessions, orgs, SSO/SCIM setup, and audit views
GET /portal.html                    API-backed operations console and account portal
GET /authservice.js                 Browser SDK and embeddable UI helpers
GET /auth-ui.js                     Shared hosted auth/account UI runtime
GET /auth-ui.css                    Shared hosted auth/account UI styles
GET /api/auth/ui/config             Tenant UI config for brand, theme, locale, providers, and hosted paths
```

The hosted auth pages are static shells backed by the same APIs as the SDK. They support custom domains through normal static hosting/reverse proxying, tenant brand settings from `client.settings.auth_ui`, locale selection with `locale=`, accessible labels/focus states, and redirect allow-listing against the client allowed origins.

The portal remains a static browser shell for day-to-day administration and customer self-service. Admin operators can create clients, rotate API/JWT secrets, inspect audit events, provision service accounts, manage enterprise SSO connections, and manage SCIM directories. Authenticated users can load and update their profile, change passwords, configure TOTP/recovery codes, register/delete passkeys, create organizations, send invitations, accept invitations, and mint org-scoped tokens.

The SDKs expose helpers for signup, login, refresh, logout, `/me`, profile updates, session listing/revocation, TOTP, recovery codes, passkeys, organizations, magic links, OAuth/SSO redirects, M2M token exchange, admin SSO/SCIM/audit workflows, and embeddable sign-in/signup/profile/org/enterprise widgets. Browser usage starts with `AuthService.createClient({ baseUrl, apiKey, sessionMode: "token" })`; React, Vue, Svelte, Next.js, Node.js, iOS, and Android starters live under `sdks/`.

```html
<div id="signin"></div>
<div id="user"></div>
<script src="/authservice.js"></script>
<script>
  const auth = AuthService.createClient({
    baseUrl: "https://auth.example.com",
    apiKey: "raw-api-key-save-this",
    sessionMode: "token"
  });

  auth.mountSignIn("#signin", {
    onSuccess() {
      auth.mountUserButton("#user").refresh();
    }
  });

  auth.mountUserProfile("#profile");
  auth.mountOrganizationSwitcher("#orgs");
  auth.mountOrganizationManagement("#members");
  auth.mountEnterpriseSetup("#enterprise", {
    clientID: "client_uuid",
    adminKey: "admin-key"
  });
  auth.mountAuditLog("#audit", {
    clientID: "client_uuid",
    adminKey: "admin-key"
  });
</script>
```

Tenant branding can be stored on a client with `PATCH /api/admin/clients/{id}`:

```json
{
  "settings": {
    "auth_ui": {
      "brand_name": "Acme",
      "logo_url": "https://app.example.com/logo.png",
      "primary_color": "#0f766e",
      "locale": "en",
      "oauth_providers": ["google", "github", "microsoft"],
      "redirect_url": "https://app.example.com/dashboard"
    }
  }
}
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

`magic-link/verify` accepts `token` as a query parameter and supports browser redirect or JSON response. Browser redirects use a short-lived `auth_code`; exchange it with `POST /api/auth/redirect/exchange` instead of reading tokens from the URL.

### TOTP Two-Factor Authentication

```
POST /api/auth/totp/setup          Generate TOTP secret and QR code URI (requires auth)
POST /api/auth/totp/enable         Confirm TOTP setup with a valid code (requires auth)
POST /api/auth/totp/verify         Complete 2FA login with TOTP code
POST /api/auth/totp/disable        Disable TOTP on the account (requires auth)
GET  /api/auth/recovery-codes      Count unused recovery codes (requires auth)
POST /api/auth/recovery-codes      Rotate and return one-time recovery codes (requires auth)
POST /api/auth/recovery-codes/verify Complete 2FA login with a recovery code
```

Recovery codes are shown once, stored only as hashes, and consumed after a successful recovery-code login.

### Adaptive Security and Step-Up

```
POST   /api/auth/step-up/verify       Verify a step-up challenge and receive a short-lived step_up_token
POST   /api/admin/step-up/verify      Verify an admin step-up challenge for protected admin mutations
GET    /api/auth/devices              List remembered devices for the current user
PATCH  /api/auth/devices/{id}         Trust, untrust, or rename a remembered device
DELETE /api/auth/devices/{id}         Remove a remembered device
GET    /api/admin/clients/{id}/security-policy  Get client adaptive security policy
PUT    /api/admin/clients/{id}/security-policy  Replace client adaptive security policy
PATCH  /api/admin/clients/{id}/security-policy  Replace client adaptive security policy
```

Client policy lives in `client.settings.adaptive_security`; organization policy lives in organization metadata as `adaptive_security_policy` and overrides the client baseline for org actions. Policies can set MFA mode (`off`, `allow`, `required`, `adaptive`), risk challenge/block levels, trusted-device lifetime, IP/ASN lists, and per-action behavior (`off`, `notify`, `challenge`, `block`).

Sensitive actions are protected centrally: organization updates, member role/removal changes, org token issuance, client key rotation, service-account key rotation, SCIM token rotation, audit export, billing changes, and data export. When a protected endpoint returns `step_up_required`, call `/api/auth/step-up/verify` with the `challenge_token`, `factor` (`totp` or `recovery_code`), and code, then retry the original request with `X-Step-Up-Token`.

Risk signals are built from local history and optional provider data: new IP, new device, impossible travel, configured blocked/trusted/Tor CIDRs, ASN/VPN/Tor/proxy/bot flags, failed-login velocity, suspicious refresh-token reuse, and provider-supplied signals. High and critical security events are written to audit logs and therefore feed dashboards, exports, webhooks, and stream sinks.

Example client policy:

```json
{
  "mfa": {
    "mode": "adaptive",
    "challenge_risk_level": "medium",
    "block_risk_level": "critical",
    "remember_device_days": 30,
    "trusted_device_bypass": true,
    "enrollment_required": true
  },
  "risk": {
    "challenge_level": "medium",
    "block_level": "critical",
    "failed_velocity_threshold": 3,
    "blocked_ip_cidrs": ["203.0.113.10/32"],
    "tor_ip_cidrs": ["198.51.100.0/24"],
    "high_risk_asns": [64512]
  },
  "actions": {
    "client.key.rotate": { "mode": "block", "risk_block_level": "high" },
    "organization.member.role_change": { "mode": "challenge", "max_age_seconds": 600 },
    "audit.export": { "mode": "challenge", "risk_challenge_level": "medium" }
  }
}
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

Client settings can request direct or enterprise attestation during registration and reject credentials whose attestation format is `none` or outside an allowed list. Set `webauthn_attestation`, `webauthn_require_attestation`, and `webauthn_allowed_attestation_formats` with `PATCH /api/admin/clients/{id}` for regulated or managed-device deployments.

### Admin (Client Management)

```
POST /api/admin/auth/login                   Admin password login; returns MFA challenge or admin token
POST /api/admin/auth/sso                     Admin SSO assertion handoff; returns admin token
GET  /api/admin/users                        List admin users
POST /api/admin/users                        Create admin user with roles, scope, MFA, and optional SSO identity
POST /api/admin/clients                       Create a new client (tenant)
GET  /api/admin/clients                       List all clients
GET  /api/admin/clients/{id}                  Get client by ID
PATCH /api/admin/clients/{id}                 Update mutable client settings, origins, webhook URL, or status
POST /api/admin/clients/{id}/rotate-secret    Rotate client JWT secret
POST /api/admin/clients/{id}/rotate-api-key   Rotate client API key
POST /api/admin/clients/{id}/rotate-jwt       Alias for rotate-secret
POST /api/admin/clients/{id}/rotate-key       Alias for rotate-api-key
GET  /api/admin/clients/{id}/security-policy  Get client adaptive security policy
PUT  /api/admin/clients/{id}/security-policy  Replace client adaptive security policy
PATCH /api/admin/clients/{id}/security-policy Replace client adaptive security policy
GET  /api/admin/audit-events                  Query audit events
GET  /api/admin/audit-events/export           Export audit events as CSV or NDJSON
POST /api/admin/audit-events/legal-hold       Enable or disable legal hold for event IDs
POST /api/admin/audit-events/retention/purge  Dry-run or execute expired audit purge
GET  /api/admin/audit-events/chain/verify     Verify tamper-evident audit chain
```

Admin roles are `owner`, `security_admin`, `support_admin`, `billing_admin`, and `read_only_auditor`. Scopes can be `all`, one `client`, or one `organization`; scoped admins cannot access other clients. Every admin route records actor, target, before/after metadata, request ID, IP, and user agent.

`GET /api/admin/audit-events` and `/export` support `client_id`, `user_id`, `event_type`, `actor_type`, `actor_id`, `target_type`, `target_id`, `request_id`, `from`, `to`, `legal_hold`, and `limit` query parameters. The limit defaults to 50 and is capped at 10000. Export supports `format=csv` (default), `format=jsonl`, or `format=ndjson`. Exports include retention, legal hold, and hash-chain fields.

When `WEBHOOK_SIGNING_SECRET` is set, audit events are also delivered to the client's `webhook_url` as JSON with retries. Each delivery includes `X-AuthService-Event: audit.event`, `X-AuthService-Delivery`, `X-AuthService-Timestamp`, and `X-AuthService-Signature`. Verify the signature by computing `HMAC-SHA256(secret, timestamp + "." + raw_body)` and comparing it to the `v1=<hex>` header value.

### Health

```
GET /healthz                  Health check (returns {"status": "ok"})
GET /metrics                  Prometheus metrics
GET /api/admin/metrics        Prometheus metrics with admin auth
GET /.well-known/jwks.json    Public issuer JWKS (`X-API-Key` or `client_id` optionally narrows to one client)
```

Operational runbooks: `docs/operations-runbook.md`, `docs/multi-region-deployment.md`, and `docs/compliance-readiness.md`.

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

When CAPTCHA/bot protection is enabled, include `captcha_token` on signup and/or password login. Supported provider presets are Cloudflare Turnstile, hCaptcha, and reCAPTCHA; custom verification endpoints can be supplied with `CAPTCHA_VERIFY_URL`.

### B2B Organization Integration

Create an organization after the first user signs up:

```bash
curl -X POST http://localhost:8080/api/auth/organizations \
  -H "X-API-Key: raw-api-key-save-this" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Inc"}'
```

Invite a teammate:

```bash
curl -X POST http://localhost:8080/api/auth/organizations/{org_id}/invitations \
  -H "X-API-Key: raw-api-key-save-this" \
  -H "Authorization: Bearer $OWNER_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"teammate@acme.com","role":"member"}'
```

After the invited user accepts the returned one-time token, mint an organization-scoped access token:

```bash
curl -X POST http://localhost:8080/api/auth/organizations/{org_id}/token \
  -H "X-API-Key: raw-api-key-save-this" \
  -H "Authorization: Bearer $USER_ACCESS_TOKEN"
```

Downstream APIs should enforce `client_id` plus `org_id`, `org_role`, and `org_permissions`. Organization actions are audit logged with event types such as `organization_created`, `organization_invitation_created`, `organization_invitation_accepted`, `organization_member_updated`, and `organization_member_removed`.

### Machine-to-Machine Integration

Provision a service account under a client:

```bash
curl -X POST http://localhost:8080/api/admin/clients/{client_id}/service-accounts \
  -H "X-Admin-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{"name":"Billing Worker","scopes":["invoices:read","invoices:write"]}'
```

Exchange its credentials for a scoped access token:

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$SERVICE_ACCOUNT_ID" \
  -d "client_secret=$SERVICE_ACCOUNT_SECRET" \
  -d "scope=invoices:read"
```

Introspect a token:

```bash
curl -X POST http://localhost:8080/oauth/introspect \
  -u "$SERVICE_ACCOUNT_ID:$SERVICE_ACCOUNT_SECRET" \
  -d "token=$ACCESS_TOKEN"
```

Machine tokens include `token_use=client_credentials`, `service_account_id`, `service_account_name`, `scope`, and `scopes`. Downstream services should enforce the parent `client_id` plus required scopes.

### Enterprise SSO Integration

Create a generic OIDC connection for Okta, Azure AD, Google Workspace, or Ping:

```bash
curl -X POST http://localhost:8080/api/admin/clients/{client_id}/sso-connections \
  -H "X-Admin-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"Acme Okta",
    "slug":"acme-okta",
    "protocol":"oidc",
    "domains":["acme.com"],
    "oidc":{"issuer":"https://acme.okta.com/oauth2/default","client_id":"...","client_secret":"..."}
  }'
```

Create a SAML connection and give the IdP the generated metadata URL:

```bash
curl -X POST http://localhost:8080/api/admin/clients/{client_id}/sso-connections \
  -H "X-Admin-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"Acme SAML",
    "protocol":"saml",
    "domains":["acme.com"],
    "saml":{"idp_entity_id":"https://idp.example.com/metadata","idp_sso_url":"https://idp.example.com/sso","idp_certificate":"BASE64_DER_CERT"}
  }'
```

Start login with `GET /api/auth/sso?domain=acme.com` or `GET /api/auth/sso/{connection_id_or_slug}` using the client API key. Successful SSO creates or links a user by provider subject and returns the same access/refresh token flow as other login methods.

### SCIM Directory Integration

Provision a SCIM directory and save the returned token once:

```bash
curl -X POST http://localhost:8080/api/admin/clients/{client_id}/scim-directories \
  -H "X-Admin-Key: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Directory","domains":["acme.com"]}'
```

Configure your IdP SCIM base URL as:

```text
https://auth.example.com/scim/v2/{directory_id}
```

Use the returned token as the bearer token. AuthService supports SCIM `Users` and `Groups`, including `POST`, `GET`, `PUT`, `PATCH`, and `DELETE`; user provisioning creates or links a local user by email and SCIM `externalId`.

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

The REST E2E suite includes auth lifecycle, refresh rotation, logout, email verification, magic links, TOTP, OAuth state/PKCE, passkey route handling, organization RBAC, machine-to-machine client credentials, audit queries, client admin, and Redis-required feature failures.

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
    Email                   string   `json:"email"`
    Role                    string   `json:"role"`
    EmailVerified           bool     `json:"email_verified"`
    ClientID                string   `json:"client_id"`
    TokenUse                string   `json:"token_use,omitempty"`
    Scope                   string   `json:"scope,omitempty"`
    Scopes                  []string `json:"scopes,omitempty"`
    ServiceAccountID        string   `json:"service_account_id,omitempty"`
    ServiceAccountName      string   `json:"service_account_name,omitempty"`
    OrganizationID          string   `json:"org_id,omitempty"`
    OrganizationSlug        string   `json:"org_slug,omitempty"`
    OrganizationRole        string   `json:"org_role,omitempty"`
    OrganizationPermissions []string `json:"org_permissions,omitempty"`
}
```

The `UserID()` method returns the `sub` (Subject) claim. For user tokens it is the user's UUID; for machine tokens it is the service account ID. Organization fields are present only on tokens minted by `POST /api/auth/organizations/{org_id}/token`.

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
  string org_id = 8;
  string org_slug = 9;
  string org_role = 10;
  repeated string org_permissions = 11;
  string token_use = 12;
  string scope = 13;
  repeated string scopes = 14;
  string service_account_id = 15;
  string service_account_name = 16;
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
      organization.go           Organization, membership, invitation, role, and permission entities
      service_account.go        Service account and scoped key entities
      enterprise_sso.go         Enterprise SAML/OIDC connection and identity entities
      scim.go                   SCIM directory, user, and group entities
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
      organization_service.go   Organization RBAC, invitations, member management, and org token issuance
      m2m_service.go            OAuth2 client credentials, service-account keys, and introspection
      enterprise_sso_service.go Enterprise SSO setup, OIDC callbacks, SAML metadata, and login completion
      scim_service.go           SCIM directory token, user provisioning, group sync, and deprovisioning logic
    infrastructure/
      postgres/                 PostgreSQL repository implementations
        migrations/             SQL migration files (auto-run on startup)
          008_add_jwks_signing_keys.sql   token_mode + signing key tables
          009_create_organizations.sql    organizations, memberships, invitations
          010_create_service_accounts.sql service accounts and hashed scoped keys
          011_create_enterprise_sso.sql   SAML/OIDC connections and linked identities
          012_create_scim.sql             SCIM directories, users, and groups
        signing_key_repo.go     Signing key persistence for JWKS/RS256
        organization_repo.go    Organization RBAC persistence
        service_account_repo.go Service account persistence
        enterprise_sso_repo.go  Enterprise SSO connection and identity persistence
        scim_repo.go            SCIM directory sync persistence
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
        organization_handler.go Organization and member/invitation handlers
        m2m_handler.go          Client credentials token/introspection and service-account admin handlers
        enterprise_sso_handler.go Enterprise SSO admin, begin, callback, and metadata handlers
        scim_handler.go         SCIM 2.0 bearer-token Users/Groups handlers
        client_handler.go       Admin client management handlers
      grpc/                     gRPC server implementation
  pkg/
    jwtvalidator/               Public JWT validation package
      validator.go              Token parsing and HTTP middleware
      claims.go                 Claims type definition
      context.go                Context helpers for claims storage
  sdks/
    README.md                   Mobile SDK usage notes
    node/authservice-node.js     Node 18+ SDK for SSR, API routes, workers, and M2M
    react/authservice-react.js   React/Next.js provider, hooks, and UI components
    ios/AuthServiceClient.swift Swift URLSession client with token-store hooks
    android/com/authservice/sdk/AuthServiceClient.java
                                Android Java client with token-store hooks
  public/                       Static browser shells
    authservice.js              Dependency-free browser SDK and embeddable widgets
    login.html                  Login, OAuth, magic link, TOTP, and passkey login
    signup.html                 Signup and passkey registration
    portal.html                 Admin console and customer account portal
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
