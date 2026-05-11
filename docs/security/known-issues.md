# Security follow-ups (audit, 2026-05-11)

Tonight's commit lands two safe hardening changes:

- **Rate limiter fail-closed.** `internal/infrastructure/redis/rate_limiter.go`
  `Allow()` now returns `(false, 0, err)` when Redis is unreachable, instead
  of silently returning `(true, limit, nil)`. Set `RATE_LIMITER_FAIL_OPEN=true`
  to restore old behavior for local dev. Without this, an attacker could
  evict Redis (or wait for an outage) and skip login throttling + lockout.
- **`ALLOW_ORIGIN` default change.** `cmd/server/config.go` no longer
  defaults to `"*"`. Production sets `ALLOW_ORIGIN` explicitly via env;
  the default protects newly-spun-up instances from accidental wildcard.

The audit (2026-05-11) flagged the items below as needing follow-up commits.
Each has a non-trivial migration or test impact and was not safe to land in
the same change as the iOS API-key removal.

## CRITICAL — fix before App Store launch

### 1. Account enumeration on signup
`internal/interfaces/rest/auth_handler.go:67` returns `409
duplicate_email` when an email is already registered. This lets anyone
probe which emails have Paervo / TapDue / Anchrix accounts.

**Fix:** require email verification on signup. Return a generic `201
{verification_required: true}` whether the email is new or duplicate; the
duplicate path additionally fires a "someone tried to sign up with your
email" notification to the existing user. Update `e2e_test.go:204` to
expect the generic response.

### 2. TOTP secrets stored plaintext
`internal/infrastructure/postgres/user_repo.go:137` writes
`users.totp_secret` unencrypted. A DB read = MFA bypass for every user.

**Fix:** add `MFA_KEK` env var (32-byte key, generated via
`openssl rand -base64 32` and stored in Coolify). Encrypt with AES-GCM
at write, decrypt at read. Forward-only migration:
```
ALTER TABLE users ADD COLUMN totp_secret_v2 bytea;
-- background-migrate plaintext -> v2 via a one-shot job
ALTER TABLE users DROP COLUMN totp_secret;
ALTER TABLE users RENAME COLUMN totp_secret_v2 TO totp_secret;
```
Same pattern fits `pkg/jwtvalidator` shared-secret blobs.

### 3. Per-client JWT + RSA signing keys stored plaintext
`internal/infrastructure/postgres/client_repo.go:27` (`jwt_secret`) and
`signing_key_repo.go:21` (`private_key_pem`).

**Fix:** same envelope-encryption pattern as #2 with a separate
`CLIENT_KEK` so MFA and signing have isolated key material. Forge a key
rotation runbook before flipping over so backends using
`pkg/jwtvalidator` get a heads-up.

### 4. Spoofable client IP
`internal/interfaces/rest/helpers.go` `clientIP()` trusts
`X-Forwarded-For` from anyone. All per-IP rate-limit keys (login, signup,
magic link) are trivially bypassed by setting the header to a random IP.

**Fix:** introduce `TRUSTED_PROXY_IPS` env var (CIDRs allowed). Only
trust XFF when `r.RemoteAddr` is inside the list. Walk the XFF list
right-to-left, returning the right-most untrusted hop. Tests
(`e2e_test.go:229`) need `TRUSTED_PROXY_IPS=127.0.0.1` injected in
`setupEnv` to keep spoofing in test-only contexts.

## HIGH — before App Store launch

### 5. Email verification not required for login
`internal/application/auth_service.go:513` allows any active user to
log in, even with `email_verified = false`. Combined with auto-login on
signup, this means anyone can sign up with any email and access the
account without owning the inbox.

**Fix:** add per-client `RequireEmailVerified bool` policy flag.
Block login with `domain.ErrEmailNotVerified` when the user hasn't
verified. Paervo + TapDue should be opt-in `true` at app-store launch.

### 6. Account-lockout DoS
`rate_limiter.go:59-60` locks `email` globally after 5 wrong attempts.
An attacker spraying wrong passwords across IPs can lock real users out
for 30 minutes at zero cost.

**Fix:** key the lockout on `client_id + ip` (so the attacker locks
their own IP, not the user). Add exponential backoff per-IP. Drop the
hard lockout in favor of CAPTCHA after threshold for known good emails.

### 7. Admin endpoints CORS wildcards
`audit_handler.go:36,69,131,160,191`, `client_handler.go:32,83`,
`scim_handler.go:29`, `admin_handler.go:73` literally hardcode
`setCorsHeaders(w, "*", false)`. Plus no rate-limit middleware on
`/api/admin/*`. A leaked admin key + wildcard CORS = scriptable admin
access from any origin.

**Fix:** introduce `ADMIN_ALLOWED_ORIGINS` env var, pass through to
each admin handler instead of `"*"`. Add a per-IP rate limiter on
admin routes (10 req/min).

### 8. Apple JWKS no caching
`internal/application/oauth_service.go:459` fetches
`https://appleid.apple.com/auth/keys` on every Apple-login request.
Apple outage = Apple-login outage. Also a small DoS vector against
Apple.

**Fix:** in-memory LRU with 24h TTL and a single in-flight fetch
(borrow `pkg/jwtvalidator`'s caching code).

### 9. Phantom Go toolchain version
`go.mod:3` declares `go 1.26.3` (Go 1.26 does not exist as of 2026-05).
Pin a real version (1.23.4 LTS or 1.24.x) and confirm the production
image's `golang:1.X` base tag matches.

## NICE — defer

- `admin_middleware.go` admin-key check is not constant-time.
- `Pool.MaxOpenConns(10)` is likely undersized for iOS + web combined
  production load.
- Document `SameSite=none` / `Secure` cookie defaults explicitly in
  the README.
- Add CSRF protection on state-changing endpoints that accept cookies
  (browser flow only; iOS is Bearer-based).
