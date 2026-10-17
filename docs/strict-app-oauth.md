# Google OAuth for confidential app backends

This opt-in contract binds one application's OAuth redirect code to a
backend-held PKCE verifier. It reuses the hosted identity service and its
existing Google provider, client API keys, callback routing, access/refresh
tokens and TTLs. It creates no new provider registration and changes no global
session policy. Deployment and client/provider registration remain separate
operator actions.

For an auth-only rollout, temporarily set the repository variable
`AUTH_DEPLOY_DEPENDENTS=false` before merging. The auth deployment and its health
checks still run; dependent application restarts are skipped. Restore the prior
variable value after the deployment completes. Leaving the variable unset
preserves the existing dependent cascade.

## Begin and capability check

The app backend generates a fresh random RFC 7636 verifier (43-128 unreserved
ASCII characters), retains it securely for one browser login, and calculates
`BASE64URL(SHA256(ASCII(verifier)))` without padding. The browser must not choose
the verifier. Authenticate this server-to-server request with the client's
confidential `X-API-Key`:

```http
GET /api/auth/oauth/google?session_mode=token&app_code_challenge=<S256-challenge>&app_code_challenge_method=S256&identity_policy=provider_subject
X-API-Key: <server-only-client-key>
```

All three app binding options must be valid and present together, or absent
together. App binding is currently supported only for Google. Partial options,
plain PKCE, malformed challenges or an unknown identity policy return `400
invalid_app_oauth_binding`.

After accepting and caching a strict transaction, a successful begin returns:

```http
HTTP/1.1 302 Found
X-App-Session-Binding: S256
Location: https://accounts.google.com/...
```

The app must check the binding header **before** redirecting its browser. Older
deployments ignore unknown query options and do not return this header; the app
must fail closed against them. Never follow an upstream redirect while carrying
the confidential API key.

Strict provider state is an opaque random handle. Its cached server-side
payload retains the provider verifier, app challenge, identity policy, client,
provider and nonce for ten minutes. The provider callback atomically consumes
that state, obtains and validates the provider profile, then redirects to the
client's existing allowlisted `settings.ui.oauth_redirect_url` with a two-minute
`auth_code`. The registered provider callback and the application's callback are
different URLs. No token is placed in either redirect URL.

## Exchange

The app callback must require its own pending browser login, retrieve that
login's backend-generated verifier, then exchange the code server-side:

```http
POST /api/auth/redirect/exchange
Content-Type: application/json

{"code":"<received-auth-code>","code_verifier":"<same-backend-held-verifier>"}
```

The challenge was bound to the code before the redirect. A missing, malformed
or mismatched verifier returns the existing generic `400` invalid-code error
without consuming the code. After verification, code consumption is atomic;
only one concurrent exchange succeeds. The production Redis implementation uses
an atomic Lua GET/DEL operation, without adding a Redis 6.2 GETDEL requirement.
Bound codes use an `app_s256.` prefix and an isolated
`auth_redirect_bound:<hash>` cache namespace. Old deployments cannot read these
credentials through their unbound legacy exchange path during mixed-version
rollouts or rollback. Codes remain opaque to the app. Legacy codes retain their
existing namespace.

A successful strict response includes the existing token fields plus:

```json
{
  "access_token": "<hosted-access-token>",
  "refresh_token": "<hosted-refresh-token-in-token-mode>",
  "token_type": "Bearer",
  "expires_in": 900,
  "app_session_binding": "S256",
  "identity_policy": "provider_subject",
  "provider": "google",
  "provider_subject": "<stable-Google-user-ID>"
}
```

The TTL shown is illustrative; it is controlled by the existing deployment.
The private cached challenge is not returned. The app must require all four
strict metadata fields, verify the hosted token and expected client through the
existing identity validation contract, and use the stable provider subject
namespaced by issuer/client/provider for its own account mapping. Never use an
email or an unverified decoded token as identity. The app's persistent session
and immediate logout revocation are separate responsibilities; this change does
not extend hosted refresh TTLs.

## Subject policy and compatibility

For `identity_policy=provider_subject`, an existing `(client, provider,
provider_subject)` link resolves its existing owner. An unseen provider subject
creates a new user and link; it never selects or merges a user by email. If the
link insertion fails, the user creation is rolled back in the same SQL statement,
so a transient failure cannot strand the email and prevent a later strict retry.
If the current unique-email constraint prevents that creation, login fails with
`provider_subject_email_conflict` internally, returning the existing generic
OAuth failure redirect. No account is linked and no tokens are issued. Provider
link errors and conflicting concurrent link ownership also fail closed.

This policy does not retroactively split historical accounts that were linked
under legacy email behavior. Applications requiring separate provider identities
must map the returned `provider_subject`, not just the hosted user's UUID.

Clients that omit all app options retain the existing behavior, including the
legacy account-linking policy. Their exchange response omits all four strict
metadata fields and needs no app verifier. Existing provider states and legacy
redirect cache payloads remain readable. Atomic state/code consumption improves
concurrent replay handling for both forms. This is not an Apple or native OIDC
implementation.

## Focused verification

```powershell
go test ./internal/application ./internal/interfaces/rest ./internal/infrastructure/redis ./internal/infrastructure/postgres
go vet ./internal/application ./internal/interfaces/rest ./internal/infrastructure/redis ./internal/infrastructure/postgres
```

`TestAppOAuth*` uses local provider and cache fixtures to verify complete opt-in,
opaque state, verifier rejection without consumption, one-winner concurrent
exchange, strict email collision rejection, stable-subject resolution after an
email change, legacy compatibility, state replay and non-successful userinfo
rejection. `TestGetDelConsumesAtomically` additionally requires a dedicated local
Redis set through `TEST_REDIS_URL`; without that variable it explicitly skips.
These tests do not prove a configured production Google login.
`TestProviderSubjectCreationRollsBackFailedLinkAndCanRetry` additionally requires
`TEST_DATABASE_URL` pointing to a dedicated local PostgreSQL database. It creates
an isolated temporary schema and verifies atomic rollback on a real link
constraint failure, retry, email collision rejection, and unchanged original
provider ownership. It explicitly skips when the variable is absent.

Recorded local results, October 17, 2026: `go test ./... -count=1` and
`go vet ./...` passed in a `golang:1.26` container. The eight new strict-flow,
Redis and PostgreSQL tests also passed under `go test -race` with dedicated
local Redis 7 and PostgreSQL 16 containers; none of those eight skipped. Four
existing browser tests explicitly skipped because the Go container has no
Chrome/Chromium. No hosted service, OAuth registration, client configuration or
global TTL was changed, and a real Google consent/callback was not exercised.
