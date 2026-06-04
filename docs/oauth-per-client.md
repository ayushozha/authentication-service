# Per-client OAuth (hybrid)

Social-login OAuth (GitHub / Google / Microsoft) resolves provider credentials
through a two-tier resolver, mirroring the email transport design:

1. **Per-client override** — a row in `client_oauth_configs` keyed by
   `(client_id, provider)` carries that client's own OAuth application
   credentials: `client_id_plain` + an AES-256-GCM-encrypted `client_secret`
   (+ optional space/comma-separated `scopes`, `enabled` flag). When a usable,
   enabled row exists it is used, so the provider's consent screen shows the
   client's own app name + logo.
2. **Global fallback** — built from `GITHUB_CLIENT_ID` / `GOOGLE_CLIENT_ID` /
   `MICROSOFT_CLIENT_ID` (+ secrets) env vars. Used for any client without a
   per-client row.

If neither exists for the requested provider, the begin endpoint returns
`404 oauth_provider_not_configured`.

Apple is intentionally **not** per-client-configurable (it uses a
private-key/JWT client-secret flow that doesn't fit the id+secret model);
Apple stays global-env-only.

## Shared callback URL

The callback URL is **never stored** — it is always derived from `BASE_URL`:

```
https://<BASE_URL>/api/auth/oauth/<provider>/callback
```

Every per-client OAuth App must register that *same* callback. The callback
handler recovers the originating client from the signed PKCE `state` (which
carries `client_id`), then re-resolves the per-client credentials to complete
the token exchange. This is why a single auth service + one callback URL can
serve unlimited independently-branded client OAuth apps.

## Secret encryption

OAuth client secrets are encrypted at rest with the same AES-256-GCM cipher
used for per-client email API keys, under the `EMAIL_CONFIG_KMS_KEY` master
key. Rotating that key invalidates every stored secret (email **and** OAuth).
Cleartext secrets never sit on disk and are never returned by the admin API
(reads are redacted to `secret_last_four`).

## Admin API

All under `RequireAdminKey` (`X-Admin-Key`):

| Method | Path | Body |
|---|---|---|
| `GET` | `/api/admin/clients/{id}/oauth-config` | — (lists all providers for the client) |
| `GET` | `/api/admin/clients/{id}/oauth-config/{provider}` | — |
| `PUT` | `/api/admin/clients/{id}/oauth-config/{provider}` | `{ "oauth_client_id", "client_secret", "scopes"?, "enabled"? }` |
| `DELETE` | `/api/admin/clients/{id}/oauth-config/{provider}` | — |

`provider` ∈ `github` \| `google` \| `microsoft`. On `PUT`, `oauth_client_id`
and `client_secret` must be supplied together. Responses redact the secret.

Example — give Crucible its own GitHub OAuth App:

```bash
curl -X PUT https://authservice.ayushojha.com/api/admin/clients/<client_id>/oauth-config/github \
  -H "X-Admin-Key: <ADMIN_KEY>" -H "Content-Type: application/json" \
  -d '{"oauth_client_id":"Iv23li...","client_secret":"<github_app_secret>"}'
```

## Login flow (frontend)

The begin endpoint requires the client's `X-API-Key` header, so it cannot be a
raw browser navigation. Front ends proxy it server-side: call
`GET /api/auth/oauth/<provider>` with `X-API-Key`, read the `302 Location`, and
redirect the browser to it. The shared callback then bounces back to
`BASE_URL/login.html?auth_code=...`, which the SPA exchanges via
`POST /api/auth/redirect/exchange`.

## Code map

- `internal/infrastructure/postgres/migrations/019_create_client_oauth_configs.sql`
- `internal/domain/client_oauth_config.go`
- `internal/infrastructure/postgres/client_oauth_config_repo.go`
- `internal/application/client_oauth_config_service.go` (admin CRUD)
- `internal/application/oauth_service.go` — `ResolveProviderConfig`,
  `BuildProviderConfig`, `SetOAuthResolution`, `SetPerClientOAuthStore`
- `internal/interfaces/rest/oauth_handler.go` (route registration + per-request resolution)
- `internal/interfaces/rest/client_handler.go` — `handleOAuthConfig`
