# Email transport (hybrid)

The auth service ships outbound mail (password reset, email verify, magic link)
through a two-tier resolver:

1. **Per-client override** — a row in `client_email_configs` keyed by
   `client_id` may carry its own Resend API key (encrypted at rest),
   from-address, reply-to, and URL templates. When present, the router uses
   that transport.
2. **Global fallback** — built from `RESEND_API_KEY` + `EMAIL_FROM` (+
   optional `EMAIL_REPLY_TO`). Used for any client that hasn't configured an
   override.

Both can be left unconfigured — the service degrades to "email sending not
configured" instead of erroring; rate-limited flows already swallow that to
preserve enumeration resistance.

## Env vars

| Var | Purpose |
|---|---|
| `RESEND_API_KEY` | Global fallback Resend key. |
| `EMAIL_FROM` | Global fallback from-address (e.g. `Auth Service <noreply@your.com>`). |
| `EMAIL_REPLY_TO` | Optional reply-to on global fallback. |
| `EMAIL_CONFIG_KMS_KEY` | **Required for per-client overrides.** Base64-encoded 32-byte AES-256-GCM master key. Encrypts client-supplied provider API keys at rest. Generate: `openssl rand -base64 32`. |

## Admin API

All endpoints require `X-Admin-Key`. Provider API keys are write-only over the
wire — `GET` returns only the redacted last-4 characters.

### `GET /api/admin/clients/{id}/email-config`

`404` if no override exists, else:

```json
{
  "client_id": "…",
  "provider": "resend",
  "has_api_key": true,
  "api_key_last_four": "wXyZ",
  "from_address": "noreply@paervo.com",
  "from_name": "Paervo",
  "reply_to": "support@paervo.com",
  "reset_password_url_template": "https://paervo.com/reset-password?t={token}",
  "verify_email_url_template":   "",
  "magic_link_url_template":     ""
}
```

### `PUT /api/admin/clients/{id}/email-config`

Field-level upsert — unset fields preserve current values. Send `"api_key": ""`
to clear the stored credential without deleting the row.

```json
{
  "provider": "resend",
  "api_key": "re_live_…",
  "from_address": "noreply@paervo.com",
  "from_name": "Paervo",
  "reply_to": "support@paervo.com",
  "reset_password_url_template": "https://paervo.com/reset-password?t={token}",
  "verify_email_url_template":   "https://paervo.com/verify-email?t={token}",
  "magic_link_url_template":     "https://paervo.com/magic?t={token}"
}
```

A row that overrides transport must carry **both** `api_key` and
`from_address`; setting one without the other returns `400 invalid email
configuration`. URL-template-only rows (no key, no from) are valid — they
rewrite link URLs while letting the global fallback handle delivery.

### `DELETE /api/admin/clients/{id}/email-config`

`204` — clears the override; client falls back to global env-var transport.

## URL templates

The `{token}` placeholder is the only substitution. Token is URL-escaped on
the way out, so static query strings around it are preserved
(`https://paervo.com/reset?utm=auth&t={token}` works).

Default URLs when no template is set:

- `password_reset`: `BASE_URL/reset-password.html?token=…`
- `verify_email`:   `BASE_URL/verify-email.html?token=…`
- `magic_link`:     `BASE_URL/api/auth/magic-link/verify?token=…`

## Storage

`client_email_configs` (migration `018_create_client_email_configs.sql`):

| Column | Type | Notes |
|---|---|---|
| `client_id` | UUID PK | FK → `clients(id)` ON DELETE CASCADE |
| `provider` | TEXT | Currently only `'resend'` (constraint). |
| `api_key_ciphertext` | BYTEA | AES-256-GCM output. |
| `api_key_nonce` | BYTEA | 12-byte nonce per row. |
| `api_key_last_four` | TEXT | Displayed in admin GET. |
| `from_address` / `from_name` / `reply_to` | TEXT | Sender identity. |
| `*_url_template` | TEXT | `{token}` substitution; empty = use default. |

Rotating `EMAIL_CONFIG_KMS_KEY` invalidates every existing ciphertext; admins
must re-PUT each per-client API key.

## Adding a new provider

1. Implement `email.resendTransport`'s contract (`Send`,
   `SendVerifyEmail`, `SendPasswordReset`, `SendMagicLink`) for the provider.
2. Extend `RouterMailer.transportFor` to branch on `cfg.Provider`.
3. Drop the `email_provider_supported` CHECK in a new migration and add the
   provider name to the allowed set.
