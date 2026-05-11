# Auth Session Contract

AuthService supports two explicit refresh-token transports. Clients should choose one per auth request and keep using it for refresh/logout.

## JSON Transport

Use this for native apps, server-side proxies, CLIs, and SDKs that can store refresh tokens securely.

Request login/signup/refresh with:

```json
{
  "token_transport": "json"
}
```

`session_mode: "token"` remains a backwards-compatible alias.

Successful login/signup/refresh responses include:

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh": {
    "transport": "json",
    "expires_in": 604800
  },
  "user": {}
}
```

TOTP verification, recovery-code verification, and passkey login finish use the same transport contract. Send `token_transport: "json"` or legacy `session_mode: "token"` on those requests when the client expects a JSON refresh token.

Refresh with:

```json
{
  "token_transport": "json",
  "refresh_token": "..."
}
```

`refreshToken` is accepted as a compatibility alias for `refresh_token`.

## Cookie Transport

Use this for browser flows that want the refresh credential stored as an HttpOnly cookie.

Request login/signup/refresh with:

```json
{
  "token_transport": "cookie"
}
```

If `token_transport` and `session_mode` are omitted, cookie transport is the default.

Successful login/signup/refresh responses include:

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh": {
    "transport": "cookie",
    "cookie_name": "auth_refresh",
    "expires_in": 604800
  },
  "user": {}
}
```

TOTP verification, recovery-code verification, and passkey login finish also include `refresh.transport` metadata and either set `auth_refresh` or return `refresh_token` depending on the requested transport.

The response also sends:

```text
Set-Cookie: auth_refresh=...; Path=/; Max-Age=604800; HttpOnly
```

For HTTPS deployments, the default cookie policy is `SameSite=None; Secure`. For local HTTP development, it falls back to `SameSite=Lax` without `Secure`. Override with `COOKIE_SAMESITE`, `COOKIE_SECURE`, and `COOKIE_DOMAIN`.

Refresh can use an empty JSON body when the cookie is present:

```json
{}
```

If neither a body token nor the `auth_refresh` cookie is present, `/api/auth/refresh` returns `400` with code `refresh_token_missing`.

## Error Shape

Errors keep the legacy human-readable `error` string and add stable agent/client fields:

```json
{
  "error": "Invalid email or password.",
  "code": "invalid_credentials",
  "message": "Invalid email or password.",
  "request_id": "optional-request-id"
}
```

Important auth codes include:

- `missing_api_key`
- `invalid_api_key`
- `invalid_credentials`
- `invalid_email`
- `refresh_token_missing`
- `invalid_refresh_token`
- `rate_limited`
- `account_locked`

Rate-limited responses include `Retry-After` when the server knows the retry window.
