# Auth Error Contract

AuthService error responses keep the legacy lowercase `code`/`error` fields for
existing clients and add canonical app-facing metadata:

```json
{
  "error": "The email or password is incorrect.",
  "code": "invalid_credentials",
  "message": "The email or password is incorrect.",
  "auth_code": "AUTH_INVALID_CREDENTIALS",
  "user_message": "The email or password is incorrect.",
  "retryable": false,
  "request_id": "req_123"
}
```

Clients should render `user_message`, branch on `auth_code`, and use `retryable`
for retry affordances. The lowercase `code` remains the provider/service code
for compatibility and diagnostics.

Required guarantees:

- Login failures for unknown email and wrong password both use
  `AUTH_INVALID_CREDENTIALS` with the copy "The email or password is incorrect."
- Password reset requests are enumeration-safe: known and unknown email
  responses are the same success payload; only validation, service
  configuration, and rate limits return distinct errors.
- OAuth callback redirects use canonical `AUTH_OAUTH_*` values in the `error`
  query parameter and never forward raw provider error strings.
- Auth error logs are structured as `auth.error` events and omit request bodies,
  tokens, passwords, OTPs, cookies, provider payloads, and raw user identifiers.
