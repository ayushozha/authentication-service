# Passkey QA Checklist

Use this checklist before claiming production passkey readiness for a new client or relying-party configuration.

## Automated Coverage

- Chrome virtual authenticator registration and login.
- Rejected signature path.
- Public login page on desktop, iOS-sized, and Android-sized browser profiles.
- Conditional UI/autofill smoke coverage through `/login.html` and `/authservice.js`.

## Manual Cross-Device Matrix

| Flow | Safari iOS | Chrome Android | Chrome Desktop | Safari macOS | Edge/Chrome Windows |
|---|---|---|---|---|---|
| Platform passkey registration | Required | Required | Required | Required | Required |
| Cross-device QR login | Required | Required | Required | Required | Optional |
| Conditional UI/autofill login | Required | Required | Required | Required | Optional |
| Recovery-code fallback after MFA challenge | Required | Required | Required | Required | Required |
| Attestation policy rejection when `webauthn_require_attestation=true` | Client-specific | Client-specific | Client-specific | Client-specific | Client-specific |

## Release Gate

1. Confirm `WEBAUTHN_RP_ID` and `WEBAUTHN_RP_ORIGIN` match the production domain.
2. Confirm client settings override RP values only for the intended tenant.
3. Register at least one platform passkey and one roaming/cross-device passkey.
4. Verify login with conditional UI/autofill enabled.
5. Verify account recovery through TOTP recovery codes.
6. Export audit events for `passkey_registered`, `login_success`, and `passkey_deleted`.
