# AuthService iOS SDK Starter

This directory is a Swift Package for native iOS and macOS clients.

## Test Harness

Run from the repository root or this directory:

```bash
swift test --package-path sdks/ios
```

The XCTest target validates configuration defaults and token-store behavior without requiring a network service.

## Password Reset

Native apps can start and complete the hosted reset flow through the SDK:

```swift
try await auth.forgotPassword(email: email)
try await auth.resetPassword(token: resetToken, newPassword: newPassword)
```

## Email Verification

Signup emails point users to the hosted verification page. Native apps that capture the verification token from a universal link can complete the same flow directly:

```swift
try await auth.verifyEmail(token: verifyToken)
try await auth.resendVerification()
```

## MFA and Passkeys

The SDK exposes native app endpoints for TOTP setup, challenge completion, recovery codes, and passkey ceremonies:

```swift
let setup = try await auth.setupTOTP()
try await auth.enableTOTP(code: code)
let session = try await auth.verifyTOTP(twoFactorToken: challengeToken, code: code)

let passkeyOptions = try await auth.beginPasskeyLogin()
// Use AuthenticationServices to satisfy passkeyOptions.publicKey, then send the WebAuthn JSON response:
let session = try await auth.finishPasskeyLogin(sessionID: passkeyOptions.sessionID!, credentialJSON: credentialJSON)
```

## Secure Storage

Use `KeychainAuthServiceTokenStore` for production apps:

```swift
let tokenStore = KeychainAuthServiceTokenStore(namespace: "com.example.app")
let auth = AuthServiceClient(config: config, tokenStore: tokenStore)
```

The in-memory store is only intended for tests and short-lived sessions.

## Deep Links

Use `session_mode=token` for native flows. Configure OAuth, magic-link, and SSO callback URLs to open an app-owned universal link, then hand the callback token or code to the matching AuthService route.
