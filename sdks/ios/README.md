# AuthService iOS SDK Starter

This directory is a Swift Package for native iOS and macOS clients.

## Test Harness

Run from the repository root or this directory:

```bash
swift test --package-path sdks/ios
```

The XCTest target validates configuration defaults and token-store behavior without requiring a network service.

## Secure Storage

Use `KeychainAuthServiceTokenStore` for production apps:

```swift
let tokenStore = KeychainAuthServiceTokenStore(namespace: "com.example.app")
let auth = AuthServiceClient(config: config, tokenStore: tokenStore)
```

The in-memory store is only intended for tests and short-lived sessions.

## Deep Links

Use `session_mode=token` for native flows. Configure OAuth, magic-link, and SSO callback URLs to open an app-owned universal link, then hand the callback token or code to the matching AuthService route.
