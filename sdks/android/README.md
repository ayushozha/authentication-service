# AuthService Android SDK Starter

This directory is a JVM-testable starter for the dependency-free Java client.

## Test Harness

Run unit tests from this directory when a JDK and Gradle are available:

```bash
gradle test
```

The harness validates token-store behavior without requiring an Android emulator or network service. Android app teams can move `com/authservice/sdk/AuthServiceClient.java` into an Android library module or publish it as a small Java/Kotlin artifact.

## Secure Storage

The SDK accepts any `AuthServiceClient.TokenStore`. In production Android apps, back that interface with encrypted storage, for example AndroidX Security `EncryptedSharedPreferences` or an Android Keystore-backed store.

## Deep Links

Use `session_mode=token` for native flows. Configure OAuth, magic-link, and SSO callback URLs to land on an app-owned HTTPS universal link or verified app link, then pass the returned token or code into the SDK flow that matches the route.
