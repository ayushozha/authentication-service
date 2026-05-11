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

## Password Reset, MFA, and Passkeys

Native apps can use the SDK for account recovery and MFA flows:

```java
client.forgotPassword(email);
client.resetPassword(resetToken, newPassword);

AuthServiceClient.AuthServiceResponse setup = client.setupTOTP();
client.enableTOTP(code);

AuthServiceClient.AuthServiceResponse login = client.login(email, password);
if (login.requires2FA()) {
    client.verifyTOTP(login.getTwoFactorToken(), code, true, "Pixel");
}
```

Passkey support is exposed as begin/finish helpers. Use Android Credential Manager or the FIDO2 API to satisfy the returned `publicKey` challenge, serialize the platform credential response as WebAuthn JSON, then send it back:

```java
AuthServiceClient.AuthServiceResponse options = client.beginPasskeyLogin();
client.finishPasskeyLogin(sessionId, credentialJson);
```

## Deep Links

Use `session_mode=token` for native flows. Configure OAuth, magic-link, and SSO callback URLs to land on an app-owned HTTPS universal link or verified app link, then pass the returned token or code into the SDK flow that matches the route.
