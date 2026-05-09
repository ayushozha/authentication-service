# AuthService SDKs

Starter native clients for teams that want to call AuthService without hand-writing every request.

## Browser JavaScript

`public/authservice.js` is served by AuthService itself and exposes token/session helpers, active-session listing/revocation, WebAuthn/passkey helpers, TOTP/recovery-code helpers, organization helpers, and embeddable sign-in/user widgets.

## React / Next.js

`sdks/react/authservice-react.js` provides dependency-free React bindings around `authservice.js`: `AuthServiceProvider`, `useAuthService`, `SignIn`, `UserButton`, and `OrganizationList`.

```js
import React from "react";
import createAuthServiceReact from "./authservice-react";

const {
  AuthServiceProvider,
  SignIn,
  UserButton
} = createAuthServiceReact(React, window.AuthService);

export default function App() {
  return (
    <AuthServiceProvider baseUrl="https://auth.example.com" apiKey="raw-api-key-save-this">
      <UserButton />
      <SignIn />
    </AuthServiceProvider>
  );
}
```

## Node.js

`sdks/node/authservice-node.js` is a dependency-free Node 18+ SDK for server-side rendering, API routes, workers, and service-to-service flows.

```js
const { createClient } = require("./authservice-node");

const auth = createClient({
  baseUrl: "https://auth.example.com",
  apiKey: "raw-api-key-save-this"
});

const session = await auth.login({
  email: "user@example.com",
  password: "ValidPass123!"
});

const user = await auth.me();
```

## iOS Swift

`sdks/ios` is a Swift Package with a dependency-free `AuthServiceClient` built on `Foundation.URLSession`, an in-memory test token store, a Keychain-backed token store helper, and XCTest fixtures.

```swift
let auth = AuthServiceClient(
    config: AuthServiceConfig(
        baseURL: URL(string: "https://auth.example.com")!,
        apiKey: "raw-api-key-save-this"
    )
)

let session = try await auth.signup(
    email: "user@example.com",
    password: "ValidPass123!",
    displayName: "User"
)

let user = try await auth.me()
```

Use `KeychainAuthServiceTokenStore` for production apps. The default store is in-memory and intended for tests or short-lived sessions.

## Android Java

`sdks/android` is a Gradle/JUnit starter around a dependency-free Java client using `HttpURLConnection`.

```java
AuthServiceClient auth = new AuthServiceClient(
    "https://auth.example.com",
    "raw-api-key-save-this"
);

AuthServiceClient.AuthServiceResponse session = auth.signup(
    "user@example.com",
    "ValidPass123!",
    "User"
);

AuthServiceClient.AuthServiceResponse me = auth.me();
```

Provide a `TokenStore` backed by encrypted shared preferences or Android Keystore for production apps. The default store is in-memory, and the Gradle harness covers token-store behavior without requiring an emulator.

## Coverage

- Signup, login, refresh, logout
- Access/refresh token persistence hooks
- Current user profile
- Profile update
- Active session list/revoke helpers in the browser and Node SDKs
- Organization create/list
- Organization-scoped token minting
- Swift Package and XCTest starter
- Android Gradle/JUnit starter
