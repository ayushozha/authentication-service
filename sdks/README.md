# AuthService SDKs

Starter native clients for teams that want to call AuthService without hand-writing every request.

## Browser JavaScript

`public/authservice.js` is served by AuthService itself and exposes token/session helpers, active-session listing/revocation, WebAuthn/passkey helpers, TOTP/recovery-code helpers, organization helpers, admin SSO/SCIM/audit helpers, and embeddable sign-in/signup/profile/org/enterprise widgets.

It also includes lightweight authorization helpers: `getAccessClaims()`, `hasScope(scope)`, `hasOrganizationPermission(permission)`, and `isAuthorized(resource, action)`. These are useful for UI gating; backend APIs should still validate JWTs and enforce permissions server-side.

OIDC helpers cover PKCE redirect flows: `createOIDCAuthorizationURL()`, `startOIDC()`, `handleOIDCCallback()`, `exchangeOIDCCode()`, and `oidcUserInfo()`.

Hosted pages are backed by `public/auth-ui.js` and `public/auth-ui.css`: `/login.html`, `/signup.html`, `/account.html`, `/forgot-password.html`, `/reset-password.html`, `/verify-email.html`, and `/2fa.html`.

## React / Next.js

`sdks/react/authservice-react.js` provides dependency-free React bindings around `authservice.js`: `AuthServiceProvider`, `useAuthService`, `SignIn`, `SignUp`, `UserButton`, `UserProfile`, `OrganizationSwitcher`, `OrganizationManagement`, `EnterpriseSetup`, and `AuditLog`.

React authorization helpers include `useAccessClaims()`, `useOrganizationPermission(permission)`, and `useAuthorization(resource, action)`. OIDC callback handling is available through `useOIDCCallback()`.

```js
import React from "react";
import createAuthServiceReact from "./authservice-react";

const {
  AuthServiceProvider,
  AuditLog,
  EnterpriseSetup,
  OrganizationManagement,
  SignIn,
  SignUp,
  UserButton
} = createAuthServiceReact(React, window.AuthService);

export default function App() {
  return (
    <AuthServiceProvider baseUrl="https://auth.example.com" apiKey="raw-api-key-save-this">
      <UserButton />
      <SignIn />
      <SignUp />
      <OrganizationManagement />
      <EnterpriseSetup clientID="client_uuid" adminKey="admin-key" />
      <AuditLog clientID="client_uuid" adminKey="admin-key" />
    </AuthServiceProvider>
  );
}
```

`sdks/nextjs/authservice-next.js` adds App Router helpers for SSR session loading, route guards, and middleware:

```js
const { createMiddleware, loadSession } = require("./nextjs/authservice-next");

exports.middleware = createMiddleware({
  baseUrl: "https://auth.example.com",
  apiKey: process.env.AUTH_SERVICE_API_KEY,
  clientId: process.env.AUTH_SERVICE_CLIENT_ID,
  publicRoutes: ["/login", "/signup"],
  loginPath: "/login",
  NextResponse
});

const session = await loadSession(request, {
  baseUrl: "https://auth.example.com",
  apiKey: process.env.AUTH_SERVICE_API_KEY,
  clientId: process.env.AUTH_SERVICE_CLIENT_ID
});
```

## Vue / Svelte

`sdks/vue/authservice-vue.js` exposes a Vue plugin and widget components for sign-in, signup, profile, organization, enterprise setup, and audit logs. `sdks/svelte/authservice-svelte.js` exposes Svelte actions for the same widgets.

## Node.js

`sdks/node/authservice-node.js` is a dependency-free Node 18+ SDK for server-side rendering, API routes, workers, and service-to-service flows.

Node helpers include `getAccessClaims()`, `hasScope(scope)`, `hasOrganizationPermission(permission)`, `isAuthorized(resource, action)`, policy/group-mapping APIs, and exported `decodeJwt(token)` for framework middleware.
Node OIDC helpers include `createOIDCAuthorizationURL()`, `handleOIDCCallback()`, `exchangeOIDCCode()`, and `oidcUserInfo()`.

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

if (auth.isAuthorized("billing", "manage")) {
  await updateBillingSettings();
}
```

## Backend Authorization Middleware

`sdks/middleware` contains small backend adapters for the same resource/action checks:

- `node.js` exports Express-style `requireAuthorization(resource, action)`.
- `python.py` exports `is_authorized`, `require_authorization`, a FastAPI dependency helper, and WSGI middleware.
- `AuthServiceAuthorization.java` includes servlet filter helpers.
- `AuthServiceAuthorization.cs` includes ASP.NET Core middleware helpers.
- Go services can use `pkg/jwtvalidator.Validator.RequireAuthorization(resource, action, next)`.

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
- MFA enrollment, recovery codes, passkey registration/deletion, and account recovery
- Organization create/list, org switching, member invites, member role updates
- SSO connection setup, SCIM directory setup/token rotation, and audit-log views
- Organization-scoped token minting
- JWT claim decoding and resource/action authorization helpers in browser, React, Next.js, Node, Go, Python, Java, and .NET starters
- OIDC PKCE redirect and callback helpers in browser, React, and Node SDKs
- Vue and Svelte embedded UI adapters
- Swift Package and XCTest starter
- Android Gradle/JUnit starter

## Generated Official SDK Packages

`tools/sdkgen` generates publishable SDK packages for the broader language matrix:

| Language | Package directory | Registry target | Framework adapters |
|---|---|---|---|
| TypeScript | `sdks/typescript` | npm (`@authservice/sdk`) | Express, Fastify, NestJS, Next.js |
| Python | `sdks/python` | PyPI (`authservice-sdk`) | Django, FastAPI, Flask |
| Go | `sdks/go/authservice` | Go modules | `net/http`, Gin, Chi, Echo, Fiber |
| Java/Kotlin | `sdks/jvm` | Maven Central (`com.authservice:authservice-sdk`) | Spring Boot |
| C# | `sdks/csharp` | NuGet (`AuthService`) | ASP.NET Core |
| PHP | `sdks/php` | Packagist (`authservice/authservice`) | Laravel |
| Ruby | `sdks/ruby` | RubyGems (`authservice`) | Rails/Rack |
| Rust | `sdks/rust` | crates.io (`authservice`) | Axum, Actix |

Each generated SDK includes a typed client, package metadata for its registry, JWT/JWKS verification helpers, scope and organization-permission helpers, webhook signature verification, and framework middleware where applicable.

Regenerate after API surface changes:

```bash
go run ./tools/sdkgen
```

## CLI And Terraform

- CLI: `cmd/authservice` supports login, token inspection, client provisioning, service accounts and keys, SSO setup, SCIM setup, audit export, and key rotation.
- Terraform: `terraform-provider-authservice` provides repeatable `authservice_client`, `authservice_service_account`, `authservice_sso_connection`, `authservice_scim_directory`, and `authservice_organization` resources.
