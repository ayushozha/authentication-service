# Authentication Provider Gap Matrix

**Last reviewed:** May 9, 2026
**Scope:** Compare this authentication microservice against Clerk, Auth0 by Okta, WorkOS, Firebase Authentication, Amazon Cognito, Supabase Auth, Stytch, Descope, Keycloak, Zitadel, FusionAuth, Ory, and Kinde. Source links are official product documentation or pricing pages.

## Positioning

The service is strongest for teams that want a self-hosted, open-source auth service for Go/microservice architectures without MAU pricing. It already has a rare combination of REST plus gRPC, tenant-scoped JWTs, JWKS/RS256 support, passkeys, TOTP, magic links, OAuth, Redis rate limiting, refresh-token rotation, and now queryable audit logs.

The strongest remaining gaps versus enterprise CIAM providers are live native mobile network fixtures, device-reputation integrations, step-up policy polish, automated audit retention jobs, and formal third-party compliance reports. Enterprise SSO, SCIM, organization RBAC, M2M tokens, an admin/customer portal, browser/React/Node SDK starters, starter native SDK packages/test harnesses, CAPTCHA hooks, audit exports, signed audit webhooks, operations runbooks, and TOTP recovery codes are now implemented.

## Current Test Coverage

| Test Area | Status | Evidence | Remaining Gap |
|---|---|---|---|
| Browser-grade passkey registration | Covered | `TestBrowserGradePasskeyRegistrationLoginAndRejectedSignature` drives Chrome through `navigator.credentials.create()` with a virtual CTAP2 platform authenticator | Real Safari/Firefox matrix is not automated |
| Browser-grade passkey login | Covered | Same test completes `navigator.credentials.get()` and verifies token-mode access plus refresh tokens | Conditional UI/autofill is not implemented in the public login page |
| Passkey negative security path | Covered | Same test forces a bogus authenticator signature and expects `401 Unauthorized` | Attestation policy and enterprise attestation are not implemented |
| Public auth pages | Covered | `TestBrowserPublicAuthPagesWorkOnDesktopIOSAndAndroidProfiles` runs signup, email verification, forgot/reset password, login, magic link, and TOTP challenge flows through the served HTML pages | OAuth still uses provider redirect stubs, not live external IdPs |
| Admin/customer portal | Covered | `TestBrowserPortalShellRendersOnDesktopIOSAndAndroidProfiles` loads `/portal.html`, switches workspaces, and checks desktop/mobile document overflow | API-backed workflows are covered by route E2Es, not a live operator acceptance test |
| Browser SDK and embeddable UI | Covered | `TestBrowserSDKSignupOrganizationsAndUserWidget` loads `/authservice.js` in Chrome and exercises signup, token storage, `/me`, profile update, org creation, org token minting, and `mountUserButton` | No packaged npm release yet |
| iOS mobile web | Covered as browser emulation | Same public-page suite runs with iPhone viewport, touch, platform, and Safari user-agent profile | Native XCTest suite is not implemented yet |
| Android mobile web | Covered as browser emulation | Same public-page suite runs with Pixel viewport, touch, platform, and Chrome user-agent profile | Native Espresso suite is not implemented yet |
| iOS Swift SDK | Starter covered | `sdks/ios/Package.swift`, `AuthServiceClient.swift`, `KeychainAuthServiceTokenStore`, and XCTest fixtures cover package/test scaffolding | No live XCTest network fixture yet |
| Android Java SDK | Starter present | `sdks/android/build.gradle` and JUnit fixtures wrap the dependency-free native request/session helpers | Java runtime is unavailable in this workspace, so javac/Gradle validation could not run; no Android AAR publishing config yet |
| Route-level E2E auth lifecycle | Covered | `e2e_test.go` covers signup, login, refresh rotation, logout, profile, password change/reset, email verification, magic links, TOTP, OAuth state/PKCE, passkey begin routes, audit querying, client admin, and Redis-required feature failures | No full external IdP sandbox runs yet |
| Enterprise-grade SSO/SCIM/RBAC/M2M | Covered | Route E2Es cover organization invitations/tokens, OAuth2 client credentials and introspection, OIDC/SAML enterprise SSO setup/callbacks, and SCIM Users/Groups provisioning | No live Okta/Azure/Ping/Google Workspace sandbox matrix yet |

## Provider Comparison

| Provider | Best Fit | Strengths | Where This Service Wins | Remaining Gap |
|---|---|---|---|---|
| Clerk | React/Next.js apps that want hosted/prebuilt UI fast | 50K MRU free tier, prebuilt UI, organizations, application logs, MFA/passkeys on paid plans, M2M features | Self-hosted, no MAU cost, Go validator, REST+gRPC, tenant-owned data | Hosted React components, organization UX, richer administration |
| Auth0 by Okta | Enterprise CIAM and complex identity programs | Enterprise connections, organizations, passkeys, Actions/Forms, SCIM/B2B add-ons, enterprise SLAs | Lower operational complexity for self-hosters, no vendor lock-in, per-client signing isolation, queryable logs without paid tiers | Mature compliance story, Actions/marketplace ecosystem, managed SLAs |
| WorkOS | B2B SaaS enterprise readiness | SSO, Directory Sync/SCIM, Admin Portal, Audit Logs, RBAC/AuthKit | Self-hosted full auth stack, passkeys/TOTP/magic links plus gRPC in one binary | Hosted admin portal polish, directory provider compatibility matrix, managed SLA |
| Firebase Authentication | Firebase/mobile-first apps | Broad mobile/web SDKs, social providers, TOTP/SMS MFA, SAML/OIDC docs, Firebase ecosystem | Standalone auth, self-hosted data, built-in tenant isolation/audit logs/rate limiting, no Firebase coupling | Mobile SDK depth, anonymous auth, Firebase integrations |
| Amazon Cognito | AWS-native products | Low-friction AWS integration, managed login, passkeys in Essentials, Plus threat/audit features, M2M add-on | Better local developer ergonomics, self-hosted, simpler mental model, REST+gRPC | AWS integration, Lambda triggers, managed scale |
| Supabase Auth | Supabase/Postgres/RLS apps | Password, magic link, OTP, social, SSO, MFA, auth hooks, RLS integration | Standalone service with gRPC, passkeys, tenant-scoped signing, queryable auth audit API | Supabase RLS/database integration, broader provider catalog |
| Stytch | API-first B2B/B2C auth with passwordless and enterprise features | 10K MAU free, organizations, SSO/SCIM, M2M, RBAC, fraud/risk add-ons | Self-hosted/no usage bill, Go-native microservice integration | Fraud/risk, hosted UX polish, managed provider ecosystem |
| Descope | Visual/no-code auth flow design | Flow builder, passkeys, MFA/step-up, tenants, RBAC, SSO/SCIM tiers, M2M exchanges | Code-owned flows, self-hosting, no workflow lock-in, gRPC | Visual flow builder, FGA, risk orchestration |
| Keycloak | Classic open-source IAM | Mature OSS IAM, admin console, SSO/OIDC/SAML, fine-grained authorization, REST admin API | Lighter single Go service, simpler deployment, app-focused REST+gRPC auth API | Full IAM breadth, admin console, federation maturity |
| Zitadel | Modern open-source/cloud-native IAM | Open-source identity infrastructure, hosted/self-hosted options, strong OIDC orientation | Simpler service footprint for product auth, Go validator package, no cloud dependency | Full IAM/OIDC platform depth, console/workflows |
| FusionAuth | Self-hosted CIAM with commercial support | Free self-hosted Community, tenants, OAuth/OIDC/SAML, MFA, magic links, passkeys in premium/enterprise, rich APIs | Lighter Go footprint, no Java server, REST+gRPC | Commercial support depth, richer admin console, enterprise support packaging |
| Ory | Headless open-source identity infrastructure | Kratos/Hydra/Keto/Oathkeeper stack, OAuth2/OIDC, authorization, cloud/self-hosted | Much simpler all-in-one deployment for product teams, built-in hosted pages, gRPC | Standards breadth, OAuth2 provider depth, relationship authorization |
| Kinde | Indie/SaaS auth plus billing/feature flags | 10,500 MAU free, organizations, MFA, M2M, feature flags, billing, SSO on paid plans | Self-hosted/no MAU cost, data ownership, gRPC, passkeys | Billing/feature flags, hosted UX, org-level policies |

## Modern Auth Standards Gap Table

| Capability | Current Status | Competitors That Make This Table Stakes | Priority |
|---|---|---|---|
| WebAuthn/passkeys | Implemented and now browser-grade tested for registration, login, resident credentials, user verification, and signature rejection | Auth0, Cognito, Stytch, Descope, Keycloak, Zitadel, FusionAuth, Hanko-style passkey-first tools | Keep hardening |
| Passkey conditional UI/autofill | Implemented in `/login.html` and exposed in `/authservice.js` with `startConditionalPasskeyLogin` | Auth0 documents passkey autofill-style login flows; passkey-first providers optimize this UX | Keep testing across real browsers |
| Cross-device passkey UX | Protocol-compatible with automated browser coverage plus manual cross-device QA checklist in `docs/passkey-qa.md` | Auth0 and passkey-first providers emphasize cross-device passkeys | Add real-device automation where practical |
| Attestation policy / enterprise attestation | Implemented with tenant settings for attestation conveyance, required attestation, and allowed attestation formats | Enterprise IAM and regulated deployments often need authenticator policy choices | Keep hardening with metadata trust stores |
| TOTP MFA | Implemented and route-level tested | Clerk, Auth0, Firebase/Identity Platform, Supabase, Cognito, Stytch, Descope, Keycloak, Kinde | Keep |
| SMS/phone OTP MFA | Missing | Firebase, Supabase, Cognito, Auth0, Stytch, Descope | Low unless mobile-first |
| Backup/recovery codes | Implemented for TOTP as one-time hashed recovery codes with login verification and usage audit events | Common in mature MFA products | Keep hardening with account recovery workflows |
| Magic links/passwordless email | Implemented and E2E tested | Firebase, Supabase, Stytch, FusionAuth, Kinde | Keep |
| Social OAuth | Implemented for Google, GitHub, Microsoft, Apple with state/PKCE tests | Most providers | Keep |
| Enterprise SAML/OIDC SSO | Implemented with admin APIs, domain routing, OIDC discovery/callbacks, SAML SP metadata, and signed response validation | Auth0, WorkOS, Clerk Enterprise Connections, Stytch, Descope, Keycloak, FusionAuth, Ory/Zitadel | Keep hardening with live IdP fixtures |
| SCIM/directory sync | Implemented for SCIM 2.0 Users and Groups with bearer-token directories and deprovisioning | WorkOS, Auth0, Stytch, Descope, FusionAuth enterprise offerings | Keep hardening with IdP compatibility fixtures |
| Organizations and org-scoped RBAC | Implemented with owner/admin/member/viewer roles, custom permissions, invitations, members, and org-scoped tokens | Clerk Organizations, WorkOS RBAC, Stytch RBAC, Descope tenants/RBAC, Kinde orgs, FusionAuth tenants | Add richer UI policies and templates |
| Machine-to-machine/client credentials | Implemented with service accounts, scoped keys, OAuth2 token endpoint, introspection, revocation, and rotation | Auth0, WorkOS, Stytch, Descope, Cognito, Ory, Kinde | Keep |
| Queryable audit logs and webhooks | Implemented with admin filters, CSV/NDJSON export, and signed audit-event webhook delivery with retries | WorkOS, Auth0, Clerk, Kinde, enterprise IAM products | Keep improving retention controls and evidence automation |
| Browser SDK and embeddable UI | Implemented as dependency-free `/authservice.js`, React/Next.js bindings, Node SDK, token/session helpers, and sign-in/user widgets | Clerk, Auth0, Firebase, Supabase, Stytch, Descope | Add npm packaging and framework-specific adapters |
| Native iOS SDK | Starter Swift client implemented for signup/login/refresh/logout/profile/org flows | Firebase, Clerk, Auth0, Cognito, Supabase, Stytch, Descope | Package with SPM, Keychain store, and XCTest fixture |
| Native Android SDK | Starter Java client implemented for signup/login/refresh/logout/profile/org flows | Firebase, Clerk, Auth0, Cognito, Supabase, Stytch, Descope | Package with Gradle/AAR, encrypted storage, and Espresso/JVM fixture |
| Fraud/risk/bot protection | Rate limiting, lockout, optional CAPTCHA hooks for signup/login, configurable password policy, common/compromised-password blocking, user-info password blocking, disposable email-domain blocking, active-session management, suspicious new IP/device login detection, adaptive MFA challenge audit signals, and audit events for blocked attempts | Stytch, Descope, Auth0, Cognito Plus, Firebase App Check ecosystem | Add managed device reputation provider integrations |

## Feature Matrix

| Capability | This Service After This Pass |
|---|---|
| Self-hosted/open-source | Yes |
| REST API | Yes |
| gRPC API | Yes |
| Multi-tenant clients | Yes |
| Email/password | Yes |
| OAuth/social | Google, GitHub, Microsoft, Apple |
| Magic links | Yes |
| Passkeys/WebAuthn | Yes |
| TOTP MFA | Yes |
| Refresh-token rotation | Yes |
| Per-client JWT/JWKS signing | Yes |
| Queryable audit logs | Yes: `GET /api/admin/audit-events` |
| Audit evidence export | Yes: `GET /api/admin/audit-events/export` as CSV or NDJSON |
| Signed audit webhooks | Yes: client `webhook_url` receives HMAC-signed `audit.event` deliveries with retry controls |
| Operations runbooks | Yes: backup, restore, migration, import/export, webhook verification, incident, and audit-retention guidance in `docs/operations-runbook.md`; helper scripts in `scripts/` |
| Admin/customer portal | Yes: `/portal.html` |
| Browser SDK and embeddable UI | Yes: `/authservice.js` |
| React/Next.js SDK starter | Yes: `sdks/react/authservice-react.js` |
| Node.js SDK starter | Yes: `sdks/node/authservice-node.js` |
| iOS Swift SDK starter | Yes: `sdks/ios/AuthServiceClient.swift` |
| Android Java SDK starter | Yes: `sdks/android/com/authservice/sdk/AuthServiceClient.java` |
| Rate limiting and lockout | Yes |
| CAPTCHA/bot verification | Yes: optional Turnstile, hCaptcha, reCAPTCHA, or custom verification endpoint for signup/login |
| Password risk policy | Yes: common/compromised-password, low-entropy, and user-info rejection |
| Device/session management | Yes: users can list and revoke active sessions |
| Suspicious login detection | Yes: password login compares active session IP/device history and audits `suspicious_login` plus adaptive MFA challenge signals |
| Browser-grade passkey E2E | Yes: Chrome DevTools virtual WebAuthn authenticator |
| iOS mobile-web E2E | Yes: public auth pages under iPhone viewport/touch/user-agent browser profile |
| Android mobile-web E2E | Yes: public auth pages under Pixel viewport/touch/user-agent browser profile |
| Enterprise SSO/SAML/OIDC | Yes |
| SCIM directory sync | Yes |
| Organization-level RBAC | Yes |
| Machine-to-machine OAuth | Yes |
| Native iOS package/test harness | Yes: Swift Package plus XCTest starter |
| Native Android package/test harness | Yes: Gradle/JUnit starter; local Java runtime unavailable for validation |

## Implemented Gap

**Implemented:** Queryable audit log API, evidence export, signed webhook delivery, token-safe browser redirects, enforced-domain SSO blocking, and constant-time break-glass admin key checks.

Before this pass, events were written to `login_audit_log` but were not accessible through a supported API. That made the service weaker than enterprise/B2B providers with audit log products. The admin endpoints make audit evidence available by `client_id`, `user_id`, `event_type`, and `limit`, export it as CSV/NDJSON, and deliver the same audit stream to each client's `webhook_url` with HMAC signatures and bounded retries.

This most directly improves the target use case: **self-hosted B2B SaaS that needs auth auditability without buying an enterprise identity tier**. Combined with existing self-hosting, gRPC, passkeys, TOTP, magic links, rate limiting, and per-client signing isolation, the service is now stronger than Firebase Auth and Supabase Auth for standalone B2B auth auditability, and stronger than Clerk/Kinde when the buyer prioritizes self-hosted data ownership and zero MAU-based auth spend over hosted UI.

This pass also closes two security gaps that mature CIAM providers avoid by default: OAuth/SSO/magic-link browser callbacks now redirect with a short-lived single-use `auth_code` instead of an access token, and active SSO connections with `enforce_for_domains` block password signup, password login, social OAuth, magic links, password reset emails, and password changes for matching domains.

## Next Feature Bets

1. **Native mobile packaging and tests**: adds Swift Package/Gradle packaging plus real XCTest/Espresso coverage.
2. **Bot protection integrations**: managed device reputation providers and richer step-up policies.
3. **Passkey UX polish**: conditional UI/autofill, cross-device fixtures, and tenant attestation policy.
4. **MFA step-up policy**: route-level MFA enforcement helpers and recovery workflow polish.
5. **Compliance/operations packaging**: automated retention controls, backup/restore automation, and evidence-friendly docs.

## Sources

- [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
- [Clerk Organizations](https://clerk.com/docs/guides/organizations/overview)
- [Clerk Pricing](https://clerk.com/pricing)
- [Auth0 Passkeys](https://auth0.com/docs/authenticate/database-connections/passkeys)
- [Auth0 Pricing](https://auth0.com/pricing)
- [WorkOS Single Sign-On](https://workos.com/docs/sso)
- [WorkOS Directory Sync](https://workos.com/docs/directory-sync)
- [WorkOS RBAC](https://workos.com/docs/rbac)
- [WorkOS Audit Logs](https://workos.com/docs/audit-logs)
- [WorkOS Pricing](https://workos.com/pricing)
- [Firebase Authentication Docs](https://firebase.google.com/docs/auth)
- [Firebase Authentication Web Docs](https://firebase.google.com/docs/auth/web/start)
- [Amazon Cognito Authentication Flows](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow-methods.html)
- [Amazon Cognito Pricing](https://aws.amazon.com/cognito/pricing/)
- [Supabase Auth Docs](https://supabase.com/docs/guides/auth)
- [Supabase MFA](https://supabase.com/docs/guides/auth/auth-mfa)
- [Stytch SSO](https://stytch.com/docs/multi-tenant-auth/authentication/sso/overview)
- [Stytch Pricing](https://stytch.com/pricing)
- [Descope Pricing](https://www.descope.com/pricing)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [Zitadel Documentation](https://zitadel.com/docs)
- [Zitadel Pricing](https://zitadel.com/pricing)
- [FusionAuth Pricing](https://fusionauth.io/pricing)
- [Ory Pricing](https://www.ory.com/pricing)
- [Ory Documentation](https://www.ory.com/docs/welcome)
- [Kinde Pricing](https://www.kinde.com/pricing/)
