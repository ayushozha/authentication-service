# Authentication Provider Gap Matrix

**Last reviewed:** May 9, 2026
**Scope:** Compare this authentication microservice against Clerk, Auth0 by Okta, WorkOS, Firebase Authentication, Amazon Cognito, Supabase Auth, Stytch, Descope, Keycloak, Zitadel, FusionAuth, Ory, and Kinde. Source links are official product documentation or pricing pages.

## Positioning

The service is strongest for teams that want a self-hosted, open-source auth service for Go/microservice architectures without MAU pricing. It already has a rare combination of REST plus gRPC, tenant-scoped JWTs, JWKS/RS256 support, passkeys, TOTP, magic links, OAuth, Redis rate limiting, refresh-token rotation, and now queryable audit logs.

The strongest remaining gaps versus enterprise CIAM providers are SAML/OIDC enterprise SSO, SCIM directory sync, organization-level RBAC, and machine-to-machine OAuth/client-credentials tokens.

## Current Test Coverage

| Test Area | Status | Evidence | Remaining Gap |
|---|---|---|---|
| Browser-grade passkey registration | Covered | `TestBrowserGradePasskeyRegistrationLoginAndRejectedSignature` drives Chrome through `navigator.credentials.create()` with a virtual CTAP2 platform authenticator | Real Safari/Firefox matrix is not automated |
| Browser-grade passkey login | Covered | Same test completes `navigator.credentials.get()` and verifies token-mode access plus refresh tokens | Conditional UI/autofill is not implemented in the public login page |
| Passkey negative security path | Covered | Same test forces a bogus authenticator signature and expects `401 Unauthorized` | Attestation policy and enterprise attestation are not implemented |
| Public auth pages | Covered | `TestBrowserPublicAuthPagesWorkOnDesktopIOSAndAndroidProfiles` runs signup, email verification, forgot/reset password, login, magic link, and TOTP challenge flows through the served HTML pages | OAuth still uses provider redirect stubs, not live external IdPs |
| iOS mobile web | Covered as browser emulation | Same public-page suite runs with iPhone viewport, touch, platform, and Safari user-agent profile | Native iOS SDK/XCTest does not exist yet |
| Android mobile web | Covered as browser emulation | Same public-page suite runs with Pixel viewport, touch, platform, and Chrome user-agent profile | Native Android SDK/Espresso does not exist yet |
| Route-level E2E auth lifecycle | Covered | `e2e_test.go` covers signup, login, refresh rotation, logout, profile, password change/reset, email verification, magic links, TOTP, OAuth state/PKCE, passkey begin routes, audit querying, client admin, and Redis-required feature failures | No full external IdP sandbox runs yet |
| Enterprise-grade SSO/SCIM/RBAC/M2M | Not covered because features are absent | The comparison below treats these as product gaps, not just test gaps | Implement SAML/OIDC enterprise SSO, SCIM 2.0, organization RBAC, and OAuth2 client credentials |

## Provider Comparison

| Provider | Best Fit | Strengths | Where This Service Wins | Remaining Gap |
|---|---|---|---|---|
| Clerk | React/Next.js apps that want hosted/prebuilt UI fast | 50K MRU free tier, prebuilt UI, organizations, application logs, MFA/passkeys on paid plans, M2M features | Self-hosted, no MAU cost, Go validator, REST+gRPC, tenant-owned data | Hosted React components, organization UX, richer administration |
| Auth0 by Okta | Enterprise CIAM and complex identity programs | Enterprise connections, organizations, passkeys, Actions/Forms, SCIM/B2B add-ons, enterprise SLAs | Lower operational complexity for self-hosters, no vendor lock-in, per-client signing isolation, queryable logs without paid tiers | SAML/SCIM, mature compliance story, ecosystem |
| WorkOS | B2B SaaS enterprise readiness | SSO, Directory Sync/SCIM, Admin Portal, Audit Logs, RBAC/AuthKit | Self-hosted full auth stack, passkeys/TOTP/magic links plus gRPC in one binary | SSO admin portal, SCIM, directory sync |
| Firebase Authentication | Firebase/mobile-first apps | Broad mobile/web SDKs, social providers, TOTP/SMS MFA, SAML/OIDC docs, Firebase ecosystem | Standalone auth, self-hosted data, built-in tenant isolation/audit logs/rate limiting, no Firebase coupling | Mobile SDK depth, anonymous auth, Firebase integrations |
| Amazon Cognito | AWS-native products | Low-friction AWS integration, managed login, passkeys in Essentials, Plus threat/audit features, M2M add-on | Better local developer ergonomics, self-hosted, simpler mental model, REST+gRPC | AWS integration, Lambda triggers, managed scale, M2M |
| Supabase Auth | Supabase/Postgres/RLS apps | Password, magic link, OTP, social, SSO, MFA, auth hooks, RLS integration | Standalone service with gRPC, passkeys, tenant-scoped signing, queryable auth audit API | Supabase RLS/database integration, broader provider catalog |
| Stytch | API-first B2B/B2C auth with passwordless and enterprise features | 10K MAU free, organizations, SSO/SCIM, M2M, RBAC, fraud/risk add-ons | Self-hosted/no usage bill, Go-native microservice integration | SSO/SCIM, fraud/risk, prebuilt admin portal |
| Descope | Visual/no-code auth flow design | Flow builder, passkeys, MFA/step-up, tenants, RBAC, SSO/SCIM tiers, M2M exchanges | Code-owned flows, self-hosting, no workflow lock-in, gRPC | Visual flow builder, FGA, SCIM |
| Keycloak | Classic open-source IAM | Mature OSS IAM, admin console, SSO/OIDC/SAML, fine-grained authorization, REST admin API | Lighter single Go service, simpler deployment, app-focused REST+gRPC auth API | Full IAM breadth, admin console, federation maturity |
| Zitadel | Modern open-source/cloud-native IAM | Open-source identity infrastructure, hosted/self-hosted options, strong OIDC orientation | Simpler service footprint for product auth, Go validator package, no cloud dependency | Full IAM/OIDC platform depth, console/workflows |
| FusionAuth | Self-hosted CIAM with commercial support | Free self-hosted Community, tenants, OAuth/OIDC/SAML, MFA, magic links, passkeys in premium/enterprise, rich APIs | Lighter Go footprint, no Java server, REST+gRPC | Commercial support depth, admin console, SCIM/enterprise features |
| Ory | Headless open-source identity infrastructure | Kratos/Hydra/Keto/Oathkeeper stack, OAuth2/OIDC, authorization, cloud/self-hosted | Much simpler all-in-one deployment for product teams, built-in hosted pages, gRPC | Standards breadth, OAuth2 provider depth, relationship authorization |
| Kinde | Indie/SaaS auth plus billing/feature flags | 10,500 MAU free, organizations, MFA, M2M, feature flags, billing, SSO on paid plans | Self-hosted/no MAU cost, data ownership, gRPC, passkeys | Billing/feature flags, hosted UX, org-level policies |

## Modern Auth Standards Gap Table

| Capability | Current Status | Competitors That Make This Table Stakes | Priority |
|---|---|---|---|
| WebAuthn/passkeys | Implemented and now browser-grade tested for registration, login, resident credentials, user verification, and signature rejection | Auth0, Cognito, Stytch, Descope, Keycloak, Zitadel, FusionAuth, Hanko-style passkey-first tools | Keep hardening |
| Passkey conditional UI/autofill | Missing; public login has an explicit passkey button only | Auth0 documents passkey autofill-style login flows; passkey-first providers optimize this UX | Medium |
| Cross-device passkey UX | Protocol-compatible, but not tested with real iOS/Android/Safari/Chrome cross-device prompts | Auth0 and passkey-first providers emphasize cross-device passkeys | Medium |
| Attestation policy / enterprise attestation | Missing; current service accepts normal WebAuthn registration without tenant policy controls | Enterprise IAM and regulated deployments often need authenticator policy choices | Medium |
| TOTP MFA | Implemented and route-level tested | Clerk, Auth0, Firebase/Identity Platform, Supabase, Cognito, Stytch, Descope, Keycloak, Kinde | Keep |
| SMS/phone OTP MFA | Missing | Firebase, Supabase, Cognito, Auth0, Stytch, Descope | Low unless mobile-first |
| Backup/recovery codes | Missing | Common in mature MFA products | Medium |
| Magic links/passwordless email | Implemented and E2E tested | Firebase, Supabase, Stytch, FusionAuth, Kinde | Keep |
| Social OAuth | Implemented for Google, GitHub, Microsoft, Apple with state/PKCE tests | Most providers | Keep |
| Enterprise SAML/OIDC SSO | Missing | Auth0, WorkOS, Clerk Enterprise Connections, Stytch, Descope, Keycloak, FusionAuth, Ory/Zitadel | Highest |
| SCIM/directory sync | Missing | WorkOS, Auth0, Stytch, Descope, FusionAuth enterprise offerings | Highest |
| Organizations and org-scoped RBAC | Missing | Clerk Organizations, WorkOS RBAC, Stytch RBAC, Descope tenants/RBAC, Kinde orgs, FusionAuth tenants | Highest |
| Machine-to-machine/client credentials | Missing | Auth0, WorkOS, Stytch, Descope, Cognito, Ory, Kinde | High |
| Queryable audit logs | Implemented with admin filters | WorkOS, Auth0, Clerk, Kinde, enterprise IAM products | Keep improving exports/streams |
| Native iOS SDK | Missing; only HTTP API and mobile-web profile test | Firebase, Clerk, Auth0, Cognito, Supabase, Stytch, Descope | Medium if mobile apps are a target |
| Native Android SDK | Missing; only HTTP API and mobile-web profile test | Firebase, Clerk, Auth0, Cognito, Supabase, Stytch, Descope | Medium if mobile apps are a target |
| Fraud/risk/bot protection | Basic rate limiting and lockout only; no CAPTCHA, device reputation, breached-password checks, or adaptive risk engine | Stytch, Descope, Auth0, Cognito Plus, Firebase App Check ecosystem | Medium |

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
| Rate limiting and lockout | Yes |
| Browser-grade passkey E2E | Yes: Chrome DevTools virtual WebAuthn authenticator |
| iOS mobile-web E2E | Yes: public auth pages under iPhone viewport/touch/user-agent browser profile |
| Android mobile-web E2E | Yes: public auth pages under Pixel viewport/touch/user-agent browser profile |
| Native iOS SDK/test harness | Not yet |
| Native Android SDK/test harness | Not yet |
| Enterprise SSO/SAML | Not yet |
| SCIM directory sync | Not yet |
| Organization-level RBAC | Not yet |
| Machine-to-machine OAuth | Not yet |

## Implemented Gap

**Implemented:** Queryable audit log API.

Before this pass, events were written to `login_audit_log` but were not accessible through a supported API. That made the service weaker than enterprise/B2B providers with audit log products. The new admin endpoint makes audit evidence available by `client_id`, `user_id`, `event_type`, and `limit`.

This most directly improves the target use case: **self-hosted B2B SaaS that needs auth auditability without buying an enterprise identity tier**. Combined with existing self-hosting, gRPC, passkeys, TOTP, magic links, rate limiting, and per-client signing isolation, the service is now stronger than Firebase Auth and Supabase Auth for standalone B2B auth auditability, and stronger than Clerk/Kinde when the buyer prioritizes self-hosted data ownership and zero MAU-based auth spend over hosted UI.

## Next Feature Bets

1. **Organization-level RBAC**: closes the most common B2B SaaS gap versus Clerk, WorkOS, Stytch, Descope, Kinde, and FusionAuth.
2. **SAML/OIDC enterprise SSO**: required to compete directly for enterprise SaaS deals.
3. **SCIM 2.0**: pairs with SSO for enterprise user lifecycle management.
4. **M2M/client credentials**: improves service-to-service auth and closes a gap against Auth0, WorkOS, Stytch, Cognito, Descope, FusionAuth, Ory, and Kinde.
5. **Native mobile SDKs and tests**: adds real XCTest/Espresso coverage instead of only mobile-web browser profiles.

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
