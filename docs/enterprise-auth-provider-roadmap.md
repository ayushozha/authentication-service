# Enterprise Auth Provider Roadmap

**Last reviewed:** May 10, 2026

This roadmap compares AuthService against the strongest current authentication providers and turns the gaps into a product and engineering backlog. It is based on the local codebase plus official provider documentation for Auth0, Clerk, WorkOS, Firebase/Identity Platform, Amazon Cognito, Supabase, Stytch, Descope, Keycloak, ZITADEL, FusionAuth, Ory, and Kinde.

For milestone planning, use the companion execution doc: [Enterprise Strengthening Goals](enterprise-strengthening-goals.md).

## Current Position

AuthService is already unusually broad for a self-hosted Go service: email/password, refresh-token rotation, passkeys, TOTP and recovery codes, OAuth social login, SAML/OIDC enterprise SSO, SCIM users/groups, organizations, org-scoped RBAC tokens, machine-to-machine OAuth, audit logs, signed audit webhooks, REST, gRPC, browser SDK, React wrapper, Node starter, iOS/Android starters, and a Go JWT validator.

The fastest path to becoming a true plug-and-play enterprise auth platform is not adding another login method first. It is hardening the control plane, making SDKs and framework adapters feel finished, and adding self-serve enterprise onboarding workflows.

## Provider Baseline

| Provider | What they set as table stakes | What AuthService has | Where AuthService is weaker |
|---|---|---|---|
| Clerk | Polished hosted UI, React/Next.js-first DX, organizations, roles/permissions, MFA/passkeys, SSO/SCIM on higher tiers | Browser SDK, React wrapper, orgs/RBAC, passkeys, TOTP, SSO/SCIM | Published packages, hosted UI polish, framework guards, customer-facing org UX |
| Auth0 by Okta | Enterprise connections, organizations, RBAC, Actions extensibility, logs, SCIM, compliance, broad SDKs | SAML/OIDC SSO, orgs, RBAC, audit API, webhooks, social OAuth | Actions/hooks marketplace, admin RBAC, compliance artifacts, mature key/secrets lifecycle |
| WorkOS | SSO, Directory Sync, Admin Portal, Audit Logs, RBAC, organization-centered enterprise onboarding | SSO, SCIM, audit logs, RBAC, orgs | Self-serve IT admin portal, domain verification, IdP compatibility matrix, group-to-role sync polish |
| Firebase/Identity Platform | Mobile/web SDKs, MFA, SAML/OIDC, multi-tenancy, blocking functions, Google ecosystem | Core auth, SSO, MFA, tenant-scoped clients, webhooks | Mobile SDK depth, anonymous/phone auth, blocking hooks, Google/Firebase integrations |
| Amazon Cognito | Managed login, passkeys, MFA, adaptive auth, SAML/OIDC IdPs, Lambda triggers, M2M, AWS integration | Passkeys, TOTP, SAML/OIDC, M2M, audit logs | Managed threat protection, Lambda-style triggers, AWS IAM/WAF/CloudWatch integration |
| Supabase Auth | Many auth methods, Postgres/RLS integration, hooks, MFA, custom OAuth/OIDC, client SDKs | Standalone auth, custom OAuth providers, TOTP, webhooks | RLS-native authorization, hooks, SDK breadth, phone OTP |
| Stytch | API-first B2B/B2C auth, RBAC policy, SSO/SCIM, passkeys, frontend/backend SDKs | API-first auth, org RBAC, SSO/SCIM, passkeys | RBAC policy management APIs, authorization checks, SDK/UI depth, risk/fraud add-ons |
| Descope | Visual flow builder, passkeys, MFA/step-up, RBAC and FGA/ReBAC/ABAC, SSO/SCIM | Code-owned flows, passkeys, TOTP, SSO/SCIM, org RBAC | Visual orchestration, FGA engine, richer step-up policy |
| Keycloak/ZITADEL/FusionAuth/Ory | Mature OSS IAM, OIDC/OAuth depth, admin consoles, federation, authorization, self-hosting | Much lighter all-in-one product auth service | Full OIDC provider surface, federation maturity, admin console depth, policy engines |

## Highest-Risk Weaknesses

**Closed in the May 10 hardening pass:** browser callback token leakage is now addressed with one-time redirect auth codes, `enforce_for_domains` blocks password/signup/OAuth/magic-link/reset/password-change paths for enforced SSO domains, and break-glass admin key checks use constant-time secret comparison. The remaining risks below are the next provider-parity gaps.

1. **Admin plane maturity**
   Admin identities, scoped roles, MFA/SSO login, break-glass auditability, and rate limits are in place, but the control plane still needs more customer delegation polish, admin UX depth, and operational lifecycle workflows.

2. **Redirect token leakage**
   Implemented for OAuth, SSO, and magic-link browser redirects with short-lived single-use auth codes exchanged at `/api/auth/redirect/exchange`. Keep testing framework adapters and external callback deployments.

3. **SSO enforcement**
   Implemented across password signup, password login, social OAuth, magic link sending, password reset email sending, and password changes for active enforced SSO domains. Future work should add customer-visible fallback policy controls.

4. **Secrets and key lifecycle**
   TOTP secrets, OAuth provider credentials, SSO client secrets, SAML private keys, and RS256 private keys need envelope encryption/KMS support. RS256 needs active/retiring/retired states, overlap windows, admin rotation APIs, and audit events.

5. **SCIM compatibility**
   Enterprise IdPs expect `filter`, pagination, ETags, complete PATCH semantics, group membership updates, and group-to-role/org mapping. Current SCIM is useful but not yet IdP-hard.

6. **SDK and connector breadth**
   Browser JS is broad; Node/React/iOS/Android are starter-grade; Python, Java server, .NET, PHP, Ruby, Rust, CLI, Terraform, and framework adapters are missing.

7. **Policy extensibility**
   Competitors win enterprise deals with hooks/actions/triggers. AuthService needs signed lifecycle webhooks or synchronous hooks for signup, login, token minting, MFA verification, SSO JIT, SCIM provisioning, and password reset.

## Roadmap To Beat The Market

### 0. Immediate Security Hardening

- Require authenticated user context on all gRPC user methods.
- Keep admin rate limits and constant-time admin key comparison covered by regression tests.
- Keep one-time redirect auth-code exchange covered across OAuth, SSO, and magic-link browser callbacks.
- Keep SSO enforced-domain checks covered across non-SSO auth entry points.
- Make refresh-token and verification-token consumption atomic with `UPDATE ... RETURNING` or row locks.
- Add tenant-scoped repository methods for user/session/MFA mutations.
- Disable or gate gRPC reflection in production.

### 1. Enterprise Control Plane

- Admin users with roles: owner, security admin, support admin, billing admin, read-only auditor.
- Admin SSO and MFA requirement.
- Tenant/customer admin delegation for org-level SSO, SCIM, members, roles, and audit views.
- Full audit actor model: actor type, actor ID, source, request ID, before/after diff, target resource.
- Tamper-evident audit chain and append-only export option.
- Retention policies, legal hold, and automated evidence export.

### 2. RBAC, ABAC, And FGA

- First-class RBAC policy API: resources, actions, permissions, roles, descriptions, defaults, and versioning.
- Organization-level custom roles and permission templates.
- Group-to-role mapping from SSO and SCIM.
- `isAuthorized(resource, action)` endpoint and SDK helpers.
- Server middleware for permission checks in every major backend framework.
- Optional FGA/ReBAC model for resources such as documents, projects, workspaces, and nested teams.
- Policy simulator and explain endpoint for debugging authorization decisions.

### 3. Self-Serve Enterprise Onboarding

- Hosted Admin Portal equivalent for customer IT admins.
- Domain verification with DNS TXT records.
- Guided SAML/OIDC setup for Okta, Microsoft Entra ID, Google Workspace, Ping, OneLogin, JumpCloud, and generic SAML/OIDC.
- SCIM setup wizard with copyable base URL/token, test event, and provider-specific docs.
- Connection health, last sync, error history, and test sign-in.
- Certificate expiration alerts and SAML metadata refresh.

### 4. Full OIDC Provider Surface

- OIDC discovery: `/.well-known/openid-configuration`.
- `/authorize`, `/token`, `/userinfo`, `/revoke`, `/introspect`, `/logout`.
- Authorization code + PKCE for first-party apps.
- Consent screens and trusted first-party app bypass.
- Dynamic client registration if needed.
- Fine-grained audiences/resource servers/scopes.
- ID token support with nonce, `iss`, `aud`, `azp`, `auth_time`, `acr`, and `amr`.

### 5. SDKs And Language Portability

- Generated typed SDKs from OpenAPI for TypeScript, Python, Go, Java/Kotlin, C#, PHP, Ruby, and Rust.
- Published packages: npm, PyPI, Maven Central, NuGet, Packagist, RubyGems, crates.io.
- Backend middleware: Express, Fastify, NestJS, Next.js, Remix, SvelteKit, Nuxt, Django, FastAPI, Flask, Spring Boot, ASP.NET Core, Laravel, Symfony, Rails, Rack, Axum, Actix, Gin, Chi, Echo, Fiber.
- JWT verifier packages with JWKS caching, issuer/audience enforcement, token-use checks, org permission helpers, and webhook signature verification.
- CLI for login, token inspect, client provisioning, service accounts, SSO/SCIM setup, audit export, and key rotation.
- Terraform provider for clients, origins, webhooks, service accounts, SSO connections, SCIM directories, org role policies, and signing keys.

### 6. Hosted And Embedded UI

- Hosted login with brand themes, custom domains, passkey-first flows, MFA enrollment, account recovery, org selection, SSO discovery, and error-state polish.
- Drop-in React/Vue/Svelte components for sign-in, sign-up, user profile, org switcher, org member management, SSO setup, SCIM setup, and audit logs.
- Next.js App Router helpers, route guards, server actions, middleware, and SSR session loading.
- Accessibility and localization across hosted and embedded UI.

### 7. Risk, Fraud, And Step-Up

- Per-client/org MFA policy: required, optional, adaptive, specific factors, recovery rules.
- Step-up challenges for sensitive actions and high-risk sessions.
- Device trust and remembered-device management.
- IP reputation, impossible travel, ASN/VPN/Tor signals, breached credential checks.
- CAPTCHA/risk provider integrations.
- Security event feedback loop and admin risk dashboard.

### 8. Compliance And Operations

- SOC 2 evidence pack template, HIPAA/BAA readiness docs, GDPR/DPA templates, subprocessor list for hosted mode.
- Backup/restore drills with RPO/RTO targets.
- Metrics: login success/failure, MFA challenge rate, SSO errors, SCIM sync lag, webhook delivery, token refresh reuse.
- SIEM integrations and log streams: Datadog, Splunk, Elastic, S3, CloudWatch, Google Cloud Logging, Azure Monitor.
- Multi-region deployment guide and optional read-replica/JWKS edge cache strategy.

## Product Strategy

The strongest wedge is: **self-hosted, enterprise-ready B2B auth with WorkOS-like enterprise onboarding, Auth0-like extensibility, Clerk-like developer experience, and Keycloak-like control without Keycloak complexity.**

Do not try to win by matching every provider feature in random order. Win by making the core path excellent:

1. Create a client.
2. Add a framework SDK.
3. Drop in hosted/embedded login.
4. Add orgs and RBAC.
5. Let the customer IT admin self-configure SSO and SCIM.
6. Validate JWTs locally in any language.
7. Export audit evidence and operate confidently.

## Official Source Links

- Auth0: [Organizations](https://auth0.com/docs/organizations), [Enterprise Connections](https://auth0.com/docs/authenticate/enterprise-connections), [RBAC](https://auth0.com/docs/manage-users/access-control/rbac), [Actions](https://auth0.com/docs/customize/actions/actions-overview), [SCIM](https://auth0.com/docs/authenticate/protocols/scim)
- Clerk: [Roles and Permissions](https://clerk.com/docs/guides/organizations/control-access/roles-and-permissions)
- WorkOS: [Admin Portal](https://workos.com/docs/admin-portal), [RBAC](https://workos.com/docs/rbac), [Audit Logs](https://workos.com/docs/audit-logs/admin-portal)
- Firebase: [Auth Blocking Triggers](https://firebase.google.com/docs/functions/auth-blocking-events)
- Amazon Cognito: [User Pools](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools.html), [Managed Login](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-integration.html), [Adaptive Authentication](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html)
- Supabase: [Auth](https://supabase.com/docs/guides/auth), [Auth Hooks](https://supabase.com/docs/guides/auth/auth-hooks), [MFA](https://supabase.com/docs/guides/auth/auth-mfa)
- Stytch: [B2B RBAC](https://stytch.com/docs/b2b/guides/rbac/overview), [SCIM](https://stytch.com/docs/b2b/guides/scim/overview), [SSO](https://stytch.com/docs/api-reference/b2b/api/sso/overview)
- Descope: [Flows](https://docs.descope.com/flows), [Authorization](https://docs.descope.com/authorization), [RBAC](https://docs.descope.com/manage/roles/)
- ZITADEL: [Documentation](https://zitadel.com/docs)
