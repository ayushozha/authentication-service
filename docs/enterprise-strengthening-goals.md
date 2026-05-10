# Enterprise Strengthening Goals

**Last reviewed:** May 10, 2026

These goals turn the enterprise roadmap into eight concrete workstreams. Each goal is meant to be independently trackable, testable, and useful for planning issues, milestones, or investor/customer-facing progress.

## Goal 1: Build A Real Enterprise Admin Plane

**Objective:** Replace the single master-key admin model with enterprise-grade admin identities, scoped roles, MFA, tenant delegation, and complete admin auditability.

**Why it matters:** Auth0, WorkOS, ZITADEL, Keycloak, and FusionAuth all assume that administration itself is an identity and authorization problem. A master key is fine for bootstrap, but it is not enough for enterprise buyers.

**Done means:**

- Admin users can sign in with MFA and optional SSO.
- Admin roles exist for owner, security admin, support admin, billing admin, and read-only auditor.
- Admin permissions can be scoped to one client, one organization, or all clients.
- Break-glass master key remains available but is rate-limited, audited, and discouraged for daily use.
- Every admin action records actor, target, before/after metadata, request ID, IP, and user agent.
- Admin APIs reject unauthorized role/tenant combinations with tests.

**Primary metric:** 100% of admin routes enforce an admin identity/permission check and emit an actor-aware audit event.

## Goal 2: Make Authorization A First-Class Product

**Objective:** Evolve organization RBAC into a provider-grade authorization system with policies, custom roles, resources/actions, SDK checks, and eventually FGA/ReBAC support.

**Why it matters:** WorkOS, Clerk, Stytch, and Descope compete heavily on roles, permissions, tenant-scoped authorization, and developer ergonomics.

**Done means:**

- RBAC policy APIs support resources, actions, permissions, roles, descriptions, defaults, and versions.
- Organizations can define custom role templates.
- SSO and SCIM groups can map into org roles and permissions.
- SDKs expose `isAuthorized(resource, action)` style helpers.
- Backend middleware exists for at least Node, Python, Go, and Java/.NET.
- Policy simulator explains why access was allowed or denied.
- Authorization decisions are covered by route-level and unit tests.

**Primary metric:** A B2B app can model `billing:manage`, `documents:read`, and `members:invite` without custom application-side auth glue.

## Goal 3: Create Self-Serve Enterprise Onboarding

**Objective:** Build a WorkOS-style portal where customer IT admins can configure SSO, SCIM, domain verification, and audit access without engineering support.

**Why it matters:** Enterprise adoption is won or lost during onboarding. Customers expect guided Okta, Microsoft Entra ID, Google Workspace, Ping, OneLogin, and generic SAML/OIDC setup.

**Done means:**

- Customer admins can access a scoped setup portal.
- Domains can be verified with DNS TXT records.
- SAML/OIDC setup has provider-specific instructions and metadata helpers.
- SCIM setup exposes copyable base URL/token and provider-specific steps.
- Connections show health, last login, last sync, errors, and test sign-in.
- Certificate expiration and metadata refresh warnings are visible.
- Portal actions are permissioned and audit logged.

**Primary metric:** A customer IT admin can configure SAML SSO and SCIM from scratch without direct database access or internal operator intervention.

## Goal 4: Become A Complete OIDC Provider

**Objective:** Add a standards-complete OIDC/OAuth provider surface for customer apps, not just social OAuth client support and M2M tokens.

**Why it matters:** Auth0, Cognito, Keycloak, ZITADEL, FusionAuth, and Ory are trusted because they speak standard OIDC deeply. This unlocks universal app compatibility.

**Done means:**

- OIDC discovery is available at `/.well-known/openid-configuration`.
- `/authorize`, `/token`, `/userinfo`, `/revoke`, `/introspect`, and `/logout` are implemented.
- Authorization code with PKCE is supported for browser/mobile apps.
- ID tokens include correct `iss`, `aud`, `azp`, `nonce`, `auth_time`, `acr`, and `amr` where applicable.
- Access tokens support audiences/resource servers/scopes.
- Consent and trusted first-party app behavior are configurable.
- SDKs include OIDC callback helpers.

**Primary metric:** A generic OIDC client library can integrate with AuthService without custom protocol logic.

## Goal 5: Ship Real SDKs, Connectors, CLI, And Terraform

**Objective:** Make AuthService portable across languages and frameworks so teams can plug it into any stack quickly.

**Why it matters:** Clerk wins React/Next.js DX, Firebase wins mobile DX, Auth0 wins SDK breadth, and WorkOS wins enterprise workflow SDKs. AuthService needs the same plug-and-play feeling.

**Done means:**

- Generated typed SDKs exist for TypeScript, Python, Go, Java/Kotlin, C#, PHP, Ruby, and Rust.
- Packages are publishable to npm, PyPI, Maven Central, NuGet, Packagist, RubyGems, and crates.io.
- Backend middleware covers Express, Fastify, NestJS, Next.js, Django, FastAPI, Flask, Spring Boot, ASP.NET Core, Laravel, Rails, Axum, Actix, Gin, Chi, Echo, and Fiber.
- JWT verifiers support JWKS caching, issuer/audience checks, token-use checks, scopes, org permissions, and webhook signature verification.
- A CLI supports login, token inspect, clients, service accounts, SSO/SCIM setup, audit export, and key rotation.
- Terraform provider supports repeatable client/org/SSO/SCIM/service-account provisioning.

**Primary metric:** A developer can add AuthService to a new app in their language/framework in under 15 minutes using an official package.

## Goal 6: Build Hosted And Embedded UI That Feels Premium

**Objective:** Provide polished hosted and embedded auth UI for login, signup, MFA, passkeys, SSO discovery, org switching, and profile management.

**Why it matters:** Clerk and Cognito reduce implementation time with hosted/prebuilt UI. Enterprise auth needs secure flows and excellent UX, not just endpoints.

**Done means:**

- Hosted login supports custom domains, brand themes, localization, and accessibility.
- Login supports password, passkey-first, magic link, OAuth, SSO discovery, and MFA challenges.
- MFA enrollment, recovery codes, account recovery, org selection, and profile management are built in.
- Embedded components exist for React first, then Vue/Svelte.
- B2B components include org switcher, member management, role management, SSO setup, SCIM setup, and audit log views.
- Next.js App Router helpers support route guards, SSR session loading, and middleware.

**Primary metric:** A startup can launch production auth UI without designing auth screens from scratch.

**Current implementation:** Completed in the static hosted UI and SDK layer: `/login.html`, `/signup.html`, `/account.html`, recovery pages, `auth-ui.js/css`, tenant UI config via `/api/auth/ui/config`, browser embedded widgets, React components, Vue/Svelte adapters, and Next.js App Router helpers for session loading, guards, and middleware. Remaining polish belongs in Goal 3 or Goal 7 if future work adds provider-specific IT-admin instructions, domain verification, or adaptive step-up policy.

## Goal 7: Add Adaptive Security, Fraud Defense, And Step-Up

**Objective:** Move from static auth checks to adaptive, policy-driven security that can challenge, block, or notify based on risk.

**Why it matters:** Cognito Plus, Auth0, Stytch, and Descope all sell enterprise confidence around risk, bots, device trust, and step-up authentication.

**Done means:**

- Per-client and per-org MFA policies can require, allow, or adaptively trigger factors.
- Step-up challenges protect sensitive actions such as key rotation, billing changes, exports, and member role changes.
- Device trust and remembered-device management are available.
- Risk signals include IP reputation, new device, impossible travel, ASN/VPN/Tor, failed velocity, and suspicious token reuse.
- CAPTCHA/risk providers can be plugged in.
- Security events feed dashboards, alerts, and audit logs.

**Primary metric:** High-risk login and admin actions can be challenged or blocked by policy without application code changes.

## Goal 8: Package Compliance, Reliability, And Operations

**Status:** Implemented in the service and documented in `docs/operations-runbook.md`, `docs/multi-region-deployment.md`, and `docs/compliance-readiness.md`.

**Objective:** Make AuthService enterprise-operable with evidence, metrics, retention, backups, SIEM/log streams, and deployment guidance.

**Why it matters:** Enterprise buyers do not only buy features; they buy confidence that auth can be operated, audited, recovered, and explained.

**Done means:**

- Audit retention, legal hold, CSV/NDJSON export, and tamper-evident event chains are implemented.
- SIEM/log streams support Datadog, Splunk, Elastic, S3, CloudWatch, Google Cloud Logging, and Azure Monitor.
- Metrics cover login success/failure, MFA challenge rate, SSO errors, SCIM sync lag, webhook delivery, token refresh reuse, and latency.
- Backup/restore runbooks include tested RPO/RTO targets.
- Multi-region deployment and JWKS edge-cache guidance exist.
- SOC 2, GDPR/DPA, HIPAA/BAA readiness, and hosted-mode subprocessors are documented.

**Primary metric:** A security review can verify controls from docs, audit exports, metrics, and repeatable operational procedures.

## Suggested Milestones

1. **Security Foundation:** Goals 1, 2, and 7 focused on admin auth, authorization, and adaptive controls.
2. **Enterprise Adoption:** Goals 3, 4, and 6 focused on SSO/SCIM onboarding, OIDC standards, and hosted UX.
3. **Developer Distribution:** Goal 5 focused on SDKs, connectors, CLI, and Terraform.
4. **Enterprise Trust:** Goal 8 focused on compliance, reliability, evidence, and operations.
