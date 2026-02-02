# Competitor Analysis: Authentication-as-a-Service Market

**Last Updated:** February 2026
**Document Classification:** Internal Strategy

---

## Executive Summary

The authentication-as-a-service (AaaS) market has grown into a multi-billion dollar industry, driven by the increasing complexity of modern authentication requirements (passkeys, MFA, SSO, SCIM) and the developer preference for outsourcing identity management. The market is dominated by a mix of venture-backed SaaS providers (Auth0/Okta, Clerk, Stytch, WorkOS) and open-source alternatives (Ory, SuperTokens, Logto, Hanko).

**The core tension in the market is this:** developers want authentication solved for them, but they do not want to be locked into a vendor whose pricing scales against them as they grow. MAU-based pricing -- the dominant model -- fundamentally misaligns provider incentives with customer success. Every new user a product acquires becomes a cost center for authentication.

**Where we fit:** We are a self-hosted, open-source, multi-tenant authentication microservice built in Go. We occupy the intersection of "fully-featured managed auth" and "self-hosted zero-cost infrastructure" -- a position that no competitor currently holds cleanly. Our closest competitors in philosophy are SuperTokens, Ory, and Logto, but we differentiate through native multi-tenancy, dual REST+gRPC APIs, per-tenant JWT secret isolation, and a single-binary deployment model.

**Key differentiators:**
- Self-hosted with zero recurring cost and full data ownership
- Multi-tenancy built into every tier (not enterprise-gated)
- Both REST and gRPC APIs (unique in the market)
- Per-client JWT signing secrets (true tenant isolation)
- Built-in rate limiting and audit logging on all tiers
- Importable JWT validator Go package (zero network calls for token validation)
- Single Go binary -- no runtime dependencies beyond PostgreSQL and Redis

---

## Competitor Landscape

### 1. Auth0 (Okta)

**Overview:** Auth0 is the incumbent market leader, acquired by Okta in 2021 for $6.5B. It offers a comprehensive identity platform with Universal Login, extensive SDKs, and deep enterprise features. Post-acquisition, Auth0 has shifted upmarket with significant price increases, creating an opening for alternatives in the SMB and startup segments.

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| Free | $0/mo | 7,500 | Basic auth, 2 social connections |
| Essentials | $35/mo | 500 | Custom domains, more connections |
| Professional | $240/mo | 1,000 | MFA, M2M tokens, advanced rules |
| Enterprise | Custom | Custom | SSO, SCIM, SLA, dedicated support |

**Key Features:**
- Universal Login (hosted login page)
- 30+ social connections
- Actions (serverless extensibility)
- Organizations (multi-tenancy at Professional+ tier)
- Adaptive MFA
- SCIM provisioning (Enterprise)
- Extensive SDK library (25+ languages/frameworks)
- Marketplace for integrations

**Strengths:**
- Most mature platform with the broadest feature set
- Extensive documentation and community
- Enterprise-grade compliance (SOC 2, HIPAA, PCI-DSS)
- Deep integration ecosystem

**Weaknesses:**
- Aggressive price increases post-Okta acquisition (reported 2-5x by developers)
- Universal Login latency issues (2-5 second load times reported)
- Multi-tenancy (Organizations) gated behind Professional tier
- Actions/Rules are proprietary -- deep vendor lock-in
- Password hashes are not exportable
- Complex pricing model with multiple add-ons

**Target Market:** Mid-market to enterprise; increasingly pricing out startups and SMBs.

---

### 2. Clerk

**Overview:** Clerk is a developer-experience-focused auth provider that has gained rapid traction, particularly in the Next.js/React ecosystem. Known for beautiful pre-built UI components and fast integration times. Raised $55M Series B in 2024.

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| Free | $0/mo | 10,000 | All auth methods, pre-built UI |
| Pro | $25/mo + $0.02/MAU | 10,000 (then per-MAU) | Custom domains, allowlists, production features |
| Enterprise | Custom | Custom | SSO/SAML, SCIM, SLA |

**Key Features:**
- Pre-built, customizable UI components (React, Next.js, Remix)
- Organizations (multi-tenancy)
- User management dashboard
- Webhooks and event streaming
- Session management with device tracking
- User impersonation
- Bot protection

**Strengths:**
- Best-in-class developer experience for React/Next.js
- Beautiful, ready-to-use UI components
- Fast integration (minutes, not hours)
- Generous free tier (10k MAU)
- Active community and rapid feature development

**Weaknesses:**
- Heavily tied to Next.js/React ecosystem -- limited support for non-JS backends
- UI components create UI-level vendor lock-in
- No self-hosted option
- SSO/SAML only available on Enterprise tier
- No gRPC API
- Limited backend language support outside JavaScript/TypeScript

**Target Market:** Startups and indie developers building with Next.js/React.

---

### 3. Firebase Authentication

**Overview:** Firebase Auth is Google's authentication service, tightly integrated with the Firebase platform. It offers the most generous free tier in the market (50k MAU for email/password) and benefits from Google's infrastructure, but lacks advanced features that B2B SaaS applications need.

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| Spark (Free) | $0/mo | 50,000 (email/pass) | Email/pass, social, anonymous auth |
| Blaze (Pay-as-you-go) | Variable | 50,000 free, then per-use | Phone auth ($0.01-0.06/verification), SAML/OIDC |

**Key Features:**
- Email/password, phone, anonymous auth
- Social login (Google, Facebook, Twitter, GitHub, Apple, Microsoft)
- Firebase UI (drop-in auth widgets)
- Custom token minting
- Deep integration with Firestore, Cloud Functions, Hosting
- Multi-platform SDKs (iOS, Android, Web, Flutter, Unity)

**Strengths:**
- Most generous free tier (50k MAU)
- Excellent mobile SDK support
- Google infrastructure reliability
- Easy integration with Firebase ecosystem
- Anonymous auth for progressive sign-up

**Weaknesses:**
- No built-in RBAC -- must be implemented manually
- Limited MFA (SMS only, no TOTP)
- No webhooks for auth events
- No multi-tenancy on free tier (Identity Platform required)
- Firebase security rules coupled to auth -- lock-in
- No audit logging
- No passkey/WebAuthn support in base Firebase Auth
- Bundled with Firebase platform -- difficult to use standalone

**Target Market:** Mobile developers, hobby projects, and apps already in the Firebase ecosystem.

---

### 4. Supabase Auth

**Overview:** Supabase Auth (GoTrue) is the authentication layer of the Supabase platform. Open source and built on PostgreSQL, it offers a generous free tier and tight integration with Supabase's database, storage, and edge functions. Growing rapidly as a Firebase alternative.

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| Free | $0/mo | 50,000 | All auth methods |
| Pro | $25/mo | 100,000 | Custom domains, daily backups |
| Team | $599/mo | 100,000 | SSO/SAML, SOC 2, priority support |

**Key Features:**
- Email/password, phone, magic links
- Social login (20+ providers)
- Row-level security (RLS) integration with PostgreSQL
- Server-side auth helpers
- Multi-factor authentication (TOTP)
- SSO/SAML (Team tier)
- Edge Functions hooks

**Strengths:**
- Generous free tier (50k MAU)
- Open source (GoTrue fork)
- PostgreSQL-native -- good for teams already using Supabase
- RLS integration is powerful for data-level authorization
- Growing community and ecosystem

**Weaknesses:**
- Tightly coupled to Supabase platform -- difficult to use standalone
- Email deliverability issues frequently reported
- No dedicated passkey/WebAuthn support
- Limited multi-tenancy support
- SSO/SAML only on Team tier ($599/mo)
- No gRPC API
- Self-hosted Supabase is complex (many services to manage)

**Target Market:** Developers building on the Supabase platform; PostgreSQL-centric teams.

---

### 5. Stytch

**Overview:** Stytch is a passwordless-first authentication platform targeting both B2C and B2B use cases. Raised $125M Series B at a $1B+ valuation. Strong focus on modern auth methods (passkeys, magic links, OTPs) and B2B features (SSO, SCIM, Organizations).

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| Free (B2C) | $0/mo | 1,000 | Passwords, magic links, OTPs |
| Starter | $249/mo | Included | Social logins, biometrics |
| Growth | $599/mo | Included | Custom branding, SLA |
| Enterprise | Custom | Custom | SSO/SAML, SCIM, dedicated support |

**Key Features:**
- Passwordless-first (magic links, OTPs, passkeys)
- B2B authentication (Organizations, SSO, SCIM)
- Device fingerprinting and fraud detection
- Session management with granular controls
- Direct API access (headless approach)
- Detailed analytics dashboard

**Strengths:**
- Strong B2B feature set (Organizations, SSO, SCIM)
- Good passkey implementation
- Fraud and bot detection built in
- Flexible API-first approach
- Strong enterprise positioning

**Weaknesses:**
- Expensive -- $249/mo to start, SSO requires Enterprise
- Small free tier (1,000 MAU for B2C)
- No self-hosted option
- Complex pricing with multiple product lines (B2C vs B2B)
- Smaller SDK ecosystem compared to Auth0 or Firebase
- No open-source offering

**Target Market:** B2B SaaS companies and enterprises needing SSO/SCIM.

---

### 6. WorkOS

**Overview:** WorkOS is an enterprise-readiness platform focused on SSO, SCIM, and directory sync. Recently launched AuthKit (free up to 1M MAU) to compete more broadly in the auth space. Strong positioning as the "make your app enterprise-ready" solution.

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| AuthKit Free | $0/mo | 1,000,000 | User management, social login, MFA |
| Pro | $49/mo | Included | Custom branding, bot protection |
| SSO | $125/connection/mo | Per-connection | SAML, OIDC federation |
| Enterprise | Custom | Custom | SCIM, directory sync, SLA |

**Key Features:**
- AuthKit (full authentication with extremely generous free tier)
- Enterprise SSO (SAML, OIDC)
- Directory Sync (SCIM)
- Admin Portal (self-serve SSO setup for customers)
- Audit Logs
- Fine-grained authorization (FGA)
- User management

**Strengths:**
- Most generous free tier in the market (1M MAU on AuthKit)
- Best-in-class SSO implementation
- Admin Portal for self-serve enterprise onboarding
- Per-connection SSO pricing is transparent
- Strong enterprise feature set

**Weaknesses:**
- SSO priced per connection ($125/connection/mo adds up quickly)
- Core identity expertise is enterprise SSO, not general auth
- AuthKit is relatively new compared to core SSO product
- No self-hosted option
- No open-source offering
- Limited multi-tenancy beyond SSO context

**Target Market:** SaaS companies selling to enterprise customers who need SSO/SCIM.

---

### 7. Descope

**Overview:** Descope is a drag-and-drop authentication platform that uses visual workflow builders to design auth flows. Raised $53M Series A. Focused on making complex authentication flows accessible without deep coding.

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| Free | $0/mo | 7,500 | All auth methods, flow builder |
| Starter | $0.05/MAU | Pay-per-use | Custom branding, connectors |
| Business | Custom | Custom | SSO/SAML, SCIM, SLA |

**Key Features:**
- Visual flow builder (drag-and-drop auth flows)
- Passwordless-first (OTP, magic links, passkeys, social)
- Connectors (integrate with external services in auth flows)
- Tenant management
- Step-up authentication
- Bot detection
- Pre-built UI widgets

**Strengths:**
- Visual flow builder is unique and accessible to non-developers
- Good passkey and passwordless implementation
- Flexible auth flow customization without code
- Decent free tier (7,500 MAU)
- Tenant management included

**Weaknesses:**
- Visual builder creates proprietary workflow lock-in
- SSO/SAML requires Business tier (custom pricing)
- Relatively new with smaller community
- Limited self-hosted options
- Per-MAU pricing on Starter tier scales linearly with growth
- Less control compared to code-first approaches

**Target Market:** Teams wanting no-code/low-code auth flow design; companies with non-technical product managers defining auth flows.

---

### 8. FusionAuth

**Overview:** FusionAuth is a self-hosted-first authentication platform that has been in the market since 2018. Offers a complete, downloadable auth server with a commercial model based on premium features and managed hosting. Written in Java.

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| Community (Self-Hosted) | $0 | Unlimited | Core auth, OAuth, MFA, themes |
| Cloud | $37/mo | 10,000 | Managed hosting |
| Essentials | $850/mo | Included | Advanced MFA, connectors, entity management |
| Enterprise | Custom | Custom | SCIM, breached password detection, support |

**Key Features:**
- Full self-hosted deployment (Docker, bare metal, cloud)
- Multi-tenancy built in
- Email/password, social login, MFA (TOTP, SMS, email)
- Passwordless (magic links)
- SAML and OIDC
- Advanced registration forms
- Theming engine
- Webhooks and event system
- Extensive API (REST)

**Strengths:**
- Mature self-hosted option with unlimited users on free tier
- Built-in multi-tenancy on all tiers
- Comprehensive feature set comparable to Auth0
- Data ownership and portability
- Good documentation
- Flexible theming

**Weaknesses:**
- Java-based -- heavier resource footprint than Go-based alternatives
- Community (free) tier lacks some important features (advanced MFA, connectors)
- Essentials tier is expensive ($850/mo)
- UI feels dated compared to Clerk or Descope
- No gRPC API
- No passkey/WebAuthn on Community tier
- Smaller community than open-source alternatives

**Target Market:** Companies wanting self-hosted auth with commercial support; mid-market B2B SaaS.

---

### 9. Kinde

**Overview:** Kinde is an Australian-based authentication and user management platform that has gained traction for its developer-friendly approach and competitive pricing. Raised $10.65M in funding. Positions itself as an Auth0 alternative with better pricing.

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| Free | $0/mo | 10,500 | All core auth, 3 environments |
| Pro | $25/mo + $0.035/MAU | 10,500 (then per-MAU) | Custom domains, advanced features |
| Business | $99/mo | Included | SSO/SAML, SCIM, advanced roles |

**Key Features:**
- Email/password, social, passwordless
- Multi-factor authentication
- Organizations (multi-tenancy)
- Feature flags (built-in)
- Roles and permissions
- Custom domains
- Webhooks
- SDK support for major frameworks

**Strengths:**
- Competitive pricing with generous free tier (10,500 MAU)
- Built-in feature flags (unique differentiator)
- Good developer experience
- Organizations/multi-tenancy available
- SSO at reasonable price point ($99/mo Business tier)

**Weaknesses:**
- Newer entrant with smaller ecosystem
- No self-hosted option
- Feature flags may overlap with existing tools (LaunchDarkly, etc.)
- Limited enterprise track record
- No gRPC API
- No passkey support at time of writing

**Target Market:** Startups and growing SaaS companies looking for an Auth0 alternative.

---

### 10. PropelAuth

**Overview:** PropelAuth is a B2B-focused authentication provider that emphasizes multi-tenancy (Organizations) and enterprise-readiness features. Smaller but well-regarded in the B2B SaaS community.

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| Free | $0/mo | 1,000 | Core auth, organizations |
| Startup | $100/mo | 5,000 | Custom domains, RBAC |
| Growth | $400/mo | 10,000 | SAML SSO, SCIM, advanced RBAC |

**Key Features:**
- B2B-focused with Organizations as a core primitive
- Role-based access control (RBAC)
- SAML SSO
- SCIM user provisioning
- Pre-built user management UIs
- Webhooks
- Multi-framework SDK support

**Strengths:**
- Purpose-built for B2B SaaS use cases
- Organizations and RBAC are first-class features
- Clean, well-documented API
- SSO/SAML at Growth tier ($400/mo) is cheaper than most

**Weaknesses:**
- Small free tier (1,000 MAU)
- No self-hosted option
- Smaller company -- risk factor for long-term viability
- Limited consumer/B2C features
- No passkey/WebAuthn support
- No gRPC API
- Pricing becomes expensive at scale

**Target Market:** B2B SaaS startups building multi-tenant applications.

---

### 11. Hanko

**Overview:** Hanko is an open-source, passkey-first authentication solution built by the team behind the FIDO Alliance's WebAuthn standard work. Strong focus on passwordless authentication with passkeys as a first-class citizen.

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| Self-Hosted | $0 | Unlimited | All core features |
| Cloud Free | $0/mo | 10,000 | Managed hosting |
| Pro | $29/mo + $0.03/MAU | Beyond included | Custom domains, priority support |

**Key Features:**
- Passkey-first authentication
- Pre-built web components (hanko-auth, hanko-profile)
- Email/password fallback
- Passcode (email OTP)
- OAuth/social login
- User management API
- Open source (AGPL)

**Strengths:**
- Best passkey/WebAuthn implementation in the market
- Open source with self-hosted option
- Clean, modern web components
- Strong standards expertise (FIDO Alliance involvement)
- Good free tier (10k MAU cloud)

**Weaknesses:**
- Narrow focus on passkeys -- less comprehensive feature set
- No multi-tenancy
- No SAML SSO
- No RBAC
- Smaller community and ecosystem
- AGPL license may be restrictive for some use cases
- No gRPC API
- Limited MFA options beyond passkeys

**Target Market:** Developers wanting to implement passkey-first authentication.

---

### 12. Ory

**Overview:** Ory is an open-source identity infrastructure company offering Kratos (identity management), Hydra (OAuth2/OIDC), Keto (authorization), and Oathkeeper (API gateway). Also offers Ory Network as a managed cloud service. One of the most established open-source identity projects.

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| Self-Hosted | $0 | Unlimited | All Ory projects (Kratos, Hydra, Keto, Oathkeeper) |
| Network Developer | $0/mo | 25,000 | Managed cloud, community support |
| Growth | $29/mo | Included | Custom domains, SLA, premium support |

**Key Features:**
- Ory Kratos: Identity management (login, registration, account recovery, MFA)
- Ory Hydra: Full OAuth2 and OpenID Connect provider
- Ory Keto: Authorization (relationships/permissions, Zanzibar-style)
- Ory Oathkeeper: Identity-aware API gateway
- Headless/API-first design
- Extensive customization via hooks and webhooks

**Strengths:**
- Most comprehensive open-source identity stack
- Apache 2.0 license (permissive)
- Cloud-native design (12-factor, stateless)
- Strong separation of concerns (identity vs authorization vs OAuth2)
- Active open-source community (30k+ GitHub stars across projects)
- Generous cloud free tier (25k MAU)

**Weaknesses:**
- Complexity -- four separate projects to understand and deploy
- Steep learning curve compared to all-in-one solutions
- Self-hosted deployment requires managing multiple services
- Documentation can be fragmented across projects
- Headless means no pre-built UI (must build your own)
- Configuration is YAML-heavy and can be error-prone
- No gRPC API for auth operations (REST only for most endpoints)

**Target Market:** DevOps teams and platform engineers who want full control over their identity stack.

---

### 13. SuperTokens

**Overview:** SuperTokens is an open-source authentication provider offering both self-hosted and managed cloud options. Focused on being the open-source Auth0 alternative with a straightforward feature set and pre-built UI components.

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| Self-Hosted | $0 | Unlimited | All core features |
| Cloud Free | $0/mo | 5,000 | Managed hosting |
| Pro | $0.02/MAU | Beyond 5,000 | Multi-tenancy, account linking, MFA |

**Key Features:**
- Email/password, passwordless (magic links, OTP)
- Social login (Apple, Google, GitHub, Facebook, and more)
- Session management with anti-CSRF
- Pre-built UI components (React)
- Multi-tenancy (paid feature)
- Account linking
- User roles and permissions
- MFA (TOTP)
- Webhooks

**Strengths:**
- Open source (Apache 2.0 license)
- Self-hosted with unlimited users
- Pre-built UI reduces integration time
- Straightforward feature set
- Good documentation
- Active community

**Weaknesses:**
- Multi-tenancy requires paid tier
- Pre-built UI is React-only
- Smaller feature set than Auth0 or Ory
- Cloud free tier is small (5k MAU)
- No passkey/WebAuthn support
- No SAML SSO on self-hosted free tier
- No gRPC API
- Node.js core -- heavier than Go-based alternatives

**Target Market:** Startups looking for an open-source, self-hostable Auth0 alternative.

---

### 14. Logto

**Overview:** Logto is an open-source identity solution that combines authentication, authorization, and user management. Offers a modern developer experience with a clean admin console and good multi-language SDK support. Growing rapidly in the open-source auth space.

**Pricing:**

| Tier | Price | MAU Included | Key Features |
|------|-------|-------------|--------------|
| Self-Hosted | $0 | Unlimited | All core features (OSS) |
| Cloud Free | $0/mo | 50,000 | Managed hosting, free for development |
| Pro | $16/mo | 100,000 | Custom domains, organizations, audit logs |

**Key Features:**
- Email/password, passwordless, social login
- Multi-factor authentication (TOTP, WebAuthn)
- OIDC-based (acts as an identity provider)
- Pre-built sign-in experience (customizable)
- Machine-to-machine authentication
- Organizations (multi-tenancy)
- RBAC
- Webhooks
- Audit logs (Pro tier)
- Admin console

**Strengths:**
- Very generous free tiers (self-hosted unlimited, cloud 50k MAU)
- Open source (MPL 2.0)
- Modern, clean design and admin console
- Good SDK coverage across languages
- OIDC-compliant (standards-based)
- Active development and growing community
- Lowest cloud paid tier pricing ($16/mo for 100k MAU)

**Weaknesses:**
- Organizations/multi-tenancy requires Pro tier on cloud
- Relatively new -- less battle-tested at scale
- Smaller ecosystem compared to Auth0 or Ory
- Self-hosted requires PostgreSQL + multiple components
- No gRPC API
- Community still growing
- Audit logs gated behind Pro tier on cloud

**Target Market:** Developers and startups wanting a modern, open-source identity solution with optional managed cloud.

---

## Comparison Matrix

| Feature | Auth0 | Clerk | Firebase Auth | Supabase Auth | Stytch | WorkOS | Descope | FusionAuth | Kinde | PropelAuth | Hanko | Ory | SuperTokens | Logto | **Our Service** |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **Free tier MAU** | 7,500 | 10,000 | 50,000 | 50,000 | 1,000 | 1,000,000 | 7,500 | Unlimited (self-hosted) | 10,500 | 1,000 | 10,000 | 25,000 | 5,000 | 50,000 | **Unlimited** |
| **Self-hosted** | No | No | No | Yes (complex) | No | No | No | Yes | No | No | Yes | Yes | Yes | Yes | **Yes** |
| **Open source** | No | No | No | Yes (GoTrue) | No | No | No | Partial | No | No | Yes (AGPL) | Yes (Apache 2.0) | Yes (Apache 2.0) | Yes (MPL 2.0) | **Yes (MIT)** |
| **Email/password** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | **Yes** |
| **Social login** | 30+ | 20+ | 10+ | 20+ | 10+ | 10+ | 15+ | 10+ | 15+ | 10+ | 5+ | Via Hydra | 10+ | 15+ | **4 (Google, GitHub, Microsoft, Apple)** |
| **MFA/TOTP** | Yes | Yes | SMS only | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Passkey-based | Yes | Yes | Yes | **Yes** |
| **Passkeys/WebAuthn** | Yes | Yes | No | No | Yes | Yes | Yes | Paid tier | No | No | Yes (core) | Yes | No | Yes | **Yes** |
| **Magic links** | Yes | Yes | No | Yes | Yes | No | Yes | Yes | Yes | Yes | No | Yes | Yes | Yes | **Yes** |
| **SSO/SAML** | Professional+ | Enterprise | Paid | Team ($599) | Enterprise | $125/conn | Business | Essentials ($850) | Business ($99) | Growth ($400) | No | Yes (Hydra) | Paid | Pro ($16) | **Planned** |
| **Multi-tenancy** | Professional+ | Yes | Paid (Identity Platform) | Limited | Yes | Limited | Yes | Yes (all tiers) | Yes | Yes (core) | No | Partial (Keto) | Paid | Pro | **Yes (all tiers)** |
| **RBAC** | Yes | Yes | No | Via RLS | Yes | Yes (FGA) | Yes | Yes | Yes | Yes | No | Yes (Keto) | Yes | Yes | **Planned** |
| **Pre-built UI** | Universal Login | React components | FirebaseUI | Auth UI | Widgets | AuthKit UI | Flow builder widgets | Themes | Hosted pages | Hosted pages | Web components | No (headless) | React components | Sign-in experience | **Hosted pages** |
| **Webhooks** | Yes | Yes | No | Via Edge Functions | Yes | Yes | Yes | Yes | Yes | Yes | No | Yes | Yes | Yes | **Yes** |
| **gRPC API** | No | No | No | No | No | No | No | No | No | No | No | No | No | No | **Yes** |
| **M2M auth** | Yes | No | Via custom tokens | No | Yes | Yes | Yes | Yes | No | No | No | Yes (Hydra) | No | Yes | **Planned** |
| **SCIM provisioning** | Enterprise | Enterprise | No | No | Enterprise | Yes | Business | Enterprise | Business | Growth | No | No | No | No | **Planned** |
| **Audit logging** | Yes (paid) | Yes | No | No | Yes | Yes | Yes | Yes (paid) | Yes | Yes | No | Via Keto | No | Pro | **Yes (all tiers)** |
| **Rate limiting** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | No | Via Oathkeeper | No | Yes | **Yes (built-in)** |
| **Custom domains** | Paid | Pro | N/A | Pro | Paid | Pro | Paid | Yes | Pro | Startup | Pro | Yes | N/A | Pro | **Yes (self-hosted)** |

---

## Pricing Comparison

Monthly cost at various MAU levels (cheapest available tier that supports the MAU count, excluding enterprise/custom tiers):

| MAU | Auth0 | Clerk | Firebase Auth | Supabase Auth | Stytch | WorkOS | Descope | FusionAuth | Kinde | PropelAuth | Hanko | Ory | SuperTokens | Logto | **Our Service** |
|-----|-------|-------|---------------|---------------|--------|--------|---------|------------|-------|------------|-------|-----|-------------|-------|-----------------|
| **1,000** | $35 | $0 | $0 | $0 | $0 | $0 | $0 | $0* | $0 | $0 | $0 | $0 | $0 | $0 | **$0** |
| **10,000** | $240+ | $0 | $0 | $0 | $249 | $0 | $125 | $37 | $0 | $100 | $0 | $0 | $100 | $0 | **$0** |
| **50,000** | Custom | $825 | $0 | $0 | $599+ | $0 | $2,125 | $37+ | $1,408 | $400+ | $1,229 | $29 | $900 | $0 | **$0** |
| **100,000** | Custom | $1,825 | Variable | $25 | $599+ | $0 | $4,625 | $37+ | $3,158 | Custom | $2,729 | $29 | $1,900 | $16 | **$0** |
| **500,000** | Custom | $9,825 | Variable | $25 | Custom | $0 | Custom | $37+ | Custom | Custom | Custom | $29 | $9,900 | $16+ | **$0** |
| **1,000,000** | Custom | $19,825 | Variable | $25 | Custom | $0 | Custom | $37+ | Custom | Custom | Custom | $29 | $19,900 | $16+ | **$0** |

*FusionAuth Community self-hosted is $0 at any MAU. Cloud pricing shown for managed hosting.*

**Our Service is self-hosted and always $0.** You pay only for your own infrastructure (a small VPS running PostgreSQL + Redis typically costs $5-20/mo and can handle hundreds of thousands of users).

**Key takeaway:** At 100,000 MAU, most competitors charge $500-$5,000/mo for their auth service alone. Our self-hosted approach eliminates this entirely. Even at 1,000,000 MAU, your total infrastructure cost remains under $50/mo on most cloud providers.

---

## Developer Pain Points We Solve

### Pricing Pain Points

**MAU-based pricing punishes growth.** The fundamental business model of most auth providers is misaligned with customer success. Every new user you acquire increases your auth costs. At scale, authentication becomes one of the largest line items in a SaaS company's infrastructure budget.

**Auth0 price increases post-Okta acquisition.** Developers report 2-5x price increases when renewing Auth0 contracts. The Okta acquisition has shifted Auth0 firmly upmarket, with free tier reductions and feature gating that makes it prohibitive for startups. This has been the single largest driver of Auth0-to-alternative migrations.

**Feature gating behind enterprise tiers.** Critical features for B2B SaaS -- SSO/SAML, multi-tenancy, audit logs, SCIM -- are consistently locked behind $400-$850+/mo enterprise tiers across most providers. This forces early-stage companies to either overpay or build these features themselves.

**Unpredictable costs from traffic spikes.** MAU-based pricing means a successful product launch, viral moment, or seasonal traffic spike can dramatically increase auth costs without warning. There is no cost ceiling on SaaS auth.

**No cost ceiling on SaaS auth.** Even at modest scale (100k users), companies commonly pay $1,000-$5,000/mo purely for authentication. At 1M users, costs can exceed $10,000-$20,000/mo. With self-hosted, your auth cost is effectively $0 regardless of scale.

### Technical Limitations

**Auth0 slow Universal Login.** Developers consistently report 2-5 second load times for Auth0's Universal Login page, which creates a poor user experience. This is an architectural limitation of the redirect-based approach combined with Auth0's infrastructure.

**Firebase lacks built-in RBAC, has limited MFA, and no webhooks.** Firebase Auth is generous on MAU but missing critical features. No role-based access control means building permissions from scratch. MFA is limited to SMS (no TOTP). No webhook support means no way to react to auth events in real-time.

**Clerk is Next.js-centric.** Clerk's developer experience is excellent for React/Next.js but deteriorates significantly for non-JavaScript backends. Go, Python, Ruby, and other backend developers face limited SDK support and documentation.

**Supabase Auth email deliverability issues.** Supabase Auth's default email setup (via Supabase's shared infrastructure) has well-documented deliverability problems. Teams frequently need to configure custom SMTP, which eliminates one of the key conveniences of using a managed service.

**No provider offers gRPC API alongside REST.** In microservice architectures, gRPC is the standard for service-to-service communication. Every auth provider in the market offers only REST APIs. Our dual REST+gRPC support is unique and eliminates the need for REST-to-gRPC translation layers.

### Vendor Lock-in

**Password hashes are non-exportable.** Auth0 and several other providers do not allow you to export bcrypt password hashes. This means migrating away requires forcing all users to reset their passwords -- a catastrophic user experience that makes migration effectively impossible at scale.

**Proprietary SDKs deeply embedded in code.** Auth provider SDKs get woven throughout application code -- middleware, route guards, user management, session handling. The deeper the integration, the more expensive the migration.

**Migration requires password resets for users.** Without exportable password hashes, the only option is to force password resets. For a consumer app with millions of users, this means losing a significant percentage of users who simply will not complete the reset flow.

**Auth0 Actions/Rules are proprietary.** Business logic implemented in Auth0 Actions or Rules is written against proprietary APIs and cannot be ported to any other system. This is custom code that must be entirely rewritten during migration.

**Clerk UI components create UI-level coupling.** Clerk's pre-built React components are convenient but create vendor lock-in at the UI layer. Migrating away from Clerk means rebuilding every authentication-related screen and component.

**Firebase security rules coupled to auth.** Firebase's security rules are deeply integrated with Firebase Auth. Moving to a different auth provider means rewriting your entire data access security model.

### Missing Features in the Market

**Most providers lack built-in multi-tenancy on free tiers.** Multi-tenancy is table-stakes for B2B SaaS, yet most providers gate it behind paid or enterprise tiers. Our service includes multi-tenancy on all tiers, including self-hosted.

**Passkeys are still bolted-on, not first-class.** Most providers have added passkey support as an afterthought. In many cases, it requires additional configuration, paid tiers, or has limitations (no cross-device support, no resident keys). Our service treats passkeys as a first-class authentication method alongside email/password.

**No good testing/local development story.** Most cloud auth providers make local development and testing painful. You need internet connectivity, test accounts, and often separate development environments that cost money. Self-hosted auth runs locally with zero external dependencies.

**Audit logging restricted to enterprise tiers.** Audit logs are a compliance requirement (SOC 2, HIPAA) but most providers charge extra for them. Our service logs every authentication event with IP, user agent, and metadata on all tiers.

**Rate limiting requires separate services.** Most auth providers either lack configurable rate limiting or implement it opaquely. Our service includes Redis-backed sliding window rate limiting that is configurable per endpoint, eliminating the need for a separate rate limiting layer.

---

## Our Competitive Advantages

### 1. Self-Hosted and Open Source -- Zero Vendor Lock-in, $0 Cost Forever

The service is MIT-licensed and fully self-hostable. You run it on your infrastructure, you own the code, and you pay nothing for the software itself. No MAU limits, no feature gates, no enterprise tier upsells. Your only cost is the infrastructure to run PostgreSQL, Redis, and a single Go binary.

### 2. Multi-Tenancy Built Into ALL Tiers

Multi-tenancy is a core architectural primitive, not an add-on. Register multiple client applications (tenants), each with isolated users, sessions, webhook URLs, and CORS origins. There is no paid tier required. This is how FusionAuth handles multi-tenancy, but unlike FusionAuth, our service is a lightweight Go binary, not a Java application.

### 3. Complete Authentication in One Service

Email/password, OAuth2 social login (Google, GitHub, Microsoft, Apple), magic links, passkeys (WebAuthn/FIDO2), and TOTP two-factor authentication -- all in a single service with a unified API. No need to stitch together multiple providers or services.

### 4. Both REST and gRPC APIs (Unique in the Market)

No other authentication provider offers a gRPC API alongside REST. For microservice architectures where gRPC is the standard inter-service communication protocol, this eliminates the need for REST-to-gRPC translation layers or sidecar proxies. The gRPC API includes AuthService, TokenService, and AdminService.

### 5. Per-Client JWT Secrets (True Tenant Isolation)

Each client (tenant) gets its own JWT signing secret. A compromised secret for one tenant does not affect any other tenant. Secrets can be rotated per-client without impacting other tenants. This is a level of isolation that most multi-tenant auth providers do not offer.

### 6. Built-In Rate Limiting and Audit Logging (Not Enterprise-Gated)

Redis-backed sliding window rate limiting and comprehensive audit logging (IP, user agent, event type, metadata) are included on all tiers, including self-hosted. Most competitors charge $400-$850+/mo for these features.

### 7. Importable JWT Validator Package for Go Services

The `pkg/jwtvalidator` package allows any Go service to validate JWTs issued by this authentication service without making network calls. Import the package, provide the client's JWT secret, and validate tokens locally. This eliminates the latency and availability dependency of token validation via API calls.

### 8. Full Data Ownership

Your database, your users, your password hashes (bcrypt, exportable). No data held hostage by a third party. Full GDPR compliance by design because you control where the data lives and how it is processed.

### 9. Simple Deployment

A single Go binary with no runtime dependencies beyond PostgreSQL and Redis. Deploy via Docker, Docker Compose, or drop a binary on a server. Migrations run automatically on startup. Coolify-ready for one-click deployment. Compare this to Ory's four-service architecture or Supabase's multi-container self-hosted setup.

### 10. No MAU-Based Pricing

It is your infrastructure and you control the costs. A $10/mo VPS can comfortably handle 100,000+ MAU. At the scale where competitors charge $5,000-$20,000/mo, your infrastructure cost remains under $50/mo.

---

## Suggested Pricing Model (Managed Cloud Offering)

| Tier | Price | MAU Included | Tenants | Support | Key Features |
|------|-------|-------------|---------|---------|--------------|
| **Self-Hosted** | **$0 forever** | **Unlimited** | **Unlimited** | Community (GitHub Issues) | Everything -- all features, all auth methods, full source code |
| **Cloud Starter** | **$29/mo** | 25,000 | 5 | Email (48hr response) | Managed hosting, automatic updates, daily backups |
| **Cloud Pro** | **$79/mo** | 100,000 | Unlimited | Priority email (24hr response) | Custom domains, premium email deliverability, weekly backups |
| **Cloud Business** | **$199/mo** | 500,000 | Unlimited | Dedicated support (4hr response) | SSO/SAML, SLA (99.95% uptime), SOC 2 report |
| **Cloud Enterprise** | **Custom** | Unlimited | Unlimited | Premium SLA, dedicated CSM | Custom features, on-prem deployment support, HIPAA BAA |

**Pricing philosophy:**
- Self-hosted is the PRIMARY offering. It is the full product with zero limitations.
- Cloud tiers exist purely for convenience (managed infrastructure, automatic updates, support SLA).
- Cloud pricing should always undercut competitors by 50-80% at equivalent MAU levels.
- No feature gating between self-hosted and cloud. Cloud customers pay for operations, not features.

**Comparison at 100k MAU:**

| Provider | Monthly Cost |
|----------|-------------|
| Auth0 | $2,000+ (estimated enterprise) |
| Clerk | $1,825 |
| Stytch | $599+ |
| SuperTokens | $1,900 |
| Kinde | $3,158 |
| **Our Cloud Pro** | **$79** |
| **Our Self-Hosted** | **$0** |

---

## Deep Research Prompts

The following prompts can be used with various research tools to gather additional competitive intelligence, market data, and developer sentiment. They are organized by platform for ease of use.

### ChatGPT / Claude Deep Research Prompts

**Prompt 1 -- Market Overview:**
"Analyze the authentication-as-a-service market in 2026. Compare pricing models (per-MAU vs flat-rate vs self-hosted), identify the top 10 providers by market share, and explain which pricing model is most developer-friendly and why."

**Prompt 2 -- Auth0 Post-Acquisition Sentiment:**
"Research developer sentiment about Auth0 after the Okta acquisition. What are the most common complaints? How many companies have migrated away and to which alternatives? Include data from Reddit, Hacker News, and developer surveys."

**Prompt 3 -- Total Cost of Ownership:**
"Compare the total cost of ownership (TCO) for authentication over 3 years for a SaaS app growing from 1,000 to 500,000 users: Auth0 vs Clerk vs self-hosted solution. Include engineering time, infrastructure costs, and auth provider costs."

**Prompt 4 -- Compliance Requirements:**
"What are the regulatory requirements (GDPR, HIPAA, SOC2, PCI-DSS) for authentication services? Which current providers meet all requirements? What's the market size for compliance-focused auth solutions?"

**Prompt 5 -- Passkey Adoption:**
"Research the passkey/WebAuthn adoption rate in 2025-2026. Which authentication providers have the best passkey implementation? What percentage of users prefer passkeys over passwords?"

**Prompt 6 -- B2B Auth Market:**
"Analyze the B2B SaaS authentication market specifically. What features do B2B companies need (SSO, SCIM, multi-tenancy, audit logs)? Which providers serve this market best and at what cost?"

**Prompt 7 -- Vendor Lock-in Stories:**
"Research authentication vendor lock-in stories. Find real examples of companies that struggled to migrate between auth providers. What was the cost, timeline, and user impact?"

**Prompt 8 -- Market Size:**
"What is the market size and growth rate for authentication-as-a-service in 2026? Break down by segment: B2C, B2B, enterprise, and self-hosted/open-source."

**Prompt 9 -- Open Source Comparison:**
"Compare open-source authentication solutions (Keycloak, Ory, SuperTokens, Logto, Hanko, Zitadel, Authentik) by feature completeness, community size, GitHub stars, deployment complexity, and production readiness."

**Prompt 10 -- YC Startup Auth Choices:**
"Research how YC-backed startups handle authentication. What percentage use third-party auth vs build their own? Which providers are most popular among YC companies?"

### Perplexity Research Prompts

**Prompt 11 -- Funding and Valuations:**
"What are the latest funding rounds and valuations for authentication startups (Clerk, Stytch, Descope, WorkOS, Kinde) in 2025-2026? How does funding correlate with product quality?"

**Prompt 12 -- Real Enterprise Pricing:**
"Find real pricing quotes from Auth0, Stytch, and WorkOS enterprise tiers shared publicly by developers. What are companies actually paying?"

**Prompt 13 -- Most Requested Features:**
"What authentication features are most requested by developers in 2026? Analyze GitHub issues, feature request boards, and community forums of top auth providers."

**Prompt 14 -- Self-Hosted Trend:**
"Research the self-hosted authentication trend. Is developer preference shifting from managed SaaS to self-hosted? Provide data from surveys, GitHub star trends, and download statistics."

**Prompt 15 -- Security Vulnerabilities:**
"What are the most common security vulnerabilities in authentication implementations? How do major auth providers (Auth0, Clerk, Firebase) handle these vs self-hosted solutions?"

### Google Gemini Deep Research Prompts

**Prompt 16 -- Market Map:**
"Create a comprehensive market map of the authentication industry in 2026, including all players, their positioning (enterprise vs startup, managed vs self-hosted), pricing models, and recent strategic moves."

**Prompt 17 -- Conversion Funnels:**
"Analyze the developer tool market for authentication. What is the typical conversion funnel from free tier to paid? What are the churn rates for major auth providers?"

**Prompt 18 -- Multi-Tenancy Approaches:**
"Research multi-tenancy implementation approaches across auth providers. Compare Auth0 Organizations, Clerk Organizations, WorkOS Organizations, and self-hosted multi-tenant approaches. Which is most flexible?"

**Prompt 19 -- Build vs Buy Sentiment:**
"What is the developer community sentiment about building auth in-house vs using a third-party service in 2026? Has this changed from 2023-2024?"

**Prompt 20 -- Auth + Authz Convergence:**
"Analyze the intersection of authentication and authorization. Which providers are expanding from authn to authz? What's the market opportunity for combined auth+authz platforms?"

### Twitter/X Research Prompts

**Prompt 21 -- Developer Complaints:**
"Search Twitter for complaints about Auth0 pricing, Clerk limitations, and Firebase Auth problems from developers in the past 6 months. What patterns emerge?"

**Prompt 22 -- CTO Stack Choices:**
"Find tweets from CTOs and tech leads discussing their authentication stack choices and migrations in 2025-2026."

### Reddit Research Prompts

**Prompt 23 -- Subreddit Analysis:**
"Search r/SaaS, r/webdev, r/nextjs, and r/golang for discussions about authentication service choices. What are the most upvoted recommendations and the most common warnings?"

**Prompt 24 -- Cost at Scale:**
"Find Reddit threads where developers discuss the cost of authentication at scale (100k+ users). What are the real-world numbers they share?"

**Prompt 25 -- Migration Stories:**
"Search for discussions about migrating away from Auth0, Clerk, or Firebase Auth. What alternatives did developers choose and why?"

---

*This document should be reviewed and updated quarterly as the competitive landscape evolves rapidly. Pricing data was compiled from public pricing pages and may not reflect negotiated enterprise rates.*
