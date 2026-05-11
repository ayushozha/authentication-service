package rest

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openapiSpec []byte

func DocsSpecHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	w.Write(openapiSpec)
}

func DocsUIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(docsHTML))
}

const docsHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authentication Service — API Reference</title>
  <meta name="description" content="API reference for the multi-tenant Authentication Service" />
  <style>
    :root {
      color-scheme: light;
      --ink: #111827;
      --muted: #5b6472;
      --subtle: #eef2f7;
      --surface: #ffffff;
      --surface-soft: #f7f9fc;
      --line: #d7dee8;
      --blue: #2454a6;
      --teal: #0f766e;
      --amber: #a45b13;
      --code: #121826;
    }

    * { box-sizing: border-box; }

    html { scroll-behavior: smooth; }

    body {
      margin: 0;
      background: var(--surface-soft);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }

    a { color: inherit; text-decoration: none; }

    .docs-topbar {
      position: sticky;
      top: 0;
      z-index: 20;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 18px;
      min-height: 64px;
      padding: 12px 24px;
      background: rgba(255, 255, 255, 0.94);
      border-bottom: 1px solid var(--line);
      backdrop-filter: blur(14px);
    }

    .brand {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      min-width: 0;
    }

    .brand-mark {
      display: grid;
      place-items: center;
      width: 36px;
      height: 36px;
      flex: 0 0 auto;
      border-radius: 8px;
      background: var(--ink);
      color: #fff;
      font-weight: 800;
      font-size: 14px;
    }

    .brand-copy { min-width: 0; }

    .brand-title {
      margin: 0;
      font-size: 14px;
      line-height: 1.2;
      font-weight: 800;
    }

    .brand-subtitle {
      margin: 2px 0 0;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.2;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .top-actions {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }

    .top-actions a,
    .pill-link {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 34px;
      padding: 0 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      color: #243041;
      font-size: 13px;
      font-weight: 700;
    }

    .top-actions a.primary {
      border-color: #1f2937;
      background: #1f2937;
      color: #fff;
    }

    .docs-hero {
      background: #fff;
      border-bottom: 1px solid var(--line);
    }

    .docs-hero-inner {
      max-width: 1180px;
      margin: 0 auto;
      padding: 36px 24px 28px;
    }

    .kicker {
      margin: 0 0 10px;
      color: var(--teal);
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }

    h1 {
      max-width: 880px;
      margin: 0;
      font-size: clamp(34px, 5vw, 58px);
      line-height: 1.02;
      letter-spacing: 0;
    }

    .hero-copy {
      max-width: 820px;
      margin: 16px 0 0;
      color: #3e4857;
      font-size: 18px;
      line-height: 1.65;
    }

    .signal-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-top: 26px;
    }

    .signal-card {
      min-height: 112px;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--surface-soft);
    }

    .signal-card strong {
      display: block;
      margin-bottom: 8px;
      font-size: 14px;
    }

    .signal-card span {
      display: block;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
    }

    .quickstart-band {
      border-top: 1px solid var(--line);
      background: #f8fafc;
    }

    .quickstart-inner {
      display: grid;
      grid-template-columns: minmax(0, 1.05fr) minmax(320px, 0.95fr);
      gap: 22px;
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px;
    }

    .guide-column h2,
    .code-panel h2 {
      margin: 0 0 12px;
      font-size: 18px;
      line-height: 1.25;
    }

    .guide-steps {
      display: grid;
      gap: 10px;
      margin: 0;
      padding: 0;
      list-style: none;
    }

    .guide-steps li {
      display: grid;
      grid-template-columns: 32px minmax(0, 1fr);
      gap: 10px;
      align-items: start;
      color: #394457;
      font-size: 14px;
      line-height: 1.5;
    }

    .step-number {
      display: grid;
      place-items: center;
      width: 28px;
      height: 28px;
      border-radius: 8px;
      background: #e8f3f1;
      color: var(--teal);
      font-weight: 800;
      font-size: 12px;
    }

    .code-panel {
      min-width: 0;
      padding: 18px;
      border: 1px solid #283244;
      border-radius: 8px;
      background: var(--code);
      color: #f8fafc;
    }

    .code-panel p {
      margin: 0 0 12px;
      color: #b8c2d2;
      font-size: 13px;
      line-height: 1.5;
    }

    pre {
      margin: 0;
      overflow-x: auto;
      white-space: pre;
      font: 13px/1.55 ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    }

    .reference-jump {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      max-width: 1180px;
      margin: 0 auto;
      padding: 16px 24px 22px;
      background: #f8fafc;
    }

    .reference-jump .pill-link:nth-child(2n) { color: var(--blue); }
    .reference-jump .pill-link:nth-child(3n) { color: var(--amber); }
    .reference-jump .pill-link:nth-child(4n) { color: var(--teal); }

    .api-reference-wrap {
      min-height: 820px;
      background: #fff;
      border-top: 1px solid var(--line);
    }

    @media (max-width: 900px) {
      .docs-topbar { align-items: flex-start; flex-direction: column; }
      .top-actions { justify-content: flex-start; }
      .signal-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .quickstart-inner { grid-template-columns: 1fr; }
    }

    @media (max-width: 560px) {
      .docs-topbar { padding: 12px 16px; }
      .docs-hero-inner,
      .quickstart-inner,
      .reference-jump { padding-left: 16px; padding-right: 16px; }
      .signal-grid { grid-template-columns: 1fr; }
      h1 { font-size: 36px; }
      .hero-copy { font-size: 16px; }
      .top-actions a,
      .pill-link { width: 100%; }
    }
  </style>
</head>
<body>
  <header class="docs-topbar">
    <a class="brand" href="/docs" aria-label="Authentication Service documentation home">
      <span class="brand-mark">AS</span>
      <span class="brand-copy">
        <span class="brand-title">Authentication Service</span>
        <span class="brand-subtitle">Self-hosted multi-tenant auth for products and platforms</span>
      </span>
    </a>
    <nav class="top-actions" aria-label="Documentation links">
      <a href="/docs/openapi.yaml">OpenAPI YAML</a>
      <a href="https://github.com/Ayush10/authentication-service">Repository</a>
      <a class="primary" href="#tag/Authentication/operation/login">Start integrating</a>
    </nav>
  </header>

  <main>
    <section class="docs-hero" aria-labelledby="docs-title">
      <div class="docs-hero-inner">
        <p class="kicker">Provider-grade auth, owned by your infrastructure</p>
        <h1 id="docs-title">Build login, MFA, passkeys, OAuth, JWT validation, and audit trails from one service.</h1>
        <p class="hero-copy">
          AuthService gives companies a production-ready authentication layer with tenant isolation, REST and gRPC APIs, refresh-token rotation, JWKS, rate limits, and integration patterns for browser, mobile, backend, and microservice products.
        </p>

        <div class="signal-grid" aria-label="AuthService strengths">
          <div class="signal-card">
            <strong>Multi-tenant by default</strong>
            <span>Each product or environment gets isolated users, API keys, origins, sessions, and signing material.</span>
          </div>
          <div class="signal-card">
            <strong>Modern auth flows</strong>
            <span>Email/password, magic links, TOTP, OAuth2, and WebAuthn passkeys are documented in one reference.</span>
          </div>
          <div class="signal-card">
            <strong>Microservice friendly</strong>
            <span>Validate JWTs locally with JWKS or the Go validator, or call the gRPC TokenService.</span>
          </div>
          <div class="signal-card">
            <strong>Operator visibility</strong>
            <span>Client provisioning, key rotation, health checks, JWKS, and queryable audit events are built in.</span>
          </div>
        </div>
      </div>
    </section>

    <section class="quickstart-band" aria-label="Integration quickstart">
      <div class="quickstart-inner">
        <div class="guide-column">
          <h2>Integration path</h2>
          <ol class="guide-steps">
            <li><span class="step-number">1</span><span>Create a client with the admin API and save the returned API key.</span></li>
            <li><span class="step-number">2</span><span>Choose cookie mode for browser sessions or token mode for native, CLI, SSR, and API clients.</span></li>
            <li><span class="step-number">3</span><span>Authenticate users through signup, login, OAuth, magic links, TOTP, or passkeys.</span></li>
            <li><span class="step-number">4</span><span>Validate access tokens in your product APIs with JWKS, gRPC, or the Go validator package.</span></li>
          </ol>
        </div>

        <div class="code-panel">
          <h2>Production login request</h2>
          <p>Token transport returns a refresh token in JSON for non-browser clients. Browser clients can omit token_transport and use the HttpOnly cookie.</p>
          <pre><code>curl -X POST https://authservice.ayushojha.com/api/auth/login \
  -H "X-API-Key: $AUTH_SERVICE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "correct-horse-battery-staple",
    "token_transport": "json"
  }'</code></pre>
        </div>
      </div>

      <div class="reference-jump" aria-label="Jump to API sections">
        <a class="pill-link" href="#tag/Authentication">Authentication</a>
        <a class="pill-link" href="#tag/Passkeys">Passkeys</a>
        <a class="pill-link" href="#tag/TOTP">TOTP 2FA</a>
        <a class="pill-link" href="#tag/OAuth2">OAuth2</a>
        <a class="pill-link" href="#tag/Magic-Links">Magic Links</a>
        <a class="pill-link" href="#tag/Admin">Admin</a>
        <a class="pill-link" href="#tag/Utility/operation/getJwks">JWKS</a>
        <a class="pill-link" href="#tag/Admin/operation/listAuditEvents">Audit Events</a>
      </div>
    </section>

    <section class="api-reference-wrap" aria-label="OpenAPI reference">
      <script
        id="api-reference"
        data-url="/docs/openapi.yaml"
        data-configuration='{
          "theme": "kepler",
          "layout": "modern",
          "darkMode": false,
          "hiddenClients": ["cohttp"],
          "defaultHttpClient": { "targetKey": "shell", "clientKey": "curl" },
          "metaData": {
            "title": "Authentication Service API",
            "description": "Integration-ready API documentation for AuthService"
          },
          "authentication": {
            "preferredSecurityScheme": "ApiKeyAuth"
          }
        }'
      ></script>
    </section>
  </main>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>
`
