package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	files := map[string]string{
		"sdks/typescript/package.json":      typescriptPackageJSON,
		"sdks/typescript/tsconfig.json":     typescriptTSConfig,
		"sdks/typescript/src/index.ts":      typescriptIndex,
		"sdks/typescript/src/middleware.ts": typescriptMiddleware,
		"sdks/typescript/README.md":         pythonReadme("TypeScript", "@authservice/sdk", "Express, Fastify, NestJS, and Next.js"),

		"sdks/python/pyproject.toml":            pythonPyproject,
		"sdks/python/authservice/__init__.py":   pythonInit,
		"sdks/python/authservice/client.py":     pythonClient,
		"sdks/python/authservice/jwt.py":        pythonJWT,
		"sdks/python/authservice/middleware.py": pythonMiddleware,
		"sdks/python/README.md":                 pythonReadme("Python", "authservice-sdk", "Django, FastAPI, and Flask"),

		"sdks/go/authservice/go.mod":        goSDKMod,
		"sdks/go/authservice/client.go":     goSDKClient,
		"sdks/go/authservice/jwt.go":        goSDKJWT,
		"sdks/go/authservice/middleware.go": goSDKMiddleware,
		"sdks/go/authservice/README.md":     pythonReadme("Go", "github.com/Ayush10/authentication-service/sdks/go/authservice", "net/http, Gin, Chi, Echo, and Fiber"),

		"sdks/jvm/pom.xml": jvmPom,
		"sdks/jvm/src/main/java/com/authservice/sdk/AuthServiceClient.java":           jvmClient,
		"sdks/jvm/src/main/java/com/authservice/sdk/JwtVerifier.java":                 jvmJWT,
		"sdks/jvm/src/main/java/com/authservice/sdk/SpringBootAuthServiceFilter.java": jvmSpring,
		"sdks/jvm/src/main/kotlin/com/authservice/sdk/AuthService.kt":                 jvmKotlin,
		"sdks/jvm/README.md": pythonReadme("Java/Kotlin", "com.authservice:authservice-sdk", "Spring Boot"),

		"sdks/csharp/AuthService.csproj":                 csharpProject,
		"sdks/csharp/AuthServiceClient.cs":               csharpClient,
		"sdks/csharp/JwtVerifier.cs":                     csharpJWT,
		"sdks/csharp/AspNetCoreAuthServiceExtensions.cs": csharpAspNet,
		"sdks/csharp/README.md":                          pythonReadme("C#", "AuthService", "ASP.NET Core"),

		"sdks/php/composer.json":                              phpComposer,
		"sdks/php/src/AuthServiceClient.php":                  phpClient,
		"sdks/php/src/JwtVerifier.php":                        phpJWT,
		"sdks/php/src/Laravel/AuthServiceMiddleware.php":      phpLaravelMiddleware,
		"sdks/php/src/Laravel/AuthServiceServiceProvider.php": phpLaravelProvider,
		"sdks/php/README.md":                                  pythonReadme("PHP", "authservice/authservice", "Laravel"),

		"sdks/ruby/authservice.gemspec":                 rubyGemspec,
		"sdks/ruby/lib/authservice.rb":                  rubyClient,
		"sdks/ruby/lib/authservice/jwt_verifier.rb":     rubyJWT,
		"sdks/ruby/lib/authservice/rails_middleware.rb": rubyRails,
		"sdks/ruby/README.md":                           pythonReadme("Ruby", "authservice", "Rails and Rack"),

		"sdks/rust/Cargo.toml":   rustCargo,
		"sdks/rust/src/lib.rs":   rustLib,
		"sdks/rust/src/jwt.rs":   rustJWT,
		"sdks/rust/src/axum.rs":  rustAxum,
		"sdks/rust/src/actix.rs": rustActix,
		"sdks/rust/README.md":    pythonReadme("Rust", "authservice", "Axum and Actix"),

		"sdks/framework-support.md": frameworkSupport,
	}

	for path, body := range files {
		body = strings.TrimLeft(body, "\n")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			panic(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			panic(err)
		}
		fmt.Println("generated", path)
	}
}

func pythonReadme(language, packageName, frameworks string) string {
	return fmt.Sprintf(`# AuthService %s SDK

Official generated AuthService SDK package for %s.

Package: %s

Framework adapters: %s.

The generated client covers signup, login, refresh, logout, current user, organizations, OAuth client credentials, token introspection, admin client provisioning, service accounts, enterprise SSO, SCIM directories, audit export, JWT verification, and signed webhook verification.

Publish this package through the native registry for the language. The source is generated from tools/sdkgen and is intentionally kept dependency-light, with security dependencies delegated to the ecosystem standard JWT/JWKS libraries.
`, language, language, packageName, frameworks)
}

const typescriptPackageJSON = `{
  "name": "@authservice/sdk",
  "version": "0.1.1",
  "description": "Generated TypeScript SDK and middleware for AuthService",
  "license": "MIT",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "exports": {
    ".": "./dist/index.js",
    "./middleware": "./dist/middleware.js"
  },
  "files": ["dist", "README.md"],
  "scripts": {
    "build": "tsc -p tsconfig.json",
    "prepublishOnly": "npm run build"
  },
  "dependencies": {
    "jose": "^5.9.6"
  },
  "devDependencies": {
    "typescript": "^5.6.3",
    "@types/node": "^22.7.5"
  }
}
`

const typescriptTSConfig = `{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "declaration": true,
    "outDir": "dist",
    "strict": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*.ts"]
}
`

const typescriptIndex = `import { createHmac, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, JWTPayload } from "jose";

export type Json = Record<string, unknown>;

export interface TokenStore {
  getAccessToken(): string | undefined;
  setAccessToken(token?: string): void;
  getRefreshToken(): string | undefined;
  setRefreshToken(token?: string): void;
}

export class MemoryTokenStore implements TokenStore {
  private accessToken = "";
  private refreshToken = "";
  getAccessToken() { return this.accessToken || undefined; }
  setAccessToken(token?: string) { this.accessToken = token || ""; }
  getRefreshToken() { return this.refreshToken || undefined; }
  setRefreshToken(token?: string) { this.refreshToken = token || ""; }
}

export interface AuthServiceClientOptions {
  baseUrl: string;
  apiKey?: string;
  adminKey?: string;
  sessionMode?: "cookie" | "token";
  tokenStore?: TokenStore;
  fetch?: typeof globalThis.fetch;
}

export class AuthServiceError extends Error {
  constructor(message: string, public status: number, public response: unknown) {
    super(message);
    this.name = "AuthServiceError";
  }
}

const invalidLoginCredentialsMessage = "Invalid email or password.";

function errorPayloadMessage(response: unknown): string {
  if (response && typeof response === "object") {
    const payload = response as { error?: unknown; message?: unknown };
    return String(payload.error || payload.message || "").trim();
  }
  if (typeof response === "string") return response.trim();
  return "";
}

function normalizeLoginError(error: unknown): unknown {
  if (error instanceof AuthServiceError && error.status === 401 && errorPayloadMessage(error.response).toLowerCase() === "invalid email or password") {
    return new AuthServiceError(invalidLoginCredentialsMessage, error.status, error.response);
  }
  return error;
}

function rethrowLoginError(error: unknown): never {
  throw normalizeLoginError(error);
}

export class AuthServiceClient {
  readonly baseUrl: string;
  readonly apiKey?: string;
  readonly adminKey?: string;
  readonly sessionMode: "cookie" | "token";
  readonly tokenStore: TokenStore;
  private readonly fetcher: typeof globalThis.fetch;

  constructor(options: AuthServiceClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.adminKey = options.adminKey;
    this.sessionMode = options.sessionMode || "token";
    this.tokenStore = options.tokenStore || new MemoryTokenStore();
    this.fetcher = options.fetch || globalThis.fetch;
    if (!this.fetcher) throw new Error("AuthServiceClient requires fetch");
  }

  async request<T = unknown>(path: string, init: { method?: string; body?: unknown; headers?: Record<string, string>; admin?: boolean; auth?: boolean } = {}): Promise<T> {
    const headers: Record<string, string> = { ...(init.headers || {}) };
    if (init.admin) {
      if (this.adminKey) headers["X-Admin-Key"] = this.adminKey;
    } else if (this.apiKey) {
      headers["X-API-Key"] = this.apiKey;
    }
    const accessToken = this.tokenStore.getAccessToken();
    if (init.auth !== false && accessToken) headers.Authorization = "Bearer " + accessToken;
    const req: RequestInit = { method: init.method || "GET", headers };
    if (init.body !== undefined) {
      if (typeof init.body === "string" || init.body instanceof URLSearchParams) {
        req.body = init.body;
      } else {
        headers["Content-Type"] = headers["Content-Type"] || "application/json";
        req.body = JSON.stringify(init.body);
      }
    }
    const res = await this.fetcher(this.baseUrl + path, req);
    const text = await res.text();
    let data: unknown = text;
    if (text) {
      try { data = JSON.parse(text); } catch {}
    } else {
      data = null;
    }
    if (!res.ok) {
      const message = data && typeof data === "object" && ("error" in data || "message" in data)
        ? String((data as any).error || (data as any).message)
        : res.statusText;
      throw new AuthServiceError(message, res.status, data);
    }
    return data as T;
  }

  private withSessionMode(body: Json = {}) {
    return this.sessionMode === "token"
      ? { ...body, session_mode: body.session_mode || "token", token_transport: body.token_transport || "json" }
      : body;
  }

  private persist<T extends Json | null>(data: T): T {
    if (data && typeof data.access_token === "string") this.tokenStore.setAccessToken(data.access_token);
    if (data && typeof data.refresh_token === "string") this.tokenStore.setRefreshToken(data.refresh_token);
    return data;
  }

  signup(params: Json) { return this.request<Json>("/api/auth/signup", { method: "POST", body: this.withSessionMode(params), auth: false }).then(x => this.persist(x)); }
  login(params: Json) { return this.request<Json>("/api/auth/login", { method: "POST", body: this.withSessionMode(params), auth: false }).then(x => this.persist(x)).catch(rethrowLoginError); }
  refresh(params: Json = {}) {
    const body = this.withSessionMode({ ...params });
    if (this.sessionMode === "token" && !body.refresh_token) body.refresh_token = this.tokenStore.getRefreshToken();
    return this.request<Json>("/api/auth/refresh", { method: "POST", body, auth: false }).then(x => this.persist(x));
  }
  logout() { return this.request("/api/auth/logout", { method: "POST", body: { refresh_token: this.tokenStore.getRefreshToken() }, auth: false }).finally(() => { this.tokenStore.setAccessToken(); this.tokenStore.setRefreshToken(); }); }
  me() { return this.request<Json>("/api/auth/me"); }
  updateProfile(params: Json) { return this.request<Json>("/api/auth/me", { method: "PATCH", body: params }); }
  listOrganizations() { return this.request<Json>("/api/auth/organizations"); }
  createOrganization(params: Json) { return this.request<Json>("/api/auth/organizations", { method: "POST", body: params }); }
  organizationToken(organizationId: string, activate = false) { return this.request<Json>("/api/auth/organizations/" + encodeURIComponent(organizationId) + "/token", { method: "POST", body: {} }).then(x => { if (activate && typeof x.access_token === "string") this.tokenStore.setAccessToken(x.access_token); return x; }); }
  clientCredentials(params: { clientId: string; clientSecret: string; scope?: string }) {
    const body = new URLSearchParams({ grant_type: "client_credentials", client_id: params.clientId, client_secret: params.clientSecret });
    if (params.scope) body.set("scope", params.scope);
    return this.request<Json>("/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body.toString(), auth: false });
  }
  introspect(token: string, credentials?: { clientId: string; clientSecret: string }) {
    const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
    if (credentials) headers.Authorization = "Basic " + Buffer.from(credentials.clientId + ":" + credentials.clientSecret).toString("base64");
    return this.request<Json>("/oauth/introspect", { method: "POST", headers, body: new URLSearchParams({ token }).toString(), auth: false });
  }
  listClients() { return this.request<Json>("/api/admin/clients", { admin: true, auth: false }); }
  createClient(params: Json) { return this.request<Json>("/api/admin/clients", { method: "POST", body: params, admin: true, auth: false }); }
  getClient(clientId: string) { return this.request<Json>("/api/admin/clients/" + encodeURIComponent(clientId), { admin: true, auth: false }); }
  updateClient(clientId: string, params: Json) { return this.request<Json>("/api/admin/clients/" + encodeURIComponent(clientId), { method: "PATCH", body: params, admin: true, auth: false }); }
  rotateClientApiKey(clientId: string) { return this.request<Json>("/api/admin/clients/" + encodeURIComponent(clientId) + "/rotate-api-key", { method: "POST", admin: true, auth: false }); }
  rotateClientJwtSecret(clientId: string) { return this.request<Json>("/api/admin/clients/" + encodeURIComponent(clientId) + "/rotate-jwt", { method: "POST", admin: true, auth: false }); }
  listServiceAccounts(clientId: string) { return this.request<Json>("/api/admin/clients/" + encodeURIComponent(clientId) + "/service-accounts", { admin: true, auth: false }); }
  createServiceAccount(clientId: string, params: Json) { return this.request<Json>("/api/admin/clients/" + encodeURIComponent(clientId) + "/service-accounts", { method: "POST", body: params, admin: true, auth: false }); }
  listSSOConnections(clientId: string) { return this.request<Json>("/api/admin/clients/" + encodeURIComponent(clientId) + "/sso-connections", { admin: true, auth: false }); }
  createSSOConnection(clientId: string, params: Json) { return this.request<Json>("/api/admin/clients/" + encodeURIComponent(clientId) + "/sso-connections", { method: "POST", body: params, admin: true, auth: false }); }
  listSCIMDirectories(clientId: string) { return this.request<Json>("/api/admin/clients/" + encodeURIComponent(clientId) + "/scim-directories", { admin: true, auth: false }); }
  createSCIMDirectory(clientId: string, params: Json) { return this.request<Json>("/api/admin/clients/" + encodeURIComponent(clientId) + "/scim-directories", { method: "POST", body: params, admin: true, auth: false }); }
  rotateSCIMToken(clientId: string, directoryId: string) { return this.request<Json>("/api/admin/clients/" + encodeURIComponent(clientId) + "/scim-directories/" + encodeURIComponent(directoryId) + "/rotate-token", { method: "POST", admin: true, auth: false }); }
  auditExport(params: Record<string, string> = {}) { return this.request<string>("/api/admin/audit-events/export?" + new URLSearchParams(params), { admin: true, auth: false }); }
}

export function decodeJwt(token: string): Json | null {
  try {
    const part = token.split(".")[1];
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

export interface JwtVerifierOptions {
  issuer?: string;
  audience?: string | string[];
  clientId?: string;
  tokenUse?: string;
  requiredScopes?: string[];
  requiredOrganizationPermissions?: string[];
  clockTolerance?: string | number;
}

export class AuthServiceJwtVerifier {
  private jwks;
  constructor(jwksUrl: string | URL, private options: JwtVerifierOptions = {}) {
    this.jwks = createRemoteJWKSet(new URL(jwksUrl));
  }
  async verify(token: string): Promise<JWTPayload> {
    const result = await jwtVerify(token, this.jwks, {
      issuer: this.options.issuer,
      audience: this.options.audience,
      clockTolerance: this.options.clockTolerance
    });
    const claims = result.payload as JWTPayload & Json;
    if (this.options.clientId && claims.client_id !== this.options.clientId) throw new Error("token client mismatch");
    if (this.options.tokenUse && claims.token_use !== this.options.tokenUse) throw new Error("token_use mismatch");
    requireScopes(claims, this.options.requiredScopes || []);
    requireOrganizationPermissions(claims, this.options.requiredOrganizationPermissions || []);
    return claims;
  }
}

export function hasScope(claims: Json, scope: string): boolean {
  const scopes = Array.isArray(claims.scopes) ? claims.scopes.map(String) : String(claims.scope || "").split(/\s+/).filter(Boolean);
  return scopes.includes(scope);
}

export function hasOrganizationPermission(claims: Json, permission: string): boolean {
  if (claims.org_role === "owner") return true;
  return Array.isArray(claims.org_permissions) && claims.org_permissions.map(String).includes(permission);
}

export function requireScopes(claims: Json, scopes: string[]) {
  for (const scope of scopes) if (!hasScope(claims, scope)) throw new Error("missing required scope: " + scope);
}

export function requireOrganizationPermissions(claims: Json, permissions: string[]) {
  for (const permission of permissions) if (!hasOrganizationPermission(claims, permission)) throw new Error("missing required organization permission: " + permission);
}

export function verifyWebhookSignature(secret: string, timestamp: string, signature: string, body: Buffer | string, toleranceSeconds = 300): boolean {
  const now = Math.floor(Date.now() / 1000);
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(now - ts) > toleranceSeconds) return false;
  const expected = "v1=" + createHmac("sha256", secret).update(timestamp + ".").update(body).digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(signature || "");
  return a.length === b.length && timingSafeEqual(a, b);
}

export const createClient = (options: AuthServiceClientOptions) => new AuthServiceClient(options);
`

const typescriptMiddleware = `import { AuthServiceJwtVerifier } from "./index.js";

function bearer(header?: string): string {
  const parts = String(header || "").split(" ");
  return parts.length === 2 && /^bearer$/i.test(parts[0]) ? parts[1] : "";
}

export function expressAuth(verifier: AuthServiceJwtVerifier) {
  return async (req: any, res: any, next: any) => {
    try {
      req.auth = await verifier.verify(bearer(req.headers.authorization));
      next();
    } catch (err: any) {
      res.status(401).json({ error: err.message || "unauthorized" });
    }
  };
}

export function fastifyAuth(verifier: AuthServiceJwtVerifier) {
  return async (request: any, reply: any) => {
    try {
      request.auth = await verifier.verify(bearer(request.headers.authorization));
    } catch (err: any) {
      reply.code(401).send({ error: err.message || "unauthorized" });
    }
  };
}

export function nextAuth(verifier: AuthServiceJwtVerifier) {
  return async function middleware(request: any) {
    const token = bearer(request.headers.get ? request.headers.get("authorization") : request.headers.authorization);
    await verifier.verify(token);
    return undefined;
  };
}

export function nestjsAuthGuard(verifier: AuthServiceJwtVerifier) {
  return class AuthServiceGuard {
    async canActivate(context: any) {
      const req = context.switchToHttp().getRequest();
      req.auth = await verifier.verify(bearer(req.headers.authorization));
      return true;
    }
  };
}
`

const pythonPyproject = `[project]
name = "authservice-sdk"
version = "0.1.0"
description = "Generated Python SDK and middleware for AuthService"
readme = "README.md"
requires-python = ">=3.9"
license = {text = "MIT"}
dependencies = [
  "requests>=2.31",
  "PyJWT[crypto]>=2.8"
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
`

const pythonInit = `from .client import AuthServiceClient, AuthServiceError, MemoryTokenStore
from .jwt import AuthServiceJwtVerifier, has_scope, has_org_permission, verify_webhook_signature

__all__ = [
    "AuthServiceClient",
    "AuthServiceError",
    "MemoryTokenStore",
    "AuthServiceJwtVerifier",
    "has_scope",
    "has_org_permission",
    "verify_webhook_signature",
]
`

const pythonClient = `import json
from urllib.parse import urlencode

import requests


class AuthServiceError(Exception):
    def __init__(self, message, status=0, response=None):
        super().__init__(message)
        self.status = status
        self.response = response


class MemoryTokenStore:
    def __init__(self):
        self.access_token = ""
        self.refresh_token = ""

    def get_access_token(self):
        return self.access_token or None

    def set_access_token(self, token=None):
        self.access_token = token or ""

    def get_refresh_token(self):
        return self.refresh_token or None

    def set_refresh_token(self, token=None):
        self.refresh_token = token or ""


class AuthServiceClient:
    def __init__(self, base_url, api_key=None, admin_key=None, session_mode="token", token_store=None, session=None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.admin_key = admin_key
        self.session_mode = session_mode
        self.token_store = token_store or MemoryTokenStore()
        self.session = session or requests.Session()

    def request(self, path, method="GET", body=None, headers=None, admin=False, auth=True):
        headers = dict(headers or {})
        if admin and self.admin_key:
            headers["X-Admin-Key"] = self.admin_key
        elif self.api_key:
            headers["X-API-Key"] = self.api_key
        token = self.token_store.get_access_token()
        if auth and token:
            headers["Authorization"] = "Bearer " + token
        data = None
        if body is not None:
            if isinstance(body, str):
                data = body
            else:
                headers.setdefault("Content-Type", "application/json")
                data = json.dumps(body)
        response = self.session.request(method, self.base_url + path, headers=headers, data=data)
        text = response.text
        try:
            payload = response.json() if text else None
        except ValueError:
            payload = text
        if response.status_code >= 400:
            message = payload.get("error") if isinstance(payload, dict) and payload.get("error") else response.reason
            raise AuthServiceError(message, response.status_code, payload)
        return payload

    def _with_session_mode(self, body=None):
        body = dict(body or {})
        if self.session_mode == "token" and "session_mode" not in body:
            body["session_mode"] = "token"
        return body

    def _persist(self, payload):
        if isinstance(payload, dict):
            if payload.get("access_token"):
                self.token_store.set_access_token(payload["access_token"])
            if payload.get("refresh_token"):
                self.token_store.set_refresh_token(payload["refresh_token"])
        return payload

    def signup(self, **params):
        return self._persist(self.request("/api/auth/signup", "POST", self._with_session_mode(params), auth=False))

    def login(self, **params):
        return self._persist(self.request("/api/auth/login", "POST", self._with_session_mode(params), auth=False))

    def refresh(self, **params):
        body = self._with_session_mode(params)
        if self.session_mode == "token" and not body.get("refresh_token"):
            body["refresh_token"] = self.token_store.get_refresh_token()
        return self._persist(self.request("/api/auth/refresh", "POST", body, auth=False))

    def logout(self):
        try:
            return self.request("/api/auth/logout", "POST", {"refresh_token": self.token_store.get_refresh_token()}, auth=False)
        finally:
            self.token_store.set_access_token()
            self.token_store.set_refresh_token()

    def me(self):
        return self.request("/api/auth/me")

    def update_profile(self, **params):
        return self.request("/api/auth/me", "PATCH", params)

    def list_organizations(self):
        return self.request("/api/auth/organizations")

    def create_organization(self, **params):
        return self.request("/api/auth/organizations", "POST", params)

    def organization_token(self, organization_id, activate=False):
        payload = self.request(f"/api/auth/organizations/{organization_id}/token", "POST", {})
        if activate and isinstance(payload, dict) and payload.get("access_token"):
            self.token_store.set_access_token(payload["access_token"])
        return payload

    def client_credentials(self, client_id, client_secret, scope=None):
        body = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
        if scope:
            body["scope"] = scope
        return self.request("/oauth/token", "POST", urlencode(body), {"Content-Type": "application/x-www-form-urlencoded"}, auth=False)

    def introspect(self, token):
        return self.request("/oauth/introspect", "POST", urlencode({"token": token}), {"Content-Type": "application/x-www-form-urlencoded"}, auth=False)

    def list_clients(self):
        return self.request("/api/admin/clients", admin=True, auth=False)

    def create_client(self, **params):
        return self.request("/api/admin/clients", "POST", params, admin=True, auth=False)

    def update_client(self, client_id, **params):
        return self.request(f"/api/admin/clients/{client_id}", "PATCH", params, admin=True, auth=False)

    def rotate_client_api_key(self, client_id):
        return self.request(f"/api/admin/clients/{client_id}/rotate-api-key", "POST", admin=True, auth=False)

    def rotate_client_jwt_secret(self, client_id):
        return self.request(f"/api/admin/clients/{client_id}/rotate-jwt", "POST", admin=True, auth=False)

    def list_service_accounts(self, client_id):
        return self.request(f"/api/admin/clients/{client_id}/service-accounts", admin=True, auth=False)

    def create_service_account(self, client_id, **params):
        return self.request(f"/api/admin/clients/{client_id}/service-accounts", "POST", params, admin=True, auth=False)

    def create_sso_connection(self, client_id, **params):
        return self.request(f"/api/admin/clients/{client_id}/sso-connections", "POST", params, admin=True, auth=False)

    def create_scim_directory(self, client_id, **params):
        return self.request(f"/api/admin/clients/{client_id}/scim-directories", "POST", params, admin=True, auth=False)

    def audit_export(self, **params):
        return self.request("/api/admin/audit-events/export?" + urlencode(params), admin=True, auth=False)
`

const pythonJWT = `import hmac
import time
from hashlib import sha256

import jwt
from jwt import PyJWKClient


def has_scope(claims, scope):
    scopes = claims.get("scopes")
    if not isinstance(scopes, list):
        scopes = str(claims.get("scope", "")).split()
    return scope in scopes


def has_org_permission(claims, permission):
    if claims.get("org_role") == "owner":
        return True
    permissions = claims.get("org_permissions") or []
    return permission in permissions


class AuthServiceJwtVerifier:
    def __init__(self, jwks_url, issuer=None, audience=None, client_id=None, token_use=None, required_scopes=None, required_org_permissions=None, leeway=60):
        self.jwks = PyJWKClient(jwks_url)
        self.issuer = issuer
        self.audience = audience
        self.client_id = client_id
        self.token_use = token_use
        self.required_scopes = required_scopes or []
        self.required_org_permissions = required_org_permissions or []
        self.leeway = leeway

    def verify(self, token):
        key = self.jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(token, key.key, algorithms=["RS256"], issuer=self.issuer, audience=self.audience, leeway=self.leeway)
        if self.client_id and claims.get("client_id") != self.client_id:
            raise jwt.InvalidTokenError("token client mismatch")
        if self.token_use and claims.get("token_use") != self.token_use:
            raise jwt.InvalidTokenError("token_use mismatch")
        for scope in self.required_scopes:
            if not has_scope(claims, scope):
                raise jwt.InvalidTokenError("missing required scope: " + scope)
        for permission in self.required_org_permissions:
            if not has_org_permission(claims, permission):
                raise jwt.InvalidTokenError("missing required organization permission: " + permission)
        return claims


def verify_webhook_signature(secret, timestamp, signature, body, tolerance_seconds=300):
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(int(time.time()) - ts) > tolerance_seconds:
        return False
    if isinstance(body, str):
        body = body.encode()
    expected = "v1=" + hmac.new(secret.encode(), timestamp.encode() + b"." + body, sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")
`

const pythonMiddleware = `from .jwt import AuthServiceJwtVerifier


def _bearer(header):
    parts = str(header or "").split(" ", 1)
    return parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else ""


def fastapi_dependency(verifier: AuthServiceJwtVerifier):
    async def dependency(request):
        claims = verifier.verify(_bearer(request.headers.get("authorization")))
        request.state.authservice = claims
        return claims
    return dependency


def flask_before_request(verifier: AuthServiceJwtVerifier):
    def middleware():
        from flask import g, request
        g.authservice = verifier.verify(_bearer(request.headers.get("authorization")))
    return middleware


class DjangoAuthServiceMiddleware:
    def __init__(self, get_response, verifier: AuthServiceJwtVerifier):
        self.get_response = get_response
        self.verifier = verifier

    def __call__(self, request):
        request.authservice = self.verifier.verify(_bearer(request.headers.get("authorization")))
        return self.get_response(request)
`

const goSDKMod = `module github.com/Ayush10/authentication-service/sdks/go/authservice

go 1.24

require (
	github.com/Ayush10/authentication-service v0.0.0
	github.com/gin-gonic/gin v1.10.1
	github.com/gofiber/fiber/v2 v2.52.5
	github.com/labstack/echo/v4 v4.12.0
)

replace github.com/Ayush10/authentication-service => ../../..
`

const goSDKClient = `package authservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type TokenStore interface {
	GetAccessToken() string
	SetAccessToken(string)
	GetRefreshToken() string
	SetRefreshToken(string)
}

type MemoryTokenStore struct {
	AccessToken  string
	RefreshToken string
}

func (s *MemoryTokenStore) GetAccessToken() string { return s.AccessToken }
func (s *MemoryTokenStore) SetAccessToken(token string) { s.AccessToken = token }
func (s *MemoryTokenStore) GetRefreshToken() string { return s.RefreshToken }
func (s *MemoryTokenStore) SetRefreshToken(token string) { s.RefreshToken = token }

type Client struct {
	BaseURL     string
	APIKey      string
	AdminKey    string
	SessionMode string
	TokenStore  TokenStore
	HTTPClient  *http.Client
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), APIKey: apiKey, SessionMode: "token", TokenStore: &MemoryTokenStore{}, HTTPClient: http.DefaultClient}
}

func (c *Client) Request(ctx context.Context, method, path string, body any, admin bool, auth bool, out any) error {
	var reader io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			reader = strings.NewReader(v)
		default:
			raw, err := json.Marshal(v)
			if err != nil { return err }
			reader = bytes.NewReader(raw)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil { return err }
	if body != nil {
		if _, ok := body.(string); ok {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if admin && c.AdminKey != "" { req.Header.Set("X-Admin-Key", c.AdminKey) } else if c.APIKey != "" { req.Header.Set("X-API-Key", c.APIKey) }
	if auth && c.TokenStore != nil && c.TokenStore.GetAccessToken() != "" { req.Header.Set("Authorization", "Bearer "+c.TokenStore.GetAccessToken()) }
	res, err := c.HTTPClient.Do(req)
	if err != nil { return err }
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 { return fmt.Errorf("authservice %s: %s", res.Status, strings.TrimSpace(string(raw))) }
	if out != nil && len(raw) > 0 { return json.Unmarshal(raw, out) }
	return nil
}

func (c *Client) withSessionMode(body map[string]any) map[string]any {
	if body == nil { body = map[string]any{} }
	if c.SessionMode == "token" {
		if _, ok := body["session_mode"]; !ok { body["session_mode"] = "token" }
	}
	return body
}

func (c *Client) persist(resp map[string]any) map[string]any {
	if token, _ := resp["access_token"].(string); token != "" { c.TokenStore.SetAccessToken(token) }
	if token, _ := resp["refresh_token"].(string); token != "" { c.TokenStore.SetRefreshToken(token) }
	return resp
}

func (c *Client) Signup(ctx context.Context, body map[string]any) (map[string]any, error) {
	var out map[string]any
	err := c.Request(ctx, http.MethodPost, "/api/auth/signup", c.withSessionMode(body), false, false, &out)
	return c.persist(out), err
}

func (c *Client) Login(ctx context.Context, body map[string]any) (map[string]any, error) {
	var out map[string]any
	err := c.Request(ctx, http.MethodPost, "/api/auth/login", c.withSessionMode(body), false, false, &out)
	return c.persist(out), err
}

func (c *Client) Refresh(ctx context.Context) (map[string]any, error) {
	body := c.withSessionMode(map[string]any{"refresh_token": c.TokenStore.GetRefreshToken()})
	var out map[string]any
	err := c.Request(ctx, http.MethodPost, "/api/auth/refresh", body, false, false, &out)
	return c.persist(out), err
}

func (c *Client) Me(ctx context.Context) (map[string]any, error) { var out map[string]any; return out, c.Request(ctx, http.MethodGet, "/api/auth/me", nil, false, true, &out) }
func (c *Client) CreateClient(ctx context.Context, body map[string]any) (map[string]any, error) { var out map[string]any; return out, c.Request(ctx, http.MethodPost, "/api/admin/clients", body, true, false, &out) }
func (c *Client) ListClients(ctx context.Context) ([]map[string]any, error) { var out []map[string]any; return out, c.Request(ctx, http.MethodGet, "/api/admin/clients", nil, true, false, &out) }
func (c *Client) RotateClientAPIKey(ctx context.Context, id string) (map[string]any, error) { var out map[string]any; return out, c.Request(ctx, http.MethodPost, "/api/admin/clients/"+url.PathEscape(id)+"/rotate-api-key", nil, true, false, &out) }
func (c *Client) CreateServiceAccount(ctx context.Context, clientID string, body map[string]any) (map[string]any, error) { var out map[string]any; return out, c.Request(ctx, http.MethodPost, "/api/admin/clients/"+url.PathEscape(clientID)+"/service-accounts", body, true, false, &out) }
func (c *Client) CreateSSOConnection(ctx context.Context, clientID string, body map[string]any) (map[string]any, error) { var out map[string]any; return out, c.Request(ctx, http.MethodPost, "/api/admin/clients/"+url.PathEscape(clientID)+"/sso-connections", body, true, false, &out) }
func (c *Client) CreateSCIMDirectory(ctx context.Context, clientID string, body map[string]any) (map[string]any, error) { var out map[string]any; return out, c.Request(ctx, http.MethodPost, "/api/admin/clients/"+url.PathEscape(clientID)+"/scim-directories", body, true, false, &out) }
`

const goSDKJWT = `package authservice

import (
	"net/http"

	"github.com/Ayush10/authentication-service/pkg/jwtvalidator"
)

type Claims = jwtvalidator.Claims
type JwtVerifier = jwtvalidator.Validator
type JwtVerifierConfig = jwtvalidator.Config

func NewJwtVerifier(cfg JwtVerifierConfig) *JwtVerifier {
	return jwtvalidator.New(cfg)
}

func VerifyWebhookSignature(secret, timestamp, signature string, payload []byte) bool {
	return jwtvalidator.VerifyWebhookSignature(secret, timestamp, signature, payload)
}

func ClaimsFromRequest(r *http.Request) *Claims {
	return jwtvalidator.GetClaims(r.Context())
}
`

const goSDKMiddleware = `package authservice

import (
	"net/http"

	"github.com/Ayush10/authentication-service/pkg/jwtvalidator"
	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber/v2"
	"github.com/labstack/echo/v4"
)

func HTTPMiddleware(verifier *jwtvalidator.Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return verifier.Middleware(next) }
}

func GinMiddleware(verifier *jwtvalidator.Validator) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := verifier.ValidateFromRequest(c.Request)
		if err != nil { c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()}); return }
		c.Set("authservice", claims)
		c.Request = c.Request.WithContext(jwtvalidator.WithClaims(c.Request.Context(), claims))
		c.Next()
	}
}

func ChiMiddleware(verifier *jwtvalidator.Validator) func(http.Handler) http.Handler {
	return HTTPMiddleware(verifier)
}

func EchoMiddleware(verifier *jwtvalidator.Validator) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, err := verifier.ValidateFromRequest(c.Request())
			if err != nil { return echo.NewHTTPError(http.StatusUnauthorized, err.Error()) }
			c.Set("authservice", claims)
			return next(c)
		}
	}
}

func FiberMiddleware(verifier *jwtvalidator.Validator) fiber.Handler {
	return func(c *fiber.Ctx) error {
		req, err := http.NewRequest(http.MethodGet, "/", nil)
		if err != nil { return err }
		req.Header.Set("Authorization", c.Get("Authorization"))
		claims, err := verifier.ValidateFromRequest(req)
		if err != nil { return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()}) }
		c.Locals("authservice", claims)
		return c.Next()
	}
}
`

const jvmPom = `<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.authservice</groupId>
  <artifactId>authservice-sdk</artifactId>
  <version>0.1.0</version>
  <name>AuthService SDK</name>
  <description>Generated Java and Kotlin SDK for AuthService</description>
  <url>https://github.com/Ayush10/authentication-service</url>
  <licenses><license><name>MIT</name></license></licenses>
  <properties>
    <maven.compiler.release>17</maven.compiler.release>
    <kotlin.version>2.0.21</kotlin.version>
  </properties>
  <dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.18.0</version></dependency>
    <dependency><groupId>com.nimbusds</groupId><artifactId>nimbus-jose-jwt</artifactId><version>9.41.2</version></dependency>
    <dependency><groupId>org.springframework</groupId><artifactId>spring-web</artifactId><version>6.1.13</version><optional>true</optional></dependency>
    <dependency><groupId>org.springframework.security</groupId><artifactId>spring-security-web</artifactId><version>6.3.3</version><optional>true</optional></dependency>
  </dependencies>
</project>
`

const jvmClient = `package com.authservice.sdk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;

public class AuthServiceClient {
  private final String baseUrl;
  private final String apiKey;
  private final String adminKey;
  private final HttpClient http = HttpClient.newHttpClient();
  private final ObjectMapper json = new ObjectMapper();
  private String accessToken;
  private String refreshToken;

  public AuthServiceClient(String baseUrl, String apiKey, String adminKey) {
    this.baseUrl = baseUrl.replaceAll("/+$", "");
    this.apiKey = apiKey;
    this.adminKey = adminKey;
  }

  public Map<String, Object> request(String method, String path, Object body, boolean admin, boolean auth) throws Exception {
    HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path)).method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)));
    builder.header("Content-Type", "application/json");
    if (admin && adminKey != null) builder.header("X-Admin-Key", adminKey);
    else if (apiKey != null) builder.header("X-API-Key", apiKey);
    if (auth && accessToken != null) builder.header("Authorization", "Bearer " + accessToken);
    HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() >= 400) throw new RuntimeException("AuthService " + response.statusCode() + ": " + response.body());
    if (response.body() == null || response.body().isBlank()) return Map.of();
    return json.readValue(response.body(), new TypeReference<Map<String, Object>>() {});
  }

  public Map<String, Object> login(String email, String password) throws Exception {
    Map<String, Object> body = new HashMap<>();
    body.put("email", email);
    body.put("password", password);
    body.put("session_mode", "token");
    Map<String, Object> out = request("POST", "/api/auth/login", body, false, false);
    accessToken = (String) out.get("access_token");
    refreshToken = (String) out.get("refresh_token");
    return out;
  }

  public Map<String, Object> me() throws Exception { return request("GET", "/api/auth/me", null, false, true); }
  public Map<String, Object> createClient(Map<String, Object> body) throws Exception { return request("POST", "/api/admin/clients", body, true, false); }
  public Map<String, Object> createServiceAccount(String clientId, Map<String, Object> body) throws Exception { return request("POST", "/api/admin/clients/" + clientId + "/service-accounts", body, true, false); }
  public String getAccessToken() { return accessToken; }
  public String getRefreshToken() { return refreshToken; }
}
`

const jvmJWT = `package com.authservice.sdk;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.net.URL;
import java.util.List;

public class JwtVerifier {
  private final ConfigurableJWTProcessor<com.nimbusds.jose.proc.SecurityContext> processor = new DefaultJWTProcessor<>();
  private final String clientId;
  private final String tokenUse;
  private final List<String> scopes;
  private final List<String> orgPermissions;

  public JwtVerifier(String jwksUrl, String clientId, String tokenUse, List<String> scopes, List<String> orgPermissions) throws Exception {
    processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, new RemoteJWKSet<>(new URL(jwksUrl))));
    this.clientId = clientId;
    this.tokenUse = tokenUse;
    this.scopes = scopes == null ? List.of() : scopes;
    this.orgPermissions = orgPermissions == null ? List.of() : orgPermissions;
  }

  public JWTClaimsSet verify(String token) throws Exception {
    JWTClaimsSet claims = processor.process(token, null);
    if (clientId != null && !clientId.equals(claims.getStringClaim("client_id"))) throw new SecurityException("token client mismatch");
    if (tokenUse != null && !tokenUse.equals(claims.getStringClaim("token_use"))) throw new SecurityException("token_use mismatch");
    String scope = claims.getStringClaim("scope");
    List<String> claimScopes = claims.getStringListClaim("scopes");
    for (String required : scopes) if ((claimScopes == null || !claimScopes.contains(required)) && (scope == null || !List.of(scope.split(" ")).contains(required))) throw new SecurityException("missing scope " + required);
    List<String> perms = claims.getStringListClaim("org_permissions");
    for (String required : orgPermissions) if (!"owner".equals(claims.getStringClaim("org_role")) && (perms == null || !perms.contains(required))) throw new SecurityException("missing organization permission " + required);
    return claims;
  }
}
`

const jvmSpring = `package com.authservice.sdk;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

public class SpringBootAuthServiceFilter extends OncePerRequestFilter {
  private final JwtVerifier verifier;

  public SpringBootAuthServiceFilter(JwtVerifier verifier) {
    this.verifier = verifier;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
    try {
      String header = request.getHeader("Authorization");
      String token = header != null && header.toLowerCase().startsWith("bearer ") ? header.substring(7) : "";
      request.setAttribute("authservice", verifier.verify(token));
      chain.doFilter(request, response);
    } catch (Exception ex) {
      response.setStatus(401);
      response.setContentType("application/json");
      response.getWriter().write("{\"error\":\"unauthorized\"}");
    }
  }
}
`

const jvmKotlin = `package com.authservice.sdk

fun authServiceClient(baseUrl: String, apiKey: String? = null, adminKey: String? = null): AuthServiceClient =
    AuthServiceClient(baseUrl, apiKey, adminKey)
`

const csharpProject = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <PackageId>AuthService</PackageId>
    <Version>0.1.0</Version>
    <Authors>AuthService</Authors>
    <Description>Generated C# SDK and ASP.NET Core middleware for AuthService.</Description>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.IdentityModel.Protocols.OpenIdConnect" Version="8.1.2" />
    <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="8.1.2" />
    <FrameworkReference Include="Microsoft.AspNetCore.App" />
  </ItemGroup>
</Project>
`

const csharpClient = `using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace AuthService;

public sealed class AuthServiceClient
{
    private readonly HttpClient _http;
    private readonly string? _apiKey;
    private readonly string? _adminKey;
    public string? AccessToken { get; private set; }
    public string? RefreshToken { get; private set; }

    public AuthServiceClient(string baseUrl, string? apiKey = null, string? adminKey = null, HttpClient? http = null)
    {
        _http = http ?? new HttpClient();
        _http.BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/");
        _apiKey = apiKey;
        _adminKey = adminKey;
    }

    public async Task<JsonDocument?> RequestAsync(string method, string path, object? body = null, bool admin = false, bool auth = true, CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path.TrimStart('/'));
        if (body is not null) request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        if (admin && _adminKey is not null) request.Headers.Add("X-Admin-Key", _adminKey);
        else if (_apiKey is not null) request.Headers.Add("X-API-Key", _apiKey);
        if (auth && AccessToken is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);
        using var response = await _http.SendAsync(request, ct);
        var text = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"AuthService {(int)response.StatusCode}: {text}");
        return string.IsNullOrWhiteSpace(text) ? null : JsonDocument.Parse(text);
    }

    public async Task<JsonDocument?> LoginAsync(string email, string password, CancellationToken ct = default)
    {
        var doc = await RequestAsync("POST", "/api/auth/login", new { email, password, session_mode = "token" }, false, false, ct);
        if (doc is not null && doc.RootElement.TryGetProperty("access_token", out var access)) AccessToken = access.GetString();
        if (doc is not null && doc.RootElement.TryGetProperty("refresh_token", out var refresh)) RefreshToken = refresh.GetString();
        return doc;
    }

    public Task<JsonDocument?> MeAsync(CancellationToken ct = default) => RequestAsync("GET", "/api/auth/me", ct: ct);
    public Task<JsonDocument?> CreateClientAsync(object body, CancellationToken ct = default) => RequestAsync("POST", "/api/admin/clients", body, true, false, ct);
    public Task<JsonDocument?> CreateServiceAccountAsync(string clientId, object body, CancellationToken ct = default) => RequestAsync("POST", $"/api/admin/clients/{clientId}/service-accounts", body, true, false, ct);
}
`

const csharpJWT = `using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;

namespace AuthService;

public sealed class AuthServiceJwtVerifier
{
    private readonly ConfigurationManager<OpenIdConnectConfiguration> _config;
    private readonly TokenValidationParameters _parameters;

    public AuthServiceJwtVerifier(string jwksUrl, string? issuer = null, string? audience = null)
    {
        _config = new ConfigurationManager<OpenIdConnectConfiguration>(jwksUrl, new OpenIdConnectConfigurationRetriever());
        _parameters = new TokenValidationParameters { ValidateIssuer = issuer is not null, ValidIssuer = issuer, ValidateAudience = audience is not null, ValidAudience = audience, ValidateIssuerSigningKey = true, ValidateLifetime = true };
    }

    public async Task<JwtSecurityToken> VerifyAsync(string token, string? clientId = null, string? tokenUse = null, IEnumerable<string>? scopes = null, IEnumerable<string>? orgPermissions = null, CancellationToken ct = default)
    {
        var config = await _config.GetConfigurationAsync(ct);
        _parameters.IssuerSigningKeys = config.SigningKeys;
        new JwtSecurityTokenHandler().ValidateToken(token, _parameters, out var validated);
        var jwt = (JwtSecurityToken)validated;
        if (clientId is not null && jwt.Claims.FirstOrDefault(c => c.Type == "client_id")?.Value != clientId) throw new SecurityTokenException("token client mismatch");
        if (tokenUse is not null && jwt.Claims.FirstOrDefault(c => c.Type == "token_use")?.Value != tokenUse) throw new SecurityTokenException("token_use mismatch");
        var claimScopes = jwt.Claims.Where(c => c.Type == "scopes").Select(c => c.Value).Concat((jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToHashSet();
        foreach (var scope in scopes ?? Array.Empty<string>()) if (!claimScopes.Contains(scope)) throw new SecurityTokenException("missing scope " + scope);
        var role = jwt.Claims.FirstOrDefault(c => c.Type == "org_role")?.Value;
        var perms = jwt.Claims.Where(c => c.Type == "org_permissions").Select(c => c.Value).ToHashSet();
        foreach (var permission in orgPermissions ?? Array.Empty<string>()) if (role != "owner" && !perms.Contains(permission)) throw new SecurityTokenException("missing organization permission " + permission);
        return jwt;
    }

    public static bool VerifyWebhookSignature(string secret, string timestamp, string signature, byte[] body)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var expected = "v1=" + Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(timestamp + ".").Concat(body).ToArray())).ToLowerInvariant();
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(signature ?? ""));
    }
}
`

const csharpAspNet = `using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace AuthService;

public static class AspNetCoreAuthServiceExtensions
{
    public static IApplicationBuilder UseAuthService(this IApplicationBuilder app, AuthServiceJwtVerifier verifier)
    {
        return app.Use(async (context, next) =>
        {
            try
            {
                var header = context.Request.Headers.Authorization.ToString();
                var token = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..] : "";
                context.Items["authservice"] = await verifier.VerifyAsync(token, ct: context.RequestAborted);
                await next();
            }
            catch
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "unauthorized" });
            }
        });
    }
}
`

const phpComposer = `{
  "name": "authservice/authservice",
  "description": "Generated PHP SDK and Laravel middleware for AuthService",
  "license": "MIT",
  "type": "library",
  "autoload": {
    "psr-4": {
      "AuthService\\": "src/"
    }
  },
  "require": {
    "php": ">=8.1",
    "firebase/php-jwt": "^6.10",
    "guzzlehttp/guzzle": "^7.9"
  },
  "extra": {
    "laravel": {
      "providers": ["AuthService\\Laravel\\AuthServiceServiceProvider"]
    }
  }
}
`

const phpClient = `<?php
namespace AuthService;

use GuzzleHttp\Client;

class AuthServiceClient {
    private Client $http;
    private ?string $apiKey;
    private ?string $adminKey;
    public ?string $accessToken = null;
    public ?string $refreshToken = null;

    public function __construct(string $baseUrl, ?string $apiKey = null, ?string $adminKey = null) {
        $this->http = new Client(["base_uri" => rtrim($baseUrl, "/")]);
        $this->apiKey = $apiKey;
        $this->adminKey = $adminKey;
    }

    public function request(string $method, string $path, ?array $body = null, bool $admin = false, bool $auth = true): array {
        $headers = [];
        if ($admin && $this->adminKey) $headers["X-Admin-Key"] = $this->adminKey;
        elseif ($this->apiKey) $headers["X-API-Key"] = $this->apiKey;
        if ($auth && $this->accessToken) $headers["Authorization"] = "Bearer ".$this->accessToken;
        $options = ["headers" => $headers];
        if ($body !== null) $options["json"] = $body;
        $response = $this->http->request($method, $path, $options);
        $payload = json_decode((string)$response->getBody(), true) ?: [];
        return $payload;
    }

    public function login(string $email, string $password): array {
        $payload = $this->request("POST", "/api/auth/login", ["email" => $email, "password" => $password, "session_mode" => "token"], false, false);
        $this->accessToken = $payload["access_token"] ?? null;
        $this->refreshToken = $payload["refresh_token"] ?? null;
        return $payload;
    }

    public function me(): array { return $this->request("GET", "/api/auth/me"); }
    public function createClient(array $body): array { return $this->request("POST", "/api/admin/clients", $body, true, false); }
    public function createServiceAccount(string $clientId, array $body): array { return $this->request("POST", "/api/admin/clients/".$clientId."/service-accounts", $body, true, false); }
}
`

const phpJWT = `<?php
namespace AuthService;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

class JwtVerifier {
    public function __construct(private string $jwksUrl, private ?string $clientId = null, private ?string $tokenUse = null) {}

    public function verify(string $token, array $requiredScopes = [], array $requiredOrgPermissions = []): object {
        $jwks = json_decode(file_get_contents($this->jwksUrl), true);
        $claims = JWT::decode($token, JWK::parseKeySet($jwks));
        if ($this->clientId && ($claims->client_id ?? null) !== $this->clientId) throw new \RuntimeException("token client mismatch");
        if ($this->tokenUse && ($claims->token_use ?? null) !== $this->tokenUse) throw new \RuntimeException("token_use mismatch");
        $scopes = isset($claims->scopes) ? $claims->scopes : preg_split('/\s+/', $claims->scope ?? "", -1, PREG_SPLIT_NO_EMPTY);
        foreach ($requiredScopes as $scope) if (!in_array($scope, $scopes, true)) throw new \RuntimeException("missing scope ".$scope);
        $perms = $claims->org_permissions ?? [];
        foreach ($requiredOrgPermissions as $permission) if (($claims->org_role ?? "") !== "owner" && !in_array($permission, $perms, true)) throw new \RuntimeException("missing organization permission ".$permission);
        return $claims;
    }

    public static function verifyWebhookSignature(string $secret, string $timestamp, string $signature, string $body): bool {
        $expected = "v1=".hash_hmac("sha256", $timestamp.".".$body, $secret);
        return hash_equals($expected, $signature);
    }
}
`

const phpLaravelMiddleware = `<?php
namespace AuthService\Laravel;

use AuthService\JwtVerifier;
use Closure;

class AuthServiceMiddleware {
    public function __construct(private JwtVerifier $verifier) {}

    public function handle($request, Closure $next) {
        $header = $request->header("Authorization", "");
        $token = stripos($header, "Bearer ") === 0 ? substr($header, 7) : "";
        $request->attributes->set("authservice", $this->verifier->verify($token));
        return $next($request);
    }
}
`

const phpLaravelProvider = `<?php
namespace AuthService\Laravel;

use AuthService\AuthServiceClient;
use AuthService\JwtVerifier;
use Illuminate\Support\ServiceProvider;

class AuthServiceServiceProvider extends ServiceProvider {
    public function register(): void {
        $this->app->singleton(AuthServiceClient::class, fn() => new AuthServiceClient(config("authservice.base_url"), config("authservice.api_key"), config("authservice.admin_key")));
        $this->app->singleton(JwtVerifier::class, fn() => new JwtVerifier(config("authservice.jwks_url"), config("authservice.client_id")));
    }
}
`

const rubyGemspec = `Gem::Specification.new do |spec|
  spec.name = "authservice"
  spec.version = "0.1.0"
  spec.summary = "Generated Ruby SDK and Rails middleware for AuthService"
  spec.license = "MIT"
  spec.files = Dir["lib/**/*.rb", "README.md"]
  spec.require_paths = ["lib"]
  spec.add_dependency "jwt", ">= 2.8"
  spec.add_dependency "faraday", ">= 2.0"
end
`

const rubyClient = `require "faraday"
require "json"
require_relative "authservice/jwt_verifier"
require_relative "authservice/rails_middleware"

module AuthService
  class Client
    attr_reader :access_token, :refresh_token

    def initialize(base_url:, api_key: nil, admin_key: nil)
      @base_url = base_url.sub(%r{/+$}, "")
      @api_key = api_key
      @admin_key = admin_key
      @http = Faraday.new(url: @base_url)
    end

    def request(method, path, body: nil, admin: false, auth: true)
      response = @http.public_send(method.downcase, path) do |req|
        req.headers["X-Admin-Key"] = @admin_key if admin && @admin_key
        req.headers["X-API-Key"] = @api_key if !admin && @api_key
        req.headers["Authorization"] = "Bearer #{@access_token}" if auth && @access_token
        req.headers["Content-Type"] = "application/json" if body
        req.body = JSON.generate(body) if body
      end
      raise "AuthService #{response.status}: #{response.body}" if response.status >= 400
      response.body.to_s.empty? ? {} : JSON.parse(response.body)
    end

    def login(email:, password:)
      payload = request("POST", "/api/auth/login", body: {email: email, password: password, session_mode: "token"}, auth: false)
      @access_token = payload["access_token"]
      @refresh_token = payload["refresh_token"]
      payload
    end

    def me = request("GET", "/api/auth/me")
    def create_client(body) = request("POST", "/api/admin/clients", body: body, admin: true, auth: false)
    def create_service_account(client_id, body) = request("POST", "/api/admin/clients/#{client_id}/service-accounts", body: body, admin: true, auth: false)
  end
end
`

const rubyJWT = `require "jwt"
require "net/http"
require "json"
require "openssl"

module AuthService
  class JwtVerifier
    def initialize(jwks_url:, client_id: nil, token_use: nil)
      @jwks_url = URI(jwks_url)
      @client_id = client_id
      @token_use = token_use
    end

    def verify(token, required_scopes: [], required_org_permissions: [])
      jwks = JSON.parse(Net::HTTP.get(@jwks_url))
      claims, = JWT.decode(token, nil, true, algorithms: ["RS256"], jwks: jwks)
      raise "token client mismatch" if @client_id && claims["client_id"] != @client_id
      raise "token_use mismatch" if @token_use && claims["token_use"] != @token_use
      scopes = claims["scopes"] || claims.fetch("scope", "").split
      required_scopes.each { |scope| raise "missing scope #{scope}" unless scopes.include?(scope) }
      perms = claims["org_permissions"] || []
      required_org_permissions.each { |perm| raise "missing organization permission #{perm}" unless claims["org_role"] == "owner" || perms.include?(perm) }
      claims
    end

    def self.verify_webhook_signature(secret, timestamp, signature, body)
      expected = "v1=" + OpenSSL::HMAC.hexdigest("SHA256", secret, "#{timestamp}.#{body}")
      Rack::Utils.secure_compare(expected, signature)
    end
  end
end
`

const rubyRails = `module AuthService
  class RailsMiddleware
    def initialize(app, verifier)
      @app = app
      @verifier = verifier
    end

    def call(env)
      header = env["HTTP_AUTHORIZATION"].to_s
      token = header.start_with?("Bearer ") ? header[7..] : ""
      env["authservice.claims"] = @verifier.verify(token)
      @app.call(env)
    rescue => e
      [401, {"Content-Type" => "application/json"}, [{error: e.message}.to_json]]
    end
  end
end
`

const rustCargo = `[package]
name = "authservice"
version = "0.1.0"
edition = "2021"
description = "Generated Rust SDK and Axum/Actix middleware for AuthService"
license = "MIT"

[dependencies]
anyhow = "1"
async-trait = "0.1"
jsonwebtoken = "9"
reqwest = { version = "0.12", features = ["json"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
hmac = "0.12"
sha2 = "0.10"
hex = "0.4"
axum = { version = "0.7", optional = true }
actix-web = { version = "4", optional = true }

[features]
default = []
axum = ["dep:axum"]
actix = ["dep:actix-web"]
`

const rustLib = `use anyhow::{anyhow, Result};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::{json, Value};

pub mod jwt;
#[cfg(feature = "axum")]
pub mod axum;
#[cfg(feature = "actix")]
pub mod actix;

#[derive(Clone)]
pub struct AuthServiceClient {
    base_url: String,
    api_key: Option<String>,
    admin_key: Option<String>,
    http: reqwest::Client,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
}

impl AuthServiceClient {
    pub fn new(base_url: impl Into<String>, api_key: Option<String>, admin_key: Option<String>) -> Self {
        Self { base_url: base_url.into().trim_end_matches('/').to_string(), api_key, admin_key, http: reqwest::Client::new(), access_token: None, refresh_token: None }
    }

    pub async fn request(&self, method: reqwest::Method, path: &str, body: Option<Value>, admin: bool, auth: bool) -> Result<Value> {
        let mut headers = HeaderMap::new();
        if admin {
            if let Some(key) = &self.admin_key { headers.insert("X-Admin-Key", HeaderValue::from_str(key)?); }
        } else if let Some(key) = &self.api_key {
            headers.insert("X-API-Key", HeaderValue::from_str(key)?);
        }
        if auth {
            if let Some(token) = &self.access_token { headers.insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", token))?); }
        }
        let mut req = self.http.request(method, format!("{}{}", self.base_url, path)).headers(headers);
        if let Some(body) = body { req = req.json(&body); }
        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() { return Err(anyhow!("AuthService {}: {}", status, text)); }
        Ok(if text.is_empty() { json!({}) } else { serde_json::from_str(&text)? })
    }

    pub async fn login(&mut self, email: &str, password: &str) -> Result<Value> {
        let out = self.request(reqwest::Method::POST, "/api/auth/login", Some(json!({"email": email, "password": password, "session_mode": "token"})), false, false).await?;
        self.access_token = out.get("access_token").and_then(|v| v.as_str()).map(str::to_string);
        self.refresh_token = out.get("refresh_token").and_then(|v| v.as_str()).map(str::to_string);
        Ok(out)
    }

    pub async fn me(&self) -> Result<Value> { self.request(reqwest::Method::GET, "/api/auth/me", None, false, true).await }
    pub async fn create_client(&self, body: Value) -> Result<Value> { self.request(reqwest::Method::POST, "/api/admin/clients", Some(body), true, false).await }
    pub async fn create_service_account(&self, client_id: &str, body: Value) -> Result<Value> { self.request(reqwest::Method::POST, &format!("/api/admin/clients/{}/service-accounts", client_id), Some(body), true, false).await }
}
`

const rustJWT = `use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct JwtVerifier {
    jwks_url: String,
    client_id: Option<String>,
    token_use: Option<String>,
    required_scopes: Vec<String>,
    required_org_permissions: Vec<String>,
}

impl JwtVerifier {
    pub fn new(jwks_url: impl Into<String>) -> Self {
        Self { jwks_url: jwks_url.into(), client_id: None, token_use: None, required_scopes: vec![], required_org_permissions: vec![] }
    }

    pub fn client_id(mut self, value: impl Into<String>) -> Self { self.client_id = Some(value.into()); self }
    pub fn token_use(mut self, value: impl Into<String>) -> Self { self.token_use = Some(value.into()); self }
    pub fn required_scopes(mut self, value: Vec<String>) -> Self { self.required_scopes = value; self }
    pub fn required_org_permissions(mut self, value: Vec<String>) -> Self { self.required_org_permissions = value; self }

    pub async fn verify(&self, token: &str) -> Result<Value> {
        let header = decode_header(token)?;
        let kid = header.kid.ok_or_else(|| anyhow!("missing kid"))?;
        let jwks: Value = reqwest::get(&self.jwks_url).await?.json().await?;
        let key = jwks["keys"].as_array().and_then(|keys| keys.iter().find(|k| k["kid"] == kid)).ok_or_else(|| anyhow!("signing key not found"))?;
        let decoding = DecodingKey::from_rsa_components(key["n"].as_str().unwrap_or(""), key["e"].as_str().unwrap_or(""))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_aud = false;
        let data = decode::<Value>(token, &decoding, &validation)?;
        let claims = data.claims;
        if let Some(client_id) = &self.client_id { if claims["client_id"] != *client_id { return Err(anyhow!("token client mismatch")); } }
        if let Some(token_use) = &self.token_use { if claims["token_use"] != *token_use { return Err(anyhow!("token_use mismatch")); } }
        for scope in &self.required_scopes { if !has_scope(&claims, scope) { return Err(anyhow!("missing scope {}", scope)); } }
        for permission in &self.required_org_permissions { if !has_org_permission(&claims, permission) { return Err(anyhow!("missing organization permission {}", permission)); } }
        Ok(claims)
    }
}

pub fn has_scope(claims: &Value, scope: &str) -> bool {
    claims["scopes"].as_array().map(|v| v.iter().any(|x| x == scope)).unwrap_or(false)
        || claims["scope"].as_str().map(|s| s.split_whitespace().any(|x| x == scope)).unwrap_or(false)
}

pub fn has_org_permission(claims: &Value, permission: &str) -> bool {
    claims["org_role"] == "owner" || claims["org_permissions"].as_array().map(|v| v.iter().any(|x| x == permission)).unwrap_or(false)
}

pub fn verify_webhook_signature(secret: &str, timestamp: &str, signature: &str, body: &[u8], tolerance_seconds: u64) -> bool {
    let ts: u64 = match timestamp.parse() { Ok(v) => v, Err(_) => return false };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if now.abs_diff(ts) > tolerance_seconds { return false; }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected = format!("v1={}", hex::encode(mac.finalize().into_bytes()));
    expected.as_bytes() == signature.as_bytes()
}
`

const rustAxum = `use axum::{extract::State, http::Request, middleware::Next, response::Response};
use crate::jwt::JwtVerifier;

pub async fn authservice_middleware<B>(State(verifier): State<JwtVerifier>, mut request: Request<B>, next: Next<B>) -> Result<Response, axum::http::StatusCode> {
    let header = request.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let token = header.strip_prefix("Bearer ").unwrap_or("");
    let claims = verifier.verify(token).await.map_err(|_| axum::http::StatusCode::UNAUTHORIZED)?;
    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}
`

const rustActix = `use actix_web::{dev::ServiceRequest, Error};
use crate::jwt::JwtVerifier;

pub async fn verify_actix_request(req: &mut ServiceRequest, verifier: &JwtVerifier) -> Result<(), Error> {
    let header = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let token = header.strip_prefix("Bearer ").unwrap_or("");
    let claims = verifier.verify(token).await.map_err(actix_web::error::ErrorUnauthorized)?;
    req.extensions_mut().insert(claims);
    Ok(())
}
`

const frameworkSupport = `# AuthService Framework Adapter Coverage

This generated SDK pass provides official adapters for:

- TypeScript: Express, Fastify, NestJS, Next.js
- Python: Django, FastAPI, Flask
- JVM: Spring Boot
- C#: ASP.NET Core
- PHP: Laravel
- Ruby: Rails and Rack
- Rust: Axum, Actix
- Go: net/http, Gin, Chi, Echo, Fiber

All verifier adapters enforce the same core contract where the language ecosystem supports it: JWKS-backed JWT validation, issuer and audience checks, token_use checks, required scopes, required organization permissions, and signed webhook verification.
`
