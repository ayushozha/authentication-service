import { createHmac, timingSafeEqual } from "node:crypto";
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
