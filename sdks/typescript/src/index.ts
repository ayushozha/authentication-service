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

export const AUTH_ERROR_CODES = [
  "AUTH_INVALID_REQUEST",
  "AUTH_EMAIL_REQUIRED",
  "AUTH_PASSWORD_REQUIRED",
  "AUTH_EMAIL_PASSWORD_REQUIRED",
  "AUTH_INVALID_EMAIL",
  "AUTH_PASSWORD_TOO_SHORT",
  "AUTH_INVALID_CREDENTIALS",
  "AUTH_ACCOUNT_LOCKED",
  "AUTH_ACCOUNT_DISABLED",
  "AUTH_RATE_LIMITED",
  "AUTH_SESSION_EXPIRED",
  "AUTH_TOKEN_MISSING",
  "AUTH_TOKEN_REVOKED",
  "AUTH_STORAGE_UNAVAILABLE",
  "AUTH_STORAGE_WRITE_FAILED",
  "AUTH_NETWORK_UNAVAILABLE",
  "AUTH_SERVICE_UNAVAILABLE",
  "AUTH_OAUTH_FAILED",
  "AUTH_OAUTH_CANCELLED",
  "AUTH_OAUTH_STATE_MISMATCH",
  "AUTH_OAUTH_PROVIDER_UNAVAILABLE",
  "AUTH_SSO_FAILED",
  "AUTH_PASSKEY_FAILED",
  "AUTH_PASSKEY_CANCELLED",
  "AUTH_BIOMETRIC_UNAVAILABLE",
  "AUTH_BIOMETRIC_CANCELLED",
  "AUTH_BIOMETRIC_LOCKOUT",
  "AUTH_MFA_REQUIRED",
  "AUTH_MFA_CODE_INVALID",
  "AUTH_MFA_CODE_EXPIRED",
  "AUTH_MFA_RECOVERY_CODE_INVALID",
  "AUTH_MFA_PUSH_TIMEOUT",
  "AUTH_MFA_SMS_UNAVAILABLE",
  "AUTH_UNKNOWN",
] as const;

export type AuthErrorCode = (typeof AUTH_ERROR_CODES)[number];

export interface NormalizedAuthError {
  code: AuthErrorCode;
  userMessage: string;
  retryable: boolean;
  providerCode?: string;
}

export class AuthServiceError extends Error {
  readonly code: AuthErrorCode;
  readonly userMessage: string;
  readonly retryable: boolean;
  readonly providerCode?: string;

  constructor(message: string, public status: number, public response: unknown, normalized?: NormalizedAuthError) {
    const error = normalized || normalizeAuthServiceError(status, response, message);
    super(error.userMessage || message);
    this.name = "AuthServiceError";
    this.code = error.code;
    this.userMessage = error.userMessage;
    this.retryable = error.retryable;
    this.providerCode = error.providerCode;
  }
}

const ERROR_DEFINITIONS: Record<AuthErrorCode, { userMessage: string; retryable: boolean }> = {
  AUTH_INVALID_REQUEST: { userMessage: "We could not process that request. Try again.", retryable: false },
  AUTH_EMAIL_REQUIRED: { userMessage: "Enter your email address.", retryable: false },
  AUTH_PASSWORD_REQUIRED: { userMessage: "Enter your password.", retryable: false },
  AUTH_EMAIL_PASSWORD_REQUIRED: { userMessage: "Enter your email and password.", retryable: false },
  AUTH_INVALID_EMAIL: { userMessage: "Enter a valid email address.", retryable: false },
  AUTH_PASSWORD_TOO_SHORT: { userMessage: "Use at least 8 characters for your password.", retryable: false },
  AUTH_INVALID_CREDENTIALS: { userMessage: "Invalid email or password.", retryable: false },
  AUTH_ACCOUNT_LOCKED: { userMessage: "This account is locked. Check your email for next steps.", retryable: false },
  AUTH_ACCOUNT_DISABLED: { userMessage: "This account cannot sign in right now.", retryable: false },
  AUTH_RATE_LIMITED: { userMessage: "Too many attempts. Try again in a few minutes.", retryable: true },
  AUTH_SESSION_EXPIRED: { userMessage: "Your session expired. Sign in again.", retryable: false },
  AUTH_TOKEN_MISSING: { userMessage: "Sign in again to continue.", retryable: false },
  AUTH_TOKEN_REVOKED: { userMessage: "Your session is no longer active. Sign in again.", retryable: false },
  AUTH_STORAGE_UNAVAILABLE: { userMessage: "Secure storage is unavailable on this device.", retryable: false },
  AUTH_STORAGE_WRITE_FAILED: { userMessage: "We could not save your sign-in securely. Try again.", retryable: true },
  AUTH_NETWORK_UNAVAILABLE: { userMessage: "Check your connection and try again.", retryable: true },
  AUTH_SERVICE_UNAVAILABLE: { userMessage: "We could not sign you in right now. Try again later.", retryable: true },
  AUTH_OAUTH_FAILED: { userMessage: "We could not complete sign-in with that provider.", retryable: true },
  AUTH_OAUTH_CANCELLED: { userMessage: "Sign-in was cancelled.", retryable: false },
  AUTH_OAUTH_STATE_MISMATCH: { userMessage: "We could not verify that sign-in. Try again.", retryable: false },
  AUTH_OAUTH_PROVIDER_UNAVAILABLE: { userMessage: "That sign-in provider is unavailable. Try again later.", retryable: true },
  AUTH_SSO_FAILED: { userMessage: "We could not complete single sign-on. Try again.", retryable: true },
  AUTH_PASSKEY_FAILED: { userMessage: "We could not complete passkey sign-in. Try again.", retryable: true },
  AUTH_PASSKEY_CANCELLED: { userMessage: "Passkey sign-in was cancelled.", retryable: false },
  AUTH_BIOMETRIC_UNAVAILABLE: { userMessage: "Biometric unlock is unavailable on this device.", retryable: false },
  AUTH_BIOMETRIC_CANCELLED: { userMessage: "Biometric unlock was cancelled.", retryable: false },
  AUTH_BIOMETRIC_LOCKOUT: { userMessage: "Biometric unlock is locked. Use your device passcode.", retryable: false },
  AUTH_MFA_REQUIRED: { userMessage: "Enter the code from your authenticator app.", retryable: false },
  AUTH_MFA_CODE_INVALID: { userMessage: "That code is incorrect. Try again.", retryable: false },
  AUTH_MFA_CODE_EXPIRED: { userMessage: "That code expired. Request a new one.", retryable: true },
  AUTH_MFA_RECOVERY_CODE_INVALID: { userMessage: "That recovery code is incorrect.", retryable: false },
  AUTH_MFA_PUSH_TIMEOUT: { userMessage: "The approval request timed out. Try again.", retryable: true },
  AUTH_MFA_SMS_UNAVAILABLE: { userMessage: "SMS codes are unavailable right now. Try another method.", retryable: true },
  AUTH_UNKNOWN: { userMessage: "Something went wrong. Try again.", retryable: true },
};

const LEGACY_CODE_MAP: Record<string, AuthErrorCode> = {
  invalid_request: "AUTH_INVALID_REQUEST",
  invalid_request_body: "AUTH_INVALID_REQUEST",
  email_required: "AUTH_EMAIL_REQUIRED",
  invalid_email: "AUTH_INVALID_EMAIL",
  weak_password: "AUTH_PASSWORD_TOO_SHORT",
  invalid_credentials: "AUTH_INVALID_CREDENTIALS",
  user_not_found: "AUTH_INVALID_CREDENTIALS",
  account_locked: "AUTH_ACCOUNT_LOCKED",
  account_suspended: "AUTH_ACCOUNT_DISABLED",
  account_disabled: "AUTH_ACCOUNT_DISABLED",
  rate_limited: "AUTH_RATE_LIMITED",
  refresh_token_missing: "AUTH_TOKEN_MISSING",
  missing_authorization_header: "AUTH_TOKEN_MISSING",
  invalid_access_token: "AUTH_SESSION_EXPIRED",
  invalid_refresh_token: "AUTH_TOKEN_REVOKED",
  missing_api_key: "AUTH_SERVICE_UNAVAILABLE",
  invalid_api_key: "AUTH_SERVICE_UNAVAILABLE",
  redis_required: "AUTH_SERVICE_UNAVAILABLE",
  email_not_configured: "AUTH_SERVICE_UNAVAILABLE",
  internal_error: "AUTH_SERVICE_UNAVAILABLE",
  oauth_failed: "AUTH_OAUTH_FAILED",
  access_denied: "AUTH_OAUTH_CANCELLED",
  invalid_state: "AUTH_OAUTH_STATE_MISMATCH",
  oauth_provider_unavailable: "AUTH_OAUTH_PROVIDER_UNAVAILABLE",
  sso_required: "AUTH_SSO_FAILED",
  passkey_failed: "AUTH_PASSKEY_FAILED",
  authentication_failed: "AUTH_PASSKEY_FAILED",
  invalid_totp: "AUTH_MFA_CODE_INVALID",
  invalid_code: "AUTH_MFA_CODE_INVALID",
  invalid_recovery_code: "AUTH_MFA_RECOVERY_CODE_INVALID",
};

const invalidLoginCredentialsMessage = "Invalid email or password.";

function isAuthErrorCode(value: unknown): value is AuthErrorCode {
  return typeof value === "string" && (AUTH_ERROR_CODES as readonly string[]).includes(value);
}

function errorPayloadMessage(response: unknown): string {
  if (response && typeof response === "object") {
    const payload = response as { error?: unknown; message?: unknown; user_message?: unknown; userMessage?: unknown };
    return String(payload.userMessage || payload.user_message || payload.error || payload.message || "").trim();
  }
  if (typeof response === "string") return response.trim();
  return "";
}

function normalizeAuthServiceError(status: number, response: unknown, fallbackMessage = ""): NormalizedAuthError {
  const payload = response && typeof response === "object" ? response as Record<string, unknown> : {};
  const providerCode = String(payload.code || payload.error || "").trim();
  let code: AuthErrorCode = "AUTH_UNKNOWN";
  if (isAuthErrorCode(payload.auth_code) || isAuthErrorCode(payload.authCode)) {
    code = (payload.auth_code || payload.authCode) as AuthErrorCode;
  } else {
    const legacyCode = providerCode.toLowerCase().replace(/[\s-]+/g, "_");
    code = LEGACY_CODE_MAP[legacyCode] || codeFromStatusAndMessage(status, errorPayloadMessage(response) || fallbackMessage);
  }
  const definition = ERROR_DEFINITIONS[code];
  const userMessage = String(payload.userMessage || payload.user_message || definition.userMessage).trim();
  return {
    code,
    userMessage: userMessage || definition.userMessage,
    retryable: typeof payload.retryable === "boolean" ? payload.retryable : definition.retryable,
    providerCode: providerCode || undefined,
  };
}

function codeFromStatusAndMessage(status: number, message: string): AuthErrorCode {
  const lower = message.toLowerCase();
  if (lower.includes("invalid email or password")) return "AUTH_INVALID_CREDENTIALS";
  if (lower.includes("too many") || lower.includes("rate")) return "AUTH_RATE_LIMITED";
  if (lower.includes("passkey") || lower.includes("webauthn")) return "AUTH_PASSKEY_FAILED";
  if (lower.includes("totp") || lower.includes("2fa") || lower.includes("mfa")) return "AUTH_MFA_REQUIRED";
  if (status === 429) return "AUTH_RATE_LIMITED";
  if (status === 401) return "AUTH_SESSION_EXPIRED";
  if (status >= 500) return "AUTH_SERVICE_UNAVAILABLE";
  return "AUTH_UNKNOWN";
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
      const normalized = normalizeAuthServiceError(res.status, data, res.statusText);
      throw new AuthServiceError(normalized.userMessage, res.status, data, normalized);
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
