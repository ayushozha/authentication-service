'use strict';

const crypto = require('crypto');

class AuthServiceNodeError extends Error {
  constructor(message, status, response, normalized) {
    const error = normalized || normalizeAuthServiceError(status || 0, response, message);
    super(error.userMessage || message || 'AuthService request failed');
    this.name = 'AuthServiceNodeError';
    this.status = status || 0;
    this.response = response || null;
    this.code = error.code;
    this.userMessage = error.userMessage;
    this.retryable = error.retryable;
    this.providerCode = error.providerCode;
  }
}

class MemoryTokenStore {
  constructor() {
    this.accessToken = '';
    this.refreshToken = '';
  }

  getAccessToken() {
    return this.accessToken;
  }

  setAccessToken(token) {
    this.accessToken = token || '';
  }

  getRefreshToken() {
    return this.refreshToken;
  }

  setRefreshToken(token) {
    this.refreshToken = token || '';
  }
}

function decodeJwt(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length < 2) return null;
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch (err) {
    return null;
  }
}

function randomB64url(byteLength) {
  return crypto.randomBytes(byteLength || 32).toString('base64url');
}

function createPKCEChallenge(verifier) {
  return crypto.createHash('sha256').update(String(verifier || '')).digest('base64url');
}

function permissionFor(resource, action) {
  resource = String(resource || '').trim().toLowerCase();
  action = String(action || '').trim().toLowerCase();
  return resource && action ? resource + ':' + action : '';
}

const INVALID_LOGIN_CREDENTIALS_MESSAGE = 'Invalid email or password.';
const AUTH_ERROR_CODES = [
  'AUTH_INVALID_REQUEST',
  'AUTH_EMAIL_REQUIRED',
  'AUTH_PASSWORD_REQUIRED',
  'AUTH_EMAIL_PASSWORD_REQUIRED',
  'AUTH_INVALID_EMAIL',
  'AUTH_PASSWORD_TOO_SHORT',
  'AUTH_INVALID_CREDENTIALS',
  'AUTH_ACCOUNT_LOCKED',
  'AUTH_ACCOUNT_DISABLED',
  'AUTH_RATE_LIMITED',
  'AUTH_SESSION_EXPIRED',
  'AUTH_TOKEN_MISSING',
  'AUTH_TOKEN_REVOKED',
  'AUTH_STORAGE_UNAVAILABLE',
  'AUTH_STORAGE_WRITE_FAILED',
  'AUTH_NETWORK_UNAVAILABLE',
  'AUTH_SERVICE_UNAVAILABLE',
  'AUTH_OAUTH_FAILED',
  'AUTH_OAUTH_CANCELLED',
  'AUTH_OAUTH_STATE_MISMATCH',
  'AUTH_OAUTH_PROVIDER_UNAVAILABLE',
  'AUTH_SSO_FAILED',
  'AUTH_PASSKEY_FAILED',
  'AUTH_PASSKEY_CANCELLED',
  'AUTH_BIOMETRIC_UNAVAILABLE',
  'AUTH_BIOMETRIC_CANCELLED',
  'AUTH_BIOMETRIC_LOCKOUT',
  'AUTH_MFA_REQUIRED',
  'AUTH_MFA_CODE_INVALID',
  'AUTH_MFA_CODE_EXPIRED',
  'AUTH_MFA_RECOVERY_CODE_INVALID',
  'AUTH_MFA_PUSH_TIMEOUT',
  'AUTH_MFA_SMS_UNAVAILABLE',
  'AUTH_UNKNOWN'
];
const ERROR_DEFINITIONS = {
  AUTH_INVALID_REQUEST: { userMessage: 'We could not process that request. Try again.', retryable: false },
  AUTH_EMAIL_REQUIRED: { userMessage: 'Enter your email address.', retryable: false },
  AUTH_PASSWORD_REQUIRED: { userMessage: 'Enter your password.', retryable: false },
  AUTH_EMAIL_PASSWORD_REQUIRED: { userMessage: 'Enter your email and password.', retryable: false },
  AUTH_INVALID_EMAIL: { userMessage: 'Enter a valid email address.', retryable: false },
  AUTH_PASSWORD_TOO_SHORT: { userMessage: 'Use at least 8 characters for your password.', retryable: false },
  AUTH_INVALID_CREDENTIALS: { userMessage: INVALID_LOGIN_CREDENTIALS_MESSAGE, retryable: false },
  AUTH_ACCOUNT_LOCKED: { userMessage: 'This account is locked. Check your email for next steps.', retryable: false },
  AUTH_ACCOUNT_DISABLED: { userMessage: 'This account cannot sign in right now.', retryable: false },
  AUTH_RATE_LIMITED: { userMessage: 'Too many attempts. Try again in a few minutes.', retryable: true },
  AUTH_SESSION_EXPIRED: { userMessage: 'Your session expired. Sign in again.', retryable: false },
  AUTH_TOKEN_MISSING: { userMessage: 'Sign in again to continue.', retryable: false },
  AUTH_TOKEN_REVOKED: { userMessage: 'Your session is no longer active. Sign in again.', retryable: false },
  AUTH_STORAGE_UNAVAILABLE: { userMessage: 'Secure storage is unavailable on this device.', retryable: false },
  AUTH_STORAGE_WRITE_FAILED: { userMessage: 'We could not save your sign-in securely. Try again.', retryable: true },
  AUTH_NETWORK_UNAVAILABLE: { userMessage: 'Check your connection and try again.', retryable: true },
  AUTH_SERVICE_UNAVAILABLE: { userMessage: 'We could not sign you in right now. Try again later.', retryable: true },
  AUTH_OAUTH_FAILED: { userMessage: 'We could not complete sign-in with that provider.', retryable: true },
  AUTH_OAUTH_CANCELLED: { userMessage: 'Sign-in was cancelled.', retryable: false },
  AUTH_OAUTH_STATE_MISMATCH: { userMessage: 'We could not verify that sign-in. Try again.', retryable: false },
  AUTH_OAUTH_PROVIDER_UNAVAILABLE: { userMessage: 'That sign-in provider is unavailable. Try again later.', retryable: true },
  AUTH_SSO_FAILED: { userMessage: 'We could not complete single sign-on. Try again.', retryable: true },
  AUTH_PASSKEY_FAILED: { userMessage: 'We could not complete passkey sign-in. Try again.', retryable: true },
  AUTH_PASSKEY_CANCELLED: { userMessage: 'Passkey sign-in was cancelled.', retryable: false },
  AUTH_BIOMETRIC_UNAVAILABLE: { userMessage: 'Biometric unlock is unavailable on this device.', retryable: false },
  AUTH_BIOMETRIC_CANCELLED: { userMessage: 'Biometric unlock was cancelled.', retryable: false },
  AUTH_BIOMETRIC_LOCKOUT: { userMessage: 'Biometric unlock is locked. Use your device passcode.', retryable: false },
  AUTH_MFA_REQUIRED: { userMessage: 'Enter the code from your authenticator app.', retryable: false },
  AUTH_MFA_CODE_INVALID: { userMessage: 'That code is incorrect. Try again.', retryable: false },
  AUTH_MFA_CODE_EXPIRED: { userMessage: 'That code expired. Request a new one.', retryable: true },
  AUTH_MFA_RECOVERY_CODE_INVALID: { userMessage: 'That recovery code is incorrect.', retryable: false },
  AUTH_MFA_PUSH_TIMEOUT: { userMessage: 'The approval request timed out. Try again.', retryable: true },
  AUTH_MFA_SMS_UNAVAILABLE: { userMessage: 'SMS codes are unavailable right now. Try another method.', retryable: true },
  AUTH_UNKNOWN: { userMessage: 'Something went wrong. Try again.', retryable: true }
};
const LEGACY_CODE_MAP = {
  invalid_request: 'AUTH_INVALID_REQUEST',
  invalid_request_body: 'AUTH_INVALID_REQUEST',
  invalid_json: 'AUTH_INVALID_REQUEST',
  malformed_body: 'AUTH_INVALID_REQUEST',
  method_not_allowed: 'AUTH_INVALID_REQUEST',
  origin_not_allowed: 'AUTH_INVALID_REQUEST',
  token_is_required: 'AUTH_INVALID_REQUEST',
  code_is_required: 'AUTH_INVALID_REQUEST',
  session_id_required: 'AUTH_INVALID_REQUEST',
  passkey_id_required: 'AUTH_INVALID_REQUEST',
  token_and_code_are_required: 'AUTH_INVALID_REQUEST',
  token_and_new_password_are_required: 'AUTH_INVALID_REQUEST',
  email_required: 'AUTH_EMAIL_REQUIRED',
  email_is_required: 'AUTH_EMAIL_REQUIRED',
  password_required: 'AUTH_PASSWORD_REQUIRED',
  password_is_required: 'AUTH_PASSWORD_REQUIRED',
  email_and_password_required: 'AUTH_EMAIL_PASSWORD_REQUIRED',
  invalid_email: 'AUTH_INVALID_EMAIL',
  weak_password: 'AUTH_PASSWORD_TOO_SHORT',
  password_too_short: 'AUTH_PASSWORD_TOO_SHORT',
  invalid_credentials: 'AUTH_INVALID_CREDENTIALS',
  wrong_password: 'AUTH_INVALID_CREDENTIALS',
  user_not_found: 'AUTH_INVALID_CREDENTIALS',
  account_locked: 'AUTH_ACCOUNT_LOCKED',
  account_suspended: 'AUTH_ACCOUNT_DISABLED',
  account_disabled: 'AUTH_ACCOUNT_DISABLED',
  user_disabled: 'AUTH_ACCOUNT_DISABLED',
  security_policy_blocked: 'AUTH_ACCOUNT_DISABLED',
  rate_limited: 'AUTH_RATE_LIMITED',
  too_many_requests: 'AUTH_RATE_LIMITED',
  missing_authorization_header: 'AUTH_TOKEN_MISSING',
  missing_token: 'AUTH_TOKEN_MISSING',
  token_missing: 'AUTH_TOKEN_MISSING',
  refresh_token_missing: 'AUTH_TOKEN_MISSING',
  invalid_authorization_format: 'AUTH_TOKEN_MISSING',
  unauthorized: 'AUTH_TOKEN_MISSING',
  invalid_access_token: 'AUTH_SESSION_EXPIRED',
  invalid_or_expired_token: 'AUTH_SESSION_EXPIRED',
  token_client_mismatch: 'AUTH_SESSION_EXPIRED',
  invalid_refresh_token: 'AUTH_TOKEN_REVOKED',
  refresh_token_revoked: 'AUTH_TOKEN_REVOKED',
  token_revoked: 'AUTH_TOKEN_REVOKED',
  missing_api_key: 'AUTH_SERVICE_UNAVAILABLE',
  invalid_api_key: 'AUTH_SERVICE_UNAVAILABLE',
  missing_client: 'AUTH_SERVICE_UNAVAILABLE',
  missing_client_context: 'AUTH_SERVICE_UNAVAILABLE',
  invalid_client: 'AUTH_SERVICE_UNAVAILABLE',
  client_suspended: 'AUTH_SERVICE_UNAVAILABLE',
  redis_required: 'AUTH_SERVICE_UNAVAILABLE',
  email_not_configured: 'AUTH_SERVICE_UNAVAILABLE',
  internal_error: 'AUTH_SERVICE_UNAVAILABLE',
  service_unavailable: 'AUTH_SERVICE_UNAVAILABLE',
  redirect_code_unavailable: 'AUTH_SERVICE_UNAVAILABLE',
  network_error: 'AUTH_NETWORK_UNAVAILABLE',
  timeout: 'AUTH_NETWORK_UNAVAILABLE',
  oauth_failed: 'AUTH_OAUTH_FAILED',
  oauth_error: 'AUTH_OAUTH_FAILED',
  exchange_failed: 'AUTH_OAUTH_FAILED',
  userinfo_failed: 'AUTH_OAUTH_FAILED',
  read_failed: 'AUTH_OAUTH_FAILED',
  parse_failed: 'AUTH_OAUTH_FAILED',
  create_failed: 'AUTH_OAUTH_FAILED',
  access_denied: 'AUTH_OAUTH_CANCELLED',
  oauth_cancelled: 'AUTH_OAUTH_CANCELLED',
  invalid_state: 'AUTH_OAUTH_STATE_MISMATCH',
  state_mismatch: 'AUTH_OAUTH_STATE_MISMATCH',
  oauth_state_mismatch: 'AUTH_OAUTH_STATE_MISMATCH',
  oauth_provider_unavailable: 'AUTH_OAUTH_PROVIDER_UNAVAILABLE',
  oauth_requires_redis: 'AUTH_OAUTH_PROVIDER_UNAVAILABLE',
  sso_required: 'AUTH_SSO_FAILED',
  sso_failed: 'AUTH_SSO_FAILED',
  invalid_sso_connection: 'AUTH_SSO_FAILED',
  passkey_failed: 'AUTH_PASSKEY_FAILED',
  webauthn_failed: 'AUTH_PASSKEY_FAILED',
  authentication_failed: 'AUTH_PASSKEY_FAILED',
  registration_failed: 'AUTH_PASSKEY_FAILED',
  no_registration_in_progress: 'AUTH_PASSKEY_FAILED',
  no_login_in_progress: 'AUTH_PASSKEY_FAILED',
  passkey_attestation_rejected: 'AUTH_PASSKEY_FAILED',
  passkey_cancelled: 'AUTH_PASSKEY_CANCELLED',
  requires_2fa: 'AUTH_MFA_REQUIRED',
  totp_required: 'AUTH_MFA_REQUIRED',
  mfa_required: 'AUTH_MFA_REQUIRED',
  invalid_totp: 'AUTH_MFA_CODE_INVALID',
  totp_invalid: 'AUTH_MFA_CODE_INVALID',
  invalid_code: 'AUTH_MFA_CODE_INVALID',
  mfa_code_invalid: 'AUTH_MFA_CODE_INVALID',
  otp_expired: 'AUTH_MFA_CODE_EXPIRED',
  mfa_code_expired: 'AUTH_MFA_CODE_EXPIRED',
  invalid_or_expired_2fa_token: 'AUTH_MFA_CODE_EXPIRED',
  invalid_recovery_code: 'AUTH_MFA_RECOVERY_CODE_INVALID',
  recovery_code_invalid: 'AUTH_MFA_RECOVERY_CODE_INVALID',
  mfa_push_timeout: 'AUTH_MFA_PUSH_TIMEOUT',
  sms_unavailable: 'AUTH_MFA_SMS_UNAVAILABLE'
};

function errorPayloadMessage(response) {
  if (response && typeof response === 'object') {
    return String(response.userMessage || response.user_message || response.error || response.message || '').trim();
  }
  if (typeof response === 'string') return response.trim();
  return '';
}

function isAuthErrorCode(value) {
  return typeof value === 'string' && AUTH_ERROR_CODES.includes(value);
}

function normalizeLegacyErrorCode(value) {
  return String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_').replace(/_+/g, '_');
}

function authCodeFromStatusAndMessage(status, message) {
  const lower = String(message || '').toLowerCase();
  if (lower.includes('invalid email or password')) return 'AUTH_INVALID_CREDENTIALS';
  if (lower.includes('invalid email')) return 'AUTH_INVALID_EMAIL';
  if (lower.includes('password') && lower.includes('required')) return 'AUTH_PASSWORD_REQUIRED';
  if (lower.includes('at least 8') || lower.includes('password does not meet')) return 'AUTH_PASSWORD_TOO_SHORT';
  if (lower.includes('too many') || lower.includes('rate')) return 'AUTH_RATE_LIMITED';
  if (lower.includes('redis') || lower.includes('not configured')) return 'AUTH_SERVICE_UNAVAILABLE';
  if (lower.includes('passkey') || lower.includes('webauthn')) return 'AUTH_PASSKEY_FAILED';
  if (lower.includes('totp') || lower.includes('2fa') || lower.includes('mfa')) return 'AUTH_MFA_REQUIRED';
  if (status === 429) return 'AUTH_RATE_LIMITED';
  if (status === 401) return 'AUTH_SESSION_EXPIRED';
  if (status >= 500) return 'AUTH_SERVICE_UNAVAILABLE';
  return 'AUTH_UNKNOWN';
}

function normalizeAuthServiceError(status, response, fallbackMessage) {
  const payload = response && typeof response === 'object' ? response : {};
  const providerCode = String(payload.code || payload.error || '').trim();
  let code = 'AUTH_UNKNOWN';
  if (isAuthErrorCode(payload.auth_code) || isAuthErrorCode(payload.authCode)) {
    code = payload.auth_code || payload.authCode;
  } else {
    const legacyCode = normalizeLegacyErrorCode(providerCode);
    code = LEGACY_CODE_MAP[legacyCode] || authCodeFromStatusAndMessage(status, errorPayloadMessage(response) || fallbackMessage);
  }
  const definition = ERROR_DEFINITIONS[code] || ERROR_DEFINITIONS.AUTH_UNKNOWN;
  const userMessage = String(payload.userMessage || payload.user_message || definition.userMessage).trim();
  return {
    code,
    userMessage: userMessage || definition.userMessage,
    retryable: typeof payload.retryable === 'boolean' ? payload.retryable : definition.retryable,
    providerCode: providerCode || undefined
  };
}

function normalizeLoginError(err) {
  const serverMessage = errorPayloadMessage(err && err.response).toLowerCase();
  if (err instanceof AuthServiceNodeError && err.status === 401 && serverMessage === 'invalid email or password') {
    return new AuthServiceNodeError(INVALID_LOGIN_CREDENTIALS_MESSAGE, err.status, err.response);
  }
  return err;
}

class AuthServiceNodeClient {
  constructor(options) {
    options = options || {};
    this.baseUrl = String(options.baseUrl || '').replace(/\/+$/, '');
    this.apiKey = options.apiKey || '';
    this.clientId = options.clientId || options.oidcClientId || '';
    this.adminKey = options.adminKey || '';
    this.sessionMode = options.sessionMode || 'token';
    this.tokenStore = options.tokenStore || new MemoryTokenStore();
    this.fetch = options.fetch || globalThis.fetch;
    if (!this.fetch) throw new Error('AuthServiceNodeClient requires fetch. Use Node 18+ or pass options.fetch.');
  }

  url(path, query) {
    const params = new URLSearchParams();
    Object.entries(query || {}).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') params.set(key, String(value));
    });
    const encoded = params.toString();
    return this.baseUrl + path + (encoded ? (path.includes('?') ? '&' : '?') + encoded : '');
  }

  async request(path, options) {
    options = options || {};
    const headers = Object.assign({}, options.headers || {});
    if (options.admin) headers['X-Admin-Key'] = this.adminKey;
    else if (this.apiKey) headers['X-API-Key'] = this.apiKey;
    if (options.auth !== false && this.tokenStore.getAccessToken()) {
      headers.Authorization = 'Bearer ' + this.tokenStore.getAccessToken();
    }

    const init = { method: options.method || 'GET', headers };
    if (options.body !== undefined) {
      headers['Content-Type'] = headers['Content-Type'] || 'application/json';
      init.body = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
    }

    const res = await this.fetch(this.url(path, options.query), init);
    const text = await res.text();
    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch (err) {
        data = text;
      }
    }
    if (!res.ok) {
      const message = data && (data.error || data.message) ? data.error || data.message : res.statusText;
      const normalized = normalizeAuthServiceError(res.status, data, message);
      throw new AuthServiceNodeError(normalized.userMessage, res.status, data, normalized);
    }
    return data;
  }

  withSessionMode(body) {
    const next = Object.assign({}, body || {});
    if (this.sessionMode === 'token') {
      if (!next.session_mode) next.session_mode = 'token';
      if (!next.token_transport) next.token_transport = 'json';
    }
    return next;
  }

  persist(response) {
    if (response && response.access_token) this.tokenStore.setAccessToken(response.access_token);
    if (response && response.refresh_token) this.tokenStore.setRefreshToken(response.refresh_token);
    return response;
  }

  createOIDCAuthorizationURL(options) {
    options = options || {};
    const clientId = options.clientId || options.client_id || this.clientId;
    const redirectUri = options.redirectUri || options.redirect_uri;
    const codeVerifier = options.codeVerifier || options.code_verifier || randomB64url(64);
    const codeChallengeMethod = options.codeChallengeMethod || options.code_challenge_method || 'S256';
    const codeChallenge = codeChallengeMethod === 'plain' ? codeVerifier : createPKCEChallenge(codeVerifier);
    const state = options.state || randomB64url(24);
    const nonce = options.nonce || randomB64url(24);
    return {
      url: this.url('/authorize', {
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: options.responseType || options.response_type || 'code',
        scope: options.scope || 'openid profile email',
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: codeChallengeMethod,
        audience: options.audience || '',
        resource: options.resource || '',
        prompt: options.prompt || ''
      }),
      state,
      nonce,
      codeVerifier,
      codeChallenge,
      redirectUri,
      clientId
    };
  }

  exchangeOIDCCode(params) {
    params = params || {};
    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('client_id', params.clientId || params.client_id || this.clientId);
    body.set('code', params.code || '');
    body.set('redirect_uri', params.redirectUri || params.redirect_uri || '');
    body.set('code_verifier', params.codeVerifier || params.code_verifier || '');
    if (params.clientSecret || params.client_secret) body.set('client_secret', params.clientSecret || params.client_secret);
    return this.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      auth: false
    }).then((data) => this.persist(data));
  }

  handleOIDCCallback(callbackUrl, options) {
    options = options || {};
    const parsed = new URL(callbackUrl, this.baseUrl || 'http://localhost');
    if (parsed.searchParams.get('error')) {
      throw new AuthServiceNodeError(parsed.searchParams.get('error_description') || parsed.searchParams.get('error'), 400, {
        error: parsed.searchParams.get('error')
      });
    }
    if (options.state && parsed.searchParams.get('state') !== options.state) {
      throw new AuthServiceNodeError('OIDC state mismatch', 400);
    }
    return this.exchangeOIDCCode(Object.assign({}, options, { code: parsed.searchParams.get('code') || '' }));
  }

  oidcUserInfo(accessToken) {
    return this.request('/userinfo', {
      method: 'GET',
      headers: { Authorization: 'Bearer ' + (accessToken || this.tokenStore.getAccessToken()) },
      auth: false
    });
  }

  getAccessClaims(token) {
    return decodeJwt(token || this.tokenStore.getAccessToken());
  }

  hasScope(scope, claims) {
    claims = claims || this.getAccessClaims() || {};
    const scopes = Array.isArray(claims.scopes) ? claims.scopes : String(claims.scope || '').split(/\s+/).filter(Boolean);
    return scopes.includes(scope);
  }

  hasOrganizationPermission(permission, claims) {
    claims = claims || this.getAccessClaims() || {};
    if (claims.org_role === 'owner') return true;
    return Array.isArray(claims.org_permissions) && claims.org_permissions.includes(permission);
  }

  isAuthorized(resource, action, claims) {
    return this.hasOrganizationPermission(permissionFor(resource, action), claims);
  }

  signup(params) {
    return this.request('/api/auth/signup', { method: 'POST', body: this.withSessionMode(params), auth: false }).then((data) => this.persist(data));
  }

  login(params) {
    return this.request('/api/auth/login', { method: 'POST', body: this.withSessionMode(params), auth: false })
      .then((data) => this.persist(data))
      .catch((err) => { throw normalizeLoginError(err); });
  }

  refresh(params) {
    const body = this.withSessionMode(params || {});
    if (this.sessionMode === 'token' && !body.refresh_token) body.refresh_token = this.tokenStore.getRefreshToken();
    return this.request('/api/auth/refresh', { method: 'POST', body, auth: false }).then((data) => this.persist(data));
  }

  logout() {
    return this.request('/api/auth/logout', {
      method: 'POST',
      body: { refresh_token: this.tokenStore.getRefreshToken() },
      auth: false
    }).finally(() => {
      this.tokenStore.setAccessToken('');
      this.tokenStore.setRefreshToken('');
    });
  }

  me() {
    return this.request('/api/auth/me');
  }

  updateProfile(params) {
    return this.request('/api/auth/me', { method: 'PATCH', body: params || {} });
  }

  changePassword(params) {
    return this.request('/api/auth/change-password', { method: 'POST', body: params || {} });
  }

  getUIConfig() {
    return this.request('/api/auth/ui/config', { auth: false });
  }

  forgotPassword(emailOrParams) {
    const body = typeof emailOrParams === 'string' ? { email: emailOrParams } : (emailOrParams || {});
    return this.request('/api/auth/forgot-password', { method: 'POST', body, auth: false });
  }

  resetPassword(params) {
    const body = Object.assign({}, params || {});
    if (body.password && !body.new_password) body.new_password = body.password;
    delete body.password;
    return this.request('/api/auth/reset-password', { method: 'POST', body, auth: false });
  }

  verifyEmail(tokenOrParams) {
    const body = typeof tokenOrParams === 'string' ? { token: tokenOrParams } : (tokenOrParams || {});
    return this.request('/api/auth/verify-email', { method: 'POST', body, auth: false });
  }

  listSessions() {
    return this.request('/api/auth/sessions');
  }

  revokeSession(sessionId) {
    return this.request('/api/auth/sessions/' + encodeURIComponent(sessionId), { method: 'DELETE' });
  }

  revokeAllSessions() {
    return this.request('/api/auth/sessions', { method: 'DELETE' }).finally(() => {
      this.tokenStore.setAccessToken('');
      this.tokenStore.setRefreshToken('');
    });
  }

  verifyTOTP(params) {
    return this.request('/api/auth/totp/verify', { method: 'POST', body: this.withSessionMode(params), auth: false }).then((data) => this.persist(data));
  }

  verifyRecoveryCode(params) {
    return this.request('/api/auth/recovery-codes/verify', { method: 'POST', body: this.withSessionMode(params), auth: false }).then((data) => this.persist(data));
  }

  listOrganizations() {
    return this.request('/api/auth/organizations');
  }

  createOrganization(params) {
    return this.request('/api/auth/organizations', { method: 'POST', body: params || {} });
  }

  listOrganizationMembers(organizationId) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationId) + '/members');
  }

  updateOrganizationMember(organizationId, userId, params) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationId) + '/members/' + encodeURIComponent(userId), { method: 'PATCH', body: params || {} });
  }

  inviteOrganizationMember(organizationId, params) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationId) + '/invitations', { method: 'POST', body: params || {} });
  }

  createOrganizationToken(organizationId, activate) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationId) + '/token', { method: 'POST', body: {} }).then((data) => {
      if (activate && data && data.access_token) this.tokenStore.setAccessToken(data.access_token);
      return data;
    });
  }

  getAuthorizationPolicy(organizationId) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationId) + '/authorization/policy');
  }

  updateAuthorizationPolicy(organizationId, params) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationId) + '/authorization/policy', { method: 'PUT', body: params || {} });
  }

  listAuthorizationGroupMappings(organizationId) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationId) + '/authorization/group-mappings');
  }

  upsertAuthorizationGroupMapping(organizationId, mappingId, params) {
    const suffix = mappingId ? '/' + encodeURIComponent(mappingId) : '';
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationId) + '/authorization/group-mappings' + suffix, {
      method: mappingId ? 'PATCH' : 'POST',
      body: params || {}
    });
  }

  deleteAuthorizationGroupMapping(organizationId, mappingId) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationId) + '/authorization/group-mappings/' + encodeURIComponent(mappingId), { method: 'DELETE' });
  }

  simulateAuthorization(organizationId, params) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationId) + '/authorization/simulate', { method: 'POST', body: params || {} });
  }

  clientCredentials(params) {
    const body = new URLSearchParams();
    body.set('grant_type', 'client_credentials');
    body.set('client_id', params.clientId || params.client_id);
    body.set('client_secret', params.clientSecret || params.client_secret);
    if (params.scope) body.set('scope', params.scope);
    return this.request('/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      auth: false
    });
  }

  introspect(token, credentials) {
    const body = new URLSearchParams();
    body.set('token', token);
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (credentials && credentials.clientId && credentials.clientSecret) {
      headers.Authorization = 'Basic ' + Buffer.from(credentials.clientId + ':' + credentials.clientSecret).toString('base64');
    }
    return this.request('/oauth/introspect', { method: 'POST', headers, body: body.toString(), auth: false });
  }

  listClients() {
    return this.request('/api/admin/clients', { admin: true, auth: false });
  }

  updateClient(clientId, params) {
    return this.request('/api/admin/clients/' + encodeURIComponent(clientId), {
      method: 'PATCH',
      body: params || {},
      admin: true,
      auth: false
    });
  }

  listSSOConnections(clientId) {
    return this.request('/api/admin/clients/' + encodeURIComponent(clientId) + '/sso-connections', { admin: true, auth: false });
  }

  createSSOConnection(clientId, params) {
    return this.request('/api/admin/clients/' + encodeURIComponent(clientId) + '/sso-connections', {
      method: 'POST',
      body: params || {},
      admin: true,
      auth: false
    });
  }

  listSCIMDirectories(clientId) {
    return this.request('/api/admin/clients/' + encodeURIComponent(clientId) + '/scim-directories', { admin: true, auth: false });
  }

  createSCIMDirectory(clientId, params) {
    return this.request('/api/admin/clients/' + encodeURIComponent(clientId) + '/scim-directories', {
      method: 'POST',
      body: params || {},
      admin: true,
      auth: false
    });
  }

  listAuditEvents(params) {
    return this.request('/api/admin/audit-events', { query: params || {}, admin: true, auth: false });
  }
}

module.exports = {
  AUTH_ERROR_CODES,
  AuthServiceNodeClient,
  AuthServiceNodeError,
  MemoryTokenStore,
  decodeJwt,
  randomB64url,
  createPKCEChallenge,
  permissionFor,
  createClient: (options) => new AuthServiceNodeClient(options)
};
