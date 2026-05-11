'use strict';

const crypto = require('crypto');

class AuthServiceNodeError extends Error {
  constructor(message, status, response) {
    super(message || 'AuthService request failed');
    this.name = 'AuthServiceNodeError';
    this.status = status || 0;
    this.response = response || null;
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

function errorPayloadMessage(response) {
  if (response && typeof response === 'object') return String(response.error || response.message || '').trim();
  if (typeof response === 'string') return response.trim();
  return '';
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
      throw new AuthServiceNodeError(message, res.status, data);
    }
    return data;
  }

  withSessionMode(body) {
    const next = Object.assign({}, body || {});
    if (this.sessionMode === 'token' && !next.session_mode) next.session_mode = 'token';
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
  AuthServiceNodeClient,
  AuthServiceNodeError,
  MemoryTokenStore,
  decodeJwt,
  randomB64url,
  createPKCEChallenge,
  permissionFor,
  createClient: (options) => new AuthServiceNodeClient(options)
};
