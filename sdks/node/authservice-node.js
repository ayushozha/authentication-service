'use strict';

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

class AuthServiceNodeClient {
  constructor(options) {
    options = options || {};
    this.baseUrl = String(options.baseUrl || '').replace(/\/+$/, '');
    this.apiKey = options.apiKey || '';
    this.adminKey = options.adminKey || '';
    this.sessionMode = options.sessionMode || 'token';
    this.tokenStore = options.tokenStore || new MemoryTokenStore();
    this.fetch = options.fetch || globalThis.fetch;
    if (!this.fetch) throw new Error('AuthServiceNodeClient requires fetch. Use Node 18+ or pass options.fetch.');
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

    const res = await this.fetch(this.baseUrl + path, init);
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

  signup(params) {
    return this.request('/api/auth/signup', { method: 'POST', body: this.withSessionMode(params), auth: false }).then((data) => this.persist(data));
  }

  login(params) {
    return this.request('/api/auth/login', { method: 'POST', body: this.withSessionMode(params), auth: false }).then((data) => this.persist(data));
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

  createOrganizationToken(organizationId, activate) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationId) + '/token', { method: 'POST', body: {} }).then((data) => {
      if (activate && data && data.access_token) this.tokenStore.setAccessToken(data.access_token);
      return data;
    });
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
}

module.exports = {
  AuthServiceNodeClient,
  AuthServiceNodeError,
  MemoryTokenStore,
  createClient: (options) => new AuthServiceNodeClient(options)
};
