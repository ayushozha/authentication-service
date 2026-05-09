(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(root);
  } else {
    root.AuthService = factory(root);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function(root) {
  'use strict';

  var VERSION = '0.1.0';
  var DEFAULT_PREFIX = 'authservice_';

  function AuthServiceError(message, status, response) {
    this.name = 'AuthServiceError';
    this.message = message || 'AuthService request failed';
    this.status = status || 0;
    this.response = response || null;
    if (Error.captureStackTrace) Error.captureStackTrace(this, AuthServiceError);
  }
  AuthServiceError.prototype = Object.create(Error.prototype);
  AuthServiceError.prototype.constructor = AuthServiceError;

  function noopStorage() {
    var data = {};
    return {
      getItem: function(key) { return Object.prototype.hasOwnProperty.call(data, key) ? data[key] : null; },
      setItem: function(key, value) { data[key] = String(value); },
      removeItem: function(key) { delete data[key]; }
    };
  }

  function getDefaultStorage() {
    try {
      if (root.localStorage) return root.localStorage;
    } catch (err) {
      return noopStorage();
    }
    return noopStorage();
  }

  function merge(target) {
    target = target || {};
    for (var i = 1; i < arguments.length; i++) {
      var source = arguments[i] || {};
      for (var key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key)) target[key] = source[key];
      }
    }
    return target;
  }

  function trimRightSlash(value) {
    return String(value || '').replace(/\/+$/, '');
  }

  function encodeQuery(query) {
    var parts = [];
    query = query || {};
    for (var key in query) {
      if (!Object.prototype.hasOwnProperty.call(query, key)) continue;
      var value = query[key];
      if (value === undefined || value === null || value === '') continue;
      parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(String(value)));
    }
    return parts.join('&');
  }

  function isFormBody(body) {
    return (typeof FormData !== 'undefined' && body instanceof FormData) ||
      (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) ||
      (typeof Blob !== 'undefined' && body instanceof Blob);
  }

  function b64urlToBuffer(value) {
    var pad = '='.repeat((4 - value.length % 4) % 4);
    var base64 = (value + pad).replace(/-/g, '+').replace(/_/g, '/');
    var raw = root.atob(base64);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out.buffer;
  }

  function bufferToB64url(buffer) {
    if (!buffer) return null;
    var bytes = new Uint8Array(buffer);
    var raw = '';
    for (var i = 0; i < bytes.byteLength; i++) raw += String.fromCharCode(bytes[i]);
    return root.btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  function prepareCreationOptions(options) {
    var publicKey = options.publicKey || options;
    publicKey.challenge = b64urlToBuffer(publicKey.challenge);
    if (publicKey.user && typeof publicKey.user.id === 'string') {
      publicKey.user.id = b64urlToBuffer(publicKey.user.id);
    }
    if (publicKey.excludeCredentials) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map(function(credential) {
        return merge({}, credential, { id: b64urlToBuffer(credential.id) });
      });
    }
    publicKey.authenticatorSelection = merge({}, publicKey.authenticatorSelection, {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required'
    });
    return publicKey;
  }

  function prepareRequestOptions(options) {
    var publicKey = options.publicKey || options;
    publicKey.challenge = b64urlToBuffer(publicKey.challenge);
    if (publicKey.allowCredentials) {
      publicKey.allowCredentials = publicKey.allowCredentials.map(function(credential) {
        return merge({}, credential, { id: b64urlToBuffer(credential.id) });
      });
    }
    return publicKey;
  }

  function credentialToJSON(credential) {
    var response = {
      clientDataJSON: bufferToB64url(credential.response.clientDataJSON)
    };
    if (credential.response.attestationObject) response.attestationObject = bufferToB64url(credential.response.attestationObject);
    if (credential.response.authenticatorData) response.authenticatorData = bufferToB64url(credential.response.authenticatorData);
    if (credential.response.signature) response.signature = bufferToB64url(credential.response.signature);
    if (credential.response.userHandle) response.userHandle = bufferToB64url(credential.response.userHandle);

    var payload = {
      id: credential.id,
      rawId: bufferToB64url(credential.rawId),
      type: credential.type,
      response: response
    };
    if (credential.authenticatorAttachment) payload.authenticatorAttachment = credential.authenticatorAttachment;
    if (credential.getClientExtensionResults) payload.clientExtensionResults = credential.getClientExtensionResults();
    return payload;
  }

  function resolveContainer(container) {
    var el = typeof container === 'string' ? root.document.querySelector(container) : container;
    if (!el) throw new Error('AuthService widget container not found');
    return el;
  }

  function ensureWidgetStyles() {
    if (!root.document || root.document.getElementById('authservice-widget-styles')) return;
    var style = root.document.createElement('style');
    style.id = 'authservice-widget-styles';
    style.textContent = [
      '.as-card{border:1px solid #d8dee8;border-radius:8px;background:#fff;color:#172033;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:16px;max-width:360px}',
      '.as-stack{display:grid;gap:10px}',
      '.as-field{display:grid;gap:4px}',
      '.as-field label{font-size:12px;font-weight:700;color:#536276}',
      '.as-input{width:100%;min-height:38px;border:1px solid #cfd7e3;border-radius:8px;padding:8px 10px;font:inherit}',
      '.as-button{min-height:38px;border:0;border-radius:8px;background:#146b65;color:#fff;font-weight:700;cursor:pointer;padding:8px 12px}',
      '.as-button.secondary{background:#eef3f7;color:#172033;border:1px solid #cfd7e3}',
      '.as-button:disabled{opacity:.6;cursor:not-allowed}',
      '.as-message{display:none;border-radius:8px;padding:9px 10px;font-size:13px}',
      '.as-message.show{display:block}',
      '.as-message.error{background:#fff1f2;color:#be123c;border:1px solid #fecdd3}',
      '.as-message.ok{background:#ecfdf5;color:#047857;border:1px solid #a7f3d0}',
      '.as-user{display:flex;align-items:center;justify-content:space-between;gap:12px;border:1px solid #d8dee8;border-radius:8px;background:#fff;padding:12px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}',
      '.as-user-name{font-weight:800;color:#172033}',
      '.as-user-email{font-size:12px;color:#536276;word-break:break-word}'
    ].join('');
    root.document.head.appendChild(style);
  }

  function AuthClient(options) {
    options = options || {};
    this.baseUrl = trimRightSlash(options.baseUrl || (root.location && root.location.origin) || '');
    this.apiKey = options.apiKey || options.publishableKey || options.clientKey || '';
    this.sessionMode = options.sessionMode || 'token';
    this.storagePrefix = options.storagePrefix || DEFAULT_PREFIX;
    this.storage = options.storage === false ? noopStorage() : (options.storage || getDefaultStorage());
    this.fetch = options.fetch || (root.fetch && root.fetch.bind(root));
    if (!this.apiKey) this.apiKey = this.storage.getItem('auth_api_key') || this.storage.getItem(this.key('api_key')) || '';
    if (!this.fetch) throw new Error('AuthService requires fetch');
  }

  AuthClient.prototype.key = function(name) {
    return this.storagePrefix + name;
  };

  AuthClient.prototype.setAPIKey = function(apiKey) {
    this.apiKey = apiKey || '';
    if (this.apiKey) {
      this.storage.setItem('auth_api_key', this.apiKey);
      this.storage.setItem(this.key('api_key'), this.apiKey);
    } else {
      this.storage.removeItem('auth_api_key');
      this.storage.removeItem(this.key('api_key'));
    }
    return this;
  };

  AuthClient.prototype.getAccessToken = function() {
    return this.storage.getItem(this.key('access_token')) || this.storage.getItem('auth_access_token') || '';
  };

  AuthClient.prototype.getRefreshToken = function() {
    return this.storage.getItem(this.key('refresh_token')) || '';
  };

  AuthClient.prototype.setAccessToken = function(token) {
    if (token) {
      this.storage.setItem(this.key('access_token'), token);
      this.storage.setItem('auth_access_token', token);
    } else {
      this.storage.removeItem(this.key('access_token'));
      this.storage.removeItem('auth_access_token');
    }
    return this;
  };

  AuthClient.prototype.setRefreshToken = function(token) {
    if (token) this.storage.setItem(this.key('refresh_token'), token);
    else this.storage.removeItem(this.key('refresh_token'));
    return this;
  };

  AuthClient.prototype.setSession = function(response) {
    response = response || {};
    if (response.access_token) this.setAccessToken(response.access_token);
    if (response.refresh_token) this.setRefreshToken(response.refresh_token);
    return response;
  };

  AuthClient.prototype.clearSession = function() {
    this.setAccessToken('');
    this.setRefreshToken('');
    return this;
  };

  AuthClient.prototype.authHeaders = function(includeAuth, extra) {
    var headers = merge({}, extra);
    if (this.apiKey) headers['X-API-Key'] = this.apiKey;
    if (includeAuth !== false) {
      var token = this.getAccessToken();
      if (token) headers.Authorization = 'Bearer ' + token;
    }
    return headers;
  };

  AuthClient.prototype.url = function(path, query) {
    var url = this.baseUrl + (path.charAt(0) === '/' ? path : '/' + path);
    var encoded = encodeQuery(query);
    return encoded ? url + (url.indexOf('?') === -1 ? '?' : '&') + encoded : url;
  };

  AuthClient.prototype.withSessionMode = function(payload) {
    payload = merge({}, payload);
    if (this.sessionMode === 'token' && !payload.session_mode) payload.session_mode = 'token';
    return payload;
  };

  AuthClient.prototype.request = function(path, options) {
    options = options || {};
    var headers = this.authHeaders(options.auth, options.headers);
    var init = {
      method: options.method || 'GET',
      headers: headers,
      credentials: options.credentials || 'include'
    };
    if (options.body !== undefined) {
      if (isFormBody(options.body) || typeof options.body === 'string') {
        init.body = options.body;
      } else {
        headers['Content-Type'] = headers['Content-Type'] || 'application/json';
        init.body = JSON.stringify(options.body);
      }
    }
    return this.fetch(this.url(path, options.query), init).then(function(res) {
      return res.text().then(function(text) {
        var data = null;
        if (text) {
          try {
            data = JSON.parse(text);
          } catch (err) {
            data = text;
          }
        }
        if (!res.ok) {
          var message = data && (data.error || data.message) ? (data.error || data.message) : res.statusText;
          throw new AuthServiceError(message, res.status, data);
        }
        return data;
      });
    });
  };

  AuthClient.prototype.signup = function(params) {
    var self = this;
    return this.request('/api/auth/signup', { method: 'POST', body: this.withSessionMode(params), auth: false }).then(function(data) {
      return self.setSession(data);
    });
  };

  AuthClient.prototype.login = function(params) {
    var self = this;
    return this.request('/api/auth/login', { method: 'POST', body: this.withSessionMode(params), auth: false }).then(function(data) {
      return self.setSession(data);
    });
  };

  AuthClient.prototype.refresh = function(params) {
    var self = this;
    params = this.withSessionMode(params || {});
    if (this.sessionMode === 'token' && !params.refresh_token) params.refresh_token = this.getRefreshToken();
    return this.request('/api/auth/refresh', { method: 'POST', body: params, auth: false }).then(function(data) {
      return self.setSession(data);
    });
  };

  AuthClient.prototype.logout = function(params) {
    var self = this;
    params = params || {};
    var refreshToken = params.refresh_token || this.getRefreshToken();
    return this.request('/api/auth/logout', { method: 'POST', body: { refresh_token: refreshToken }, auth: false }).then(function(data) {
      self.clearSession();
      return data;
    }, function(err) {
      self.clearSession();
      throw err;
    });
  };

  AuthClient.prototype.me = function() {
    return this.request('/api/auth/me');
  };

  AuthClient.prototype.updateProfile = function(params) {
    return this.request('/api/auth/me', { method: 'PATCH', body: params || {} });
  };

  AuthClient.prototype.changePassword = function(params) {
    return this.request('/api/auth/change-password', { method: 'POST', body: params || {} });
  };

  AuthClient.prototype.listSessions = function() {
    return this.request('/api/auth/sessions');
  };

  AuthClient.prototype.revokeSession = function(sessionID) {
    return this.request('/api/auth/sessions/' + encodeURIComponent(sessionID), { method: 'DELETE' });
  };

  AuthClient.prototype.revokeAllSessions = function() {
    var self = this;
    return this.request('/api/auth/sessions', { method: 'DELETE' }).then(function(data) {
      self.clearSession();
      return data;
    });
  };

  AuthClient.prototype.sendMagicLink = function(emailOrParams) {
    var params = typeof emailOrParams === 'string' ? { email: emailOrParams } : (emailOrParams || {});
    return this.request('/api/auth/magic-link/send', { method: 'POST', body: params, auth: false });
  };

  AuthClient.prototype.verifyMagicLink = function(token) {
    var self = this;
    return this.request('/api/auth/magic-link/verify', {
      method: 'GET',
      query: { token: token, session_mode: this.sessionMode === 'token' ? 'token' : '' },
      headers: { Accept: 'application/json' },
      auth: false
    }).then(function(data) {
      return self.setSession(data);
    });
  };

  AuthClient.prototype.verifyTOTP = function(params) {
    var self = this;
    return this.request('/api/auth/totp/verify', { method: 'POST', body: this.withSessionMode(params), auth: false }).then(function(data) {
      return self.setSession(data);
    });
  };

  AuthClient.prototype.verifyRecoveryCode = function(params) {
    var self = this;
    return this.request('/api/auth/recovery-codes/verify', { method: 'POST', body: this.withSessionMode(params), auth: false }).then(function(data) {
      return self.setSession(data);
    });
  };

  AuthClient.prototype.setupTOTP = function() {
    return this.request('/api/auth/totp/setup', { method: 'POST', body: {} });
  };

  AuthClient.prototype.enableTOTP = function(code) {
    return this.request('/api/auth/totp/enable', { method: 'POST', body: { code: code } });
  };

  AuthClient.prototype.disableTOTP = function(code) {
    return this.request('/api/auth/totp/disable', { method: 'POST', body: { code: code } });
  };

  AuthClient.prototype.generateRecoveryCodes = function() {
    return this.request('/api/auth/recovery-codes', { method: 'POST', body: {} });
  };

  AuthClient.prototype.getRecoveryCodeCount = function() {
    return this.request('/api/auth/recovery-codes');
  };

  AuthClient.prototype.listPasskeys = function() {
    return this.request('/api/auth/passkeys');
  };

  AuthClient.prototype.deletePasskey = function(passkeyID) {
    return this.request('/api/auth/passkeys/' + encodeURIComponent(passkeyID), { method: 'DELETE' });
  };

  AuthClient.prototype.beginPasskeyRegistration = function() {
    return this.request('/api/auth/passkey/register/begin', { method: 'POST', body: {} });
  };

  AuthClient.prototype.finishPasskeyRegistration = function(credential, name) {
    return this.request('/api/auth/passkey/register/finish', {
      method: 'POST',
      query: { name: name || '' },
      body: credentialToJSON(credential)
    });
  };

  AuthClient.prototype.registerPasskey = function(name) {
    var self = this;
    if (!root.navigator || !root.navigator.credentials || !root.PublicKeyCredential) {
      return Promise.reject(new Error('WebAuthn is not available in this browser'));
    }
    return this.beginPasskeyRegistration().then(function(options) {
      return root.navigator.credentials.create({ publicKey: prepareCreationOptions(options) });
    }).then(function(credential) {
      return self.finishPasskeyRegistration(credential, name);
    });
  };

  AuthClient.prototype.beginPasskeyLogin = function() {
    return this.request('/api/auth/passkey/login/begin', { method: 'POST', body: {}, auth: false });
  };

  AuthClient.prototype.finishPasskeyLogin = function(sessionID, credential) {
    var self = this;
    return this.request('/api/auth/passkey/login/finish', {
      method: 'POST',
      query: { session_id: sessionID, session_mode: this.sessionMode === 'token' ? 'token' : '' },
      body: credentialToJSON(credential),
      auth: false
    }).then(function(data) {
      return self.setSession(data);
    });
  };

  AuthClient.prototype.isConditionalPasskeyAvailable = function() {
    if (!root.PublicKeyCredential || !root.PublicKeyCredential.isConditionalMediationAvailable) {
      return Promise.resolve(false);
    }
    return root.PublicKeyCredential.isConditionalMediationAvailable();
  };

  AuthClient.prototype.loginWithPasskey = function(options) {
    var self = this;
    var credentialOptions = options || {};
    if (!root.navigator || !root.navigator.credentials || !root.PublicKeyCredential) {
      return Promise.reject(new Error('WebAuthn is not available in this browser'));
    }
    return this.beginPasskeyLogin().then(function(beginOptions) {
      var credentialRequest = { publicKey: prepareRequestOptions(beginOptions) };
      if (credentialOptions.mediation) credentialRequest.mediation = credentialOptions.mediation;
      if (credentialOptions.signal) credentialRequest.signal = credentialOptions.signal;
      return root.navigator.credentials.get(credentialRequest).then(function(credential) {
        return self.finishPasskeyLogin(beginOptions.session_id, credential);
      });
    });
  };

  AuthClient.prototype.startConditionalPasskeyLogin = function(options) {
    var self = this;
    options = options || {};
    return this.isConditionalPasskeyAvailable().then(function(available) {
      if (!available) return null;
      return self.loginWithPasskey({ mediation: 'conditional', signal: options.signal || null });
    });
  };

  AuthClient.prototype.listOrganizations = function() {
    return this.request('/api/auth/organizations');
  };

  AuthClient.prototype.createOrganization = function(params) {
    return this.request('/api/auth/organizations', { method: 'POST', body: params || {} });
  };

  AuthClient.prototype.getOrganization = function(organizationID) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID));
  };

  AuthClient.prototype.updateOrganization = function(organizationID, params) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID), { method: 'PATCH', body: params || {} });
  };

  AuthClient.prototype.listOrganizationMembers = function(organizationID) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/members');
  };

  AuthClient.prototype.updateOrganizationMember = function(organizationID, userID, params) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/members/' + encodeURIComponent(userID), { method: 'PATCH', body: params || {} });
  };

  AuthClient.prototype.removeOrganizationMember = function(organizationID, userID) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/members/' + encodeURIComponent(userID), { method: 'DELETE' });
  };

  AuthClient.prototype.listOrganizationInvitations = function(organizationID) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/invitations');
  };

  AuthClient.prototype.inviteOrganizationMember = function(organizationID, params) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/invitations', { method: 'POST', body: params || {} });
  };

  AuthClient.prototype.revokeOrganizationInvitation = function(organizationID, invitationID) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/invitations/' + encodeURIComponent(invitationID) + '/revoke', { method: 'POST', body: {} });
  };

  AuthClient.prototype.acceptOrganizationInvitation = function(token) {
    return this.request('/api/auth/organization-invitations/accept', { method: 'POST', body: { token: token } });
  };

  AuthClient.prototype.createOrganizationToken = function(organizationID, options) {
    var self = this;
    options = options || {};
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/token', { method: 'POST', body: {} }).then(function(data) {
      if (options.activate && data && data.access_token) self.setAccessToken(data.access_token);
      return data;
    });
  };

  AuthClient.prototype.beginRedirect = function(path) {
    var url = this.url(path);
    var headers = this.authHeaders(false, {});
    var self = this;
    return this.fetch(url, { method: 'GET', headers: headers, credentials: 'include', redirect: 'manual' }).then(function(res) {
      var location = res.headers && res.headers.get('Location');
      if (location) {
        root.location.assign(location);
        return location;
      }
      if (res.redirected && res.url) {
        root.location.assign(res.url);
        return res.url;
      }
      if (res.status >= 200 && res.status < 300) return self.url(path);
      throw new AuthServiceError(res.statusText || 'Redirect could not be started', res.status);
    });
  };

  AuthClient.prototype.startOAuth = function(provider) {
    return this.beginRedirect('/api/auth/oauth/' + encodeURIComponent(provider));
  };

  AuthClient.prototype.startSSO = function(params) {
    params = params || {};
    if (params.connection) return this.beginRedirect('/api/auth/sso/' + encodeURIComponent(params.connection));
    return this.beginRedirect('/api/auth/sso?' + encodeQuery({ domain: params.domain || '' }));
  };

  AuthClient.prototype.mountSignIn = function(container, options) {
    ensureWidgetStyles();
    container = resolveContainer(container);
    options = options || {};
    var client = this;
    var twoFactorToken = '';
    container.innerHTML = [
      '<div class="as-card"><form class="as-stack" data-as-login>',
      '<div class="as-message" data-as-message></div>',
      '<div class="as-field"><label>Email</label><input class="as-input" data-as-email type="email" autocomplete="email" required></div>',
      '<div class="as-field"><label>Password</label><input class="as-input" data-as-password type="password" autocomplete="current-password" required></div>',
      '<div class="as-field" data-as-totp-wrap style="display:none"><label>Authenticator code</label><input class="as-input" data-as-totp inputmode="numeric" autocomplete="one-time-code"></div>',
      '<button class="as-button" data-as-submit type="submit">Sign in</button>',
      '<button class="as-button secondary" data-as-passkey type="button">Sign in with passkey</button>',
      '</form></div>'
    ].join('');

    var form = container.querySelector('[data-as-login]');
    var message = container.querySelector('[data-as-message]');
    var submit = container.querySelector('[data-as-submit]');
    var passkey = container.querySelector('[data-as-passkey]');
    var totpWrap = container.querySelector('[data-as-totp-wrap]');

    function setMessage(text, type) {
      message.textContent = text || '';
      message.className = text ? 'as-message show ' + (type || 'ok') : 'as-message';
    }

    function setLoading(loading) {
      submit.disabled = loading;
      passkey.disabled = loading;
    }

    function complete(data) {
      setMessage('Signed in.', 'ok');
      if (options.onSuccess) options.onSuccess(data);
      return data;
    }

    form.addEventListener('submit', function(event) {
      event.preventDefault();
      setMessage('');
      setLoading(true);
      var work;
      if (twoFactorToken) {
        work = client.verifyTOTP({
          two_factor_token: twoFactorToken,
          code: container.querySelector('[data-as-totp]').value
        });
      } else {
        work = client.login({
          email: container.querySelector('[data-as-email]').value,
          password: container.querySelector('[data-as-password]').value
        });
      }
      work.then(function(data) {
        if (data && data.requires_2fa) {
          twoFactorToken = data.two_factor_token;
          totpWrap.style.display = 'grid';
          setMessage('Enter your authenticator code.', 'ok');
          return data;
        }
        return complete(data);
      }).catch(function(err) {
        setMessage(err.message || 'Sign in failed', 'error');
        if (options.onError) options.onError(err);
      }).then(function() {
        setLoading(false);
      });
    });

    passkey.addEventListener('click', function() {
      setMessage('');
      setLoading(true);
      client.loginWithPasskey().then(complete).catch(function(err) {
        setMessage(err.message || 'Passkey sign in failed', 'error');
        if (options.onError) options.onError(err);
      }).then(function() {
        setLoading(false);
      });
    });

    return {
      destroy: function() { container.innerHTML = ''; }
    };
  };

  AuthClient.prototype.mountUserButton = function(container, options) {
    ensureWidgetStyles();
    container = resolveContainer(container);
    options = options || {};
    var client = this;

    function renderSignedOut() {
      container.innerHTML = '<div class="as-user"><div><div class="as-user-name">Signed out</div><div class="as-user-email">No active session</div></div></div>';
    }

    function renderUser(user) {
      container.innerHTML = '<div class="as-user"><div><div class="as-user-name" data-as-name></div><div class="as-user-email" data-as-email></div></div><button class="as-button secondary" data-as-signout type="button">Sign out</button></div>';
      container.querySelector('[data-as-name]').textContent = user.display_name || user.email || 'Account';
      container.querySelector('[data-as-email]').textContent = user.email || user.id || '';
      container.querySelector('[data-as-signout]').addEventListener('click', function() {
        client.logout().catch(function() {}).then(function() {
          renderSignedOut();
          if (options.onSignOut) options.onSignOut();
        });
      });
    }

    function refresh() {
      if (!client.getAccessToken()) {
        renderSignedOut();
        return Promise.resolve(null);
      }
      return client.me().then(function(user) {
        renderUser(user);
        return user;
      }).catch(function(err) {
        renderSignedOut();
        if (options.onError) options.onError(err);
        return null;
      });
    }

    renderSignedOut();
    return {
      refresh: refresh,
      destroy: function() { container.innerHTML = ''; }
    };
  };

  function createClient(options) {
    return new AuthClient(options);
  }

  return {
    version: VERSION,
    AuthClient: AuthClient,
    AuthServiceError: AuthServiceError,
    createClient: createClient,
    mountSignIn: function(container, options) {
      var client = createClient(options || {});
      return client.mountSignIn(container, options || {});
    },
    mountUserButton: function(container, options) {
      var client = createClient(options || {});
      return client.mountUserButton(container, options || {});
    },
    webauthn: {
      b64urlToBuffer: b64urlToBuffer,
      bufferToB64url: bufferToB64url,
      prepareCreationOptions: prepareCreationOptions,
      prepareRequestOptions: prepareRequestOptions,
      credentialToJSON: credentialToJSON
    }
  };
});
