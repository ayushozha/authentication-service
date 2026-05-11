(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(root);
  } else {
    root.AuthService = factory(root);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function(root) {
  'use strict';

  var VERSION = '0.1.1';
  var DEFAULT_PREFIX = 'authservice_';
  var INVALID_LOGIN_CREDENTIALS_MESSAGE = 'Invalid email or password.';
  var AUTH_ERROR_CODES = [
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
  var ERROR_DEFINITIONS = {
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
  var LEGACY_CODE_MAP = {
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
    return typeof value === 'string' && AUTH_ERROR_CODES.indexOf(value) !== -1;
  }

  function normalizeLegacyErrorCode(value) {
    value = String(value || '').trim().toLowerCase();
    value = value.replace(/[\s-]+/g, '_');
    while (value.indexOf('__') !== -1) value = value.replace(/__+/g, '_');
    return value;
  }

  function authCodeFromStatusAndMessage(status, message) {
    var lower = String(message || '').toLowerCase();
    if (lower.indexOf('invalid email or password') !== -1) return 'AUTH_INVALID_CREDENTIALS';
    if (lower.indexOf('invalid email') !== -1) return 'AUTH_INVALID_EMAIL';
    if (lower.indexOf('password') !== -1 && lower.indexOf('required') !== -1) return 'AUTH_PASSWORD_REQUIRED';
    if (lower.indexOf('at least 8') !== -1 || lower.indexOf('password does not meet') !== -1) return 'AUTH_PASSWORD_TOO_SHORT';
    if (lower.indexOf('too many') !== -1 || lower.indexOf('rate') !== -1) return 'AUTH_RATE_LIMITED';
    if (lower.indexOf('redis') !== -1 || lower.indexOf('not configured') !== -1) return 'AUTH_SERVICE_UNAVAILABLE';
    if (lower.indexOf('passkey') !== -1 || lower.indexOf('webauthn') !== -1) return 'AUTH_PASSKEY_FAILED';
    if (lower.indexOf('totp') !== -1 || lower.indexOf('2fa') !== -1 || lower.indexOf('mfa') !== -1) return 'AUTH_MFA_REQUIRED';
    if (status === 429) return 'AUTH_RATE_LIMITED';
    if (status === 401) return 'AUTH_SESSION_EXPIRED';
    if (status >= 500) return 'AUTH_SERVICE_UNAVAILABLE';
    return 'AUTH_UNKNOWN';
  }

  function normalizeAuthServiceError(status, response, fallbackMessage) {
    var payload = response && typeof response === 'object' ? response : {};
    var providerCode = String(payload.code || payload.error || '').trim();
    var code = 'AUTH_UNKNOWN';
    if (isAuthErrorCode(payload.auth_code) || isAuthErrorCode(payload.authCode)) {
      code = payload.auth_code || payload.authCode;
    } else {
      var legacyCode = normalizeLegacyErrorCode(providerCode);
      code = LEGACY_CODE_MAP[legacyCode] || authCodeFromStatusAndMessage(status, errorPayloadMessage(response) || fallbackMessage);
    }
    var definition = ERROR_DEFINITIONS[code] || ERROR_DEFINITIONS.AUTH_UNKNOWN;
    var userMessage = String(payload.userMessage || payload.user_message || definition.userMessage).trim();
    return {
      code: code,
      userMessage: userMessage || definition.userMessage,
      retryable: typeof payload.retryable === 'boolean' ? payload.retryable : definition.retryable,
      providerCode: providerCode || undefined
    };
  }

  function normalizeLoginError(err) {
    var serverMessage = errorPayloadMessage(err && err.response).toLowerCase();
    if (err && err.status === 401 && serverMessage === 'invalid email or password') {
      return new AuthServiceError(INVALID_LOGIN_CREDENTIALS_MESSAGE, err.status, err.response);
    }
    return err;
  }

  function AuthServiceError(message, status, response, normalized) {
    var error = normalized || normalizeAuthServiceError(status || 0, response, message);
    this.name = 'AuthServiceError';
    this.message = error.userMessage || message || 'AuthService request failed';
    this.status = status || 0;
    this.response = response || null;
    this.code = error.code;
    this.userMessage = error.userMessage;
    this.retryable = error.retryable;
    this.providerCode = error.providerCode;
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

  function randomB64url(byteLength) {
    var bytes = new Uint8Array(byteLength || 32);
    if (root.crypto && root.crypto.getRandomValues) {
      root.crypto.getRandomValues(bytes);
    } else {
      for (var i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
    }
    return bufferToB64url(bytes.buffer);
  }

  function sha256B64url(value) {
    if (!root.crypto || !root.crypto.subtle || !root.TextEncoder) {
      return Promise.resolve(value);
    }
    return root.crypto.subtle.digest('SHA-256', new root.TextEncoder().encode(value)).then(bufferToB64url);
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

  function decodeJWT(token) {
    try {
      token = String(token || '');
      var parts = token.split('.');
      if (parts.length < 2) return null;
      var payload = parts[1];
      var pad = '='.repeat((4 - payload.length % 4) % 4);
      var base64 = (payload + pad).replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(root.atob(base64));
    } catch (err) {
      return null;
    }
  }

  function arrayContains(values, value) {
    if (!values || !value) return false;
    for (var i = 0; i < values.length; i++) {
      if (values[i] === value) return true;
    }
    return false;
  }

  function permissionFor(resource, action) {
    resource = String(resource || '').trim().toLowerCase();
    action = String(action || '').trim().toLowerCase();
    return resource && action ? resource + ':' + action : '';
  }

  function listFromText(value) {
    if (Array.isArray(value)) return value;
    return String(value || '').split(/[,\n]/).map(function(item) {
      return item.trim();
    }).filter(Boolean);
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
      '.as-card.wide{max-width:760px}',
      '.as-stack{display:grid;gap:10px}',
      '.as-grid{display:grid;gap:10px}.as-grid.two{grid-template-columns:repeat(2,minmax(0,1fr))}',
      '.as-field{display:grid;gap:4px}',
      '.as-field label{font-size:12px;font-weight:700;color:#536276}',
      '.as-input{width:100%;min-height:38px;border:1px solid #cfd7e3;border-radius:8px;padding:8px 10px;font:inherit}',
      '.as-button{min-height:38px;border:0;border-radius:8px;background:#146b65;color:#fff;font-weight:700;cursor:pointer;padding:8px 12px}',
      '.as-button.secondary{background:#eef3f7;color:#172033;border:1px solid #cfd7e3}',
      '.as-button.danger{background:#fff1f2;color:#be123c;border:1px solid #fecdd3}',
      '.as-button:disabled{opacity:.6;cursor:not-allowed}',
      '.as-message{display:none;border-radius:8px;padding:9px 10px;font-size:13px}',
      '.as-message.show{display:block}',
      '.as-message.error{background:#fff1f2;color:#be123c;border:1px solid #fecdd3}',
      '.as-message.ok{background:#ecfdf5;color:#047857;border:1px solid #a7f3d0}',
      '.as-user{display:flex;align-items:center;justify-content:space-between;gap:12px;border:1px solid #d8dee8;border-radius:8px;background:#fff;padding:12px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}',
      '.as-user-name{font-weight:800;color:#172033}',
      '.as-user-email{font-size:12px;color:#536276;word-break:break-word}',
      '.as-row{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 0;border-top:1px solid #edf1f5}',
      '.as-row:first-child{border-top:0}',
      '.as-row-main{min-width:0}.as-row-title{font-weight:750;color:#172033}.as-row-meta{font-size:12px;color:#667789;word-break:break-word}',
      '.as-tabs{display:flex;gap:6px;flex-wrap:wrap}.as-tabs .as-button{min-height:32px;padding:6px 9px;font-size:12px}',
      '.as-chip{display:inline-flex;align-items:center;min-height:24px;border-radius:999px;background:#eff6ff;color:#1d4ed8;padding:3px 8px;font-size:12px;font-weight:700}',
      '.as-table{width:100%;border-collapse:collapse;font-size:13px}.as-table th,.as-table td{padding:8px;border-top:1px solid #edf1f5;text-align:left;vertical-align:top}.as-table th{font-size:11px;color:#667789;text-transform:uppercase;letter-spacing:0}',
      '.as-muted{color:#667789;font-size:12px}.as-code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;background:#f6f8fa;border:1px solid #d8dee8;border-radius:8px;padding:8px;overflow:auto}',
      '@media(max-width:640px){.as-grid.two{grid-template-columns:1fr}.as-row{align-items:flex-start;flex-direction:column}.as-card.wide{max-width:none}}'
    ].join('');
    root.document.head.appendChild(style);
  }

  function AuthClient(options) {
    options = options || {};
    this.baseUrl = trimRightSlash(options.baseUrl || (root.location && root.location.origin) || '');
    this.apiKey = options.apiKey || options.publishableKey || options.clientKey || '';
    this.clientId = options.clientId || options.oidcClientId || '';
    this.adminKey = options.adminKey || '';
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

  AuthClient.prototype.getAccessClaims = function(token) {
    return decodeJWT(token || this.getAccessToken());
  };

  AuthClient.prototype.hasScope = function(scope, claims) {
    claims = claims || this.getAccessClaims() || {};
    var scopes = claims.scopes || String(claims.scope || '').split(/\s+/);
    return arrayContains(scopes, scope);
  };

  AuthClient.prototype.hasOrganizationPermission = function(permission, claims) {
    claims = claims || this.getAccessClaims() || {};
    if (claims.org_role === 'owner') return true;
    return arrayContains(claims.org_permissions || [], permission);
  };

  AuthClient.prototype.isAuthorized = function(resource, action, claims) {
    return this.hasOrganizationPermission(permissionFor(resource, action), claims);
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
    if (this.sessionMode === 'token') {
      if (!payload.session_mode) payload.session_mode = 'token';
      if (!payload.token_transport) payload.token_transport = 'json';
    }
    return payload;
  };

  AuthClient.prototype.request = function(path, options) {
    options = options || {};
    var headers = options.admin ? merge({}, options.headers) : this.authHeaders(options.auth, options.headers);
    if (options.admin && this.adminKey) headers['X-Admin-Key'] = this.adminKey;
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
          var normalized = normalizeAuthServiceError(res.status, data, message);
          throw new AuthServiceError(normalized.userMessage, res.status, data, normalized);
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
    }).catch(function(err) {
      throw normalizeLoginError(err);
    });
  };

  AuthClient.prototype.exchangeRedirectCode = function(code) {
    var self = this;
    return this.request('/api/auth/redirect/exchange', {
      method: 'POST',
      body: { code: code },
      auth: false
    }).then(function(data) {
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

  AuthClient.prototype.getUIConfig = function() {
    return this.request('/api/auth/ui/config', { auth: false });
  };

  AuthClient.prototype.forgotPassword = function(emailOrParams) {
    var params = typeof emailOrParams === 'string' ? { email: emailOrParams } : (emailOrParams || {});
    return this.request('/api/auth/forgot-password', { method: 'POST', body: params, auth: false });
  };

  AuthClient.prototype.resetPassword = function(params) {
    params = merge({}, params || {});
    if (params.password && !params.new_password) params.new_password = params.password;
    delete params.password;
    return this.request('/api/auth/reset-password', { method: 'POST', body: params || {}, auth: false });
  };

  AuthClient.prototype.verifyEmail = function(tokenOrParams) {
    var params = typeof tokenOrParams === 'string' ? { token: tokenOrParams } : (tokenOrParams || {});
    return this.request('/api/auth/verify-email', { method: 'POST', body: params, auth: false });
  };

  AuthClient.prototype.resendVerification = function() {
    return this.request('/api/auth/resend-verification', { method: 'POST', body: {} });
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
      query: {
        session_id: sessionID,
        session_mode: this.sessionMode === 'token' ? 'token' : '',
        token_transport: this.sessionMode === 'token' ? 'json' : 'cookie'
      },
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

  AuthClient.prototype.getAuthorizationPolicy = function(organizationID) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/authorization/policy');
  };

  AuthClient.prototype.updateAuthorizationPolicy = function(organizationID, params) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/authorization/policy', { method: 'PUT', body: params || {} });
  };

  AuthClient.prototype.listAuthorizationGroupMappings = function(organizationID) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/authorization/group-mappings');
  };

  AuthClient.prototype.upsertAuthorizationGroupMapping = function(organizationID, mappingID, params) {
    var suffix = mappingID ? '/' + encodeURIComponent(mappingID) : '';
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/authorization/group-mappings' + suffix, {
      method: mappingID ? 'PATCH' : 'POST',
      body: params || {}
    });
  };

  AuthClient.prototype.deleteAuthorizationGroupMapping = function(organizationID, mappingID) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/authorization/group-mappings/' + encodeURIComponent(mappingID), { method: 'DELETE' });
  };

  AuthClient.prototype.simulateAuthorization = function(organizationID, params) {
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/authorization/simulate', { method: 'POST', body: params || {} });
  };

  AuthClient.prototype.createOrganizationToken = function(organizationID, options) {
    var self = this;
    options = options || {};
    return this.request('/api/auth/organizations/' + encodeURIComponent(organizationID) + '/token', { method: 'POST', body: {} }).then(function(data) {
      if (options.activate && data && data.access_token) self.setAccessToken(data.access_token);
      return data;
    });
  };

  AuthClient.prototype.createOIDCAuthorizationURL = function(options) {
    options = options || {};
    var clientId = options.clientId || options.client_id || this.clientId;
    var redirectUri = options.redirectUri || options.redirect_uri || (root.location && root.location.href.split('#')[0].split('?')[0]) || '';
    var verifier = options.codeVerifier || options.code_verifier || randomB64url(64);
    var state = options.state || randomB64url(24);
    var nonce = options.nonce || randomB64url(24);
    var method = options.codeChallengeMethod || options.code_challenge_method || 'S256';
    var self = this;
    return (method === 'plain' ? Promise.resolve(verifier) : sha256B64url(verifier)).then(function(challenge) {
      if (options.store !== false) {
        self.storage.setItem(self.key('oidc_state'), state);
        self.storage.setItem(self.key('oidc_nonce'), nonce);
        self.storage.setItem(self.key('oidc_code_verifier'), verifier);
        self.storage.setItem(self.key('oidc_redirect_uri'), redirectUri);
        self.storage.setItem(self.key('oidc_client_id'), clientId);
      }
      return {
        url: self.url('/authorize', {
          client_id: clientId,
          redirect_uri: redirectUri,
          response_type: options.responseType || options.response_type || 'code',
          scope: options.scope || 'openid profile email',
          state: state,
          nonce: nonce,
          code_challenge: challenge,
          code_challenge_method: method,
          audience: options.audience || '',
          resource: options.resource || '',
          prompt: options.prompt || ''
        }),
        state: state,
        nonce: nonce,
        codeVerifier: verifier,
        codeChallenge: challenge,
        redirectUri: redirectUri,
        clientId: clientId
      };
    });
  };

  AuthClient.prototype.startOIDC = function(options) {
    return this.createOIDCAuthorizationURL(options || {}).then(function(auth) {
      root.location.assign(auth.url);
      return auth;
    });
  };

  AuthClient.prototype.exchangeOIDCCode = function(params) {
    var self = this;
    params = params || {};
    var body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('client_id', params.clientId || params.client_id || this.clientId || this.storage.getItem(this.key('oidc_client_id')) || '');
    body.set('code', params.code || '');
    body.set('redirect_uri', params.redirectUri || params.redirect_uri || this.storage.getItem(this.key('oidc_redirect_uri')) || '');
    body.set('code_verifier', params.codeVerifier || params.code_verifier || this.storage.getItem(this.key('oidc_code_verifier')) || '');
    if (params.clientSecret || params.client_secret) body.set('client_secret', params.clientSecret || params.client_secret);
    return this.request('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      auth: false
    }).then(function(data) {
      self.storage.removeItem(self.key('oidc_state'));
      self.storage.removeItem(self.key('oidc_nonce'));
      self.storage.removeItem(self.key('oidc_code_verifier'));
      return self.setSession(data);
    });
  };

  AuthClient.prototype.handleOIDCCallback = function(options) {
    options = options || {};
    var params = new URLSearchParams(options.search || (root.location && root.location.search) || '');
    if (params.get('error')) {
      return Promise.reject(new AuthServiceError(params.get('error_description') || params.get('error'), 400, { error: params.get('error') }));
    }
    var expectedState = options.state || this.storage.getItem(this.key('oidc_state')) || '';
    if (expectedState && params.get('state') !== expectedState) {
      return Promise.reject(new AuthServiceError('OIDC state mismatch', 400));
    }
    return this.exchangeOIDCCode(merge({}, options, { code: params.get('code') || '' }));
  };

  AuthClient.prototype.oidcUserInfo = function(accessToken) {
    return this.request('/userinfo', {
      method: 'GET',
      headers: { Authorization: 'Bearer ' + (accessToken || this.getAccessToken()) },
      auth: false
    });
  };

  AuthClient.prototype.adminRequest = function(path, options) {
    options = options || {};
    options.admin = true;
    options.auth = false;
    return this.request(path, options);
  };

  AuthClient.prototype.listClients = function() {
    return this.adminRequest('/api/admin/clients');
  };

  AuthClient.prototype.getClient = function(clientID) {
    return this.adminRequest('/api/admin/clients/' + encodeURIComponent(clientID));
  };

  AuthClient.prototype.updateClient = function(clientID, params) {
    return this.adminRequest('/api/admin/clients/' + encodeURIComponent(clientID), { method: 'PATCH', body: params || {} });
  };

  AuthClient.prototype.listSSOConnections = function(clientID) {
    return this.adminRequest('/api/admin/clients/' + encodeURIComponent(clientID) + '/sso-connections');
  };

  AuthClient.prototype.createSSOConnection = function(clientID, params) {
    return this.adminRequest('/api/admin/clients/' + encodeURIComponent(clientID) + '/sso-connections', { method: 'POST', body: params || {} });
  };

  AuthClient.prototype.updateSSOConnection = function(clientID, connectionID, params) {
    return this.adminRequest('/api/admin/clients/' + encodeURIComponent(clientID) + '/sso-connections/' + encodeURIComponent(connectionID), { method: 'PATCH', body: params || {} });
  };

  AuthClient.prototype.deleteSSOConnection = function(clientID, connectionID) {
    return this.adminRequest('/api/admin/clients/' + encodeURIComponent(clientID) + '/sso-connections/' + encodeURIComponent(connectionID), { method: 'DELETE' });
  };

  AuthClient.prototype.listSCIMDirectories = function(clientID) {
    return this.adminRequest('/api/admin/clients/' + encodeURIComponent(clientID) + '/scim-directories');
  };

  AuthClient.prototype.createSCIMDirectory = function(clientID, params) {
    return this.adminRequest('/api/admin/clients/' + encodeURIComponent(clientID) + '/scim-directories', { method: 'POST', body: params || {} });
  };

  AuthClient.prototype.updateSCIMDirectory = function(clientID, directoryID, params) {
    return this.adminRequest('/api/admin/clients/' + encodeURIComponent(clientID) + '/scim-directories/' + encodeURIComponent(directoryID), { method: 'PATCH', body: params || {} });
  };

  AuthClient.prototype.rotateSCIMDirectoryToken = function(clientID, directoryID) {
    return this.adminRequest('/api/admin/clients/' + encodeURIComponent(clientID) + '/scim-directories/' + encodeURIComponent(directoryID) + '/rotate-token', { method: 'POST', body: {} });
  };

  AuthClient.prototype.listAuditEvents = function(params) {
    return this.adminRequest('/api/admin/audit-events', { query: params || {} });
  };

  AuthClient.prototype.auditExportURL = function(params) {
    return this.url('/api/admin/audit-events/export', params || {});
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
    var query = this.sessionMode === 'token' ? '?session_mode=token' : '';
    return this.beginRedirect('/api/auth/oauth/' + encodeURIComponent(provider) + query);
  };

  AuthClient.prototype.startSSO = function(params) {
    params = params || {};
    var query = { session_mode: this.sessionMode === 'token' ? 'token' : '' };
    if (params.connection) return this.beginRedirect('/api/auth/sso/' + encodeURIComponent(params.connection) + '?' + encodeQuery(query));
    query.domain = params.domain || '';
    return this.beginRedirect('/api/auth/sso?' + encodeQuery(query));
  };

  function widgetValue(container, selector) {
    var el = container.querySelector(selector);
    return el ? el.value : '';
  }

  function widgetMessage(container, text, type) {
    var message = container.querySelector('[data-as-message]');
    if (!message) return;
    message.textContent = text || '';
    message.className = text ? 'as-message show ' + (type || 'ok') : 'as-message';
  }

  function widgetSetLoading(container, loading) {
    var controls = container.querySelectorAll('button, input, select, textarea');
    for (var i = 0; i < controls.length; i++) controls[i].disabled = !!loading;
  }

  function formatDate(value) {
    if (!value) return '';
    try {
      return new Date(value).toLocaleString();
    } catch (err) {
      return String(value);
    }
  }

  function normalizeArrayPayload(data, key) {
    if (!data) return [];
    if (Array.isArray(data)) return data;
    if (Array.isArray(data[key])) return data[key];
    return [];
  }

  function createRow(title, meta, actionLabel, actionClass) {
    var row = root.document.createElement('div');
    row.className = 'as-row';
    var main = root.document.createElement('div');
    main.className = 'as-row-main';
    var rowTitle = root.document.createElement('div');
    rowTitle.className = 'as-row-title';
    rowTitle.textContent = title || '';
    var rowMeta = root.document.createElement('div');
    rowMeta.className = 'as-row-meta';
    rowMeta.textContent = meta || '';
    main.appendChild(rowTitle);
    main.appendChild(rowMeta);
    row.appendChild(main);
    if (actionLabel) {
      var button = root.document.createElement('button');
      button.type = 'button';
      button.className = 'as-button ' + (actionClass || 'secondary');
      button.textContent = actionLabel;
      row.appendChild(button);
    }
    return row;
  }

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

  AuthClient.prototype.mountSignUp = function(container, options) {
    ensureWidgetStyles();
    container = resolveContainer(container);
    options = options || {};
    var client = this;
    container.innerHTML = [
      '<div class="as-card"><form class="as-stack" data-as-signup>',
      '<div class="as-message" data-as-message></div>',
      '<div class="as-field"><label>Full name</label><input class="as-input" data-as-name type="text" autocomplete="name" required></div>',
      '<div class="as-field"><label>Email</label><input class="as-input" data-as-email type="email" autocomplete="email" required></div>',
      '<div class="as-field"><label>Password</label><input class="as-input" data-as-password type="password" autocomplete="new-password" required minlength="8"></div>',
      '<button class="as-button" data-as-submit type="submit">Create account</button>',
      '<button class="as-button secondary" data-as-passkey type="button" style="display:none">Add a passkey</button>',
      '</form></div>'
    ].join('');
    var form = container.querySelector('[data-as-signup]');
    var passkey = container.querySelector('[data-as-passkey]');

    form.addEventListener('submit', function(event) {
      event.preventDefault();
      widgetMessage(container, '');
      widgetSetLoading(container, true);
      client.signup({
        display_name: widgetValue(container, '[data-as-name]'),
        email: widgetValue(container, '[data-as-email]'),
        password: widgetValue(container, '[data-as-password]')
      }).then(function(data) {
        widgetMessage(container, 'Account created.', 'ok');
        if (root.PublicKeyCredential) passkey.style.display = 'block';
        if (options.onSuccess) options.onSuccess(data);
      }).catch(function(err) {
        widgetMessage(container, err.message || 'Signup failed', 'error');
        if (options.onError) options.onError(err);
      }).then(function() {
        widgetSetLoading(container, false);
      });
    });

    passkey.addEventListener('click', function() {
      widgetMessage(container, '');
      widgetSetLoading(container, true);
      client.registerPasskey(options.passkeyName || 'Primary passkey').then(function(data) {
        widgetMessage(container, 'Passkey added.', 'ok');
        if (options.onPasskeyAdded) options.onPasskeyAdded(data);
      }).catch(function(err) {
        widgetMessage(container, err.message || 'Could not add passkey', 'error');
      }).then(function() {
        widgetSetLoading(container, false);
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

  AuthClient.prototype.mountUserProfile = function(container, options) {
    ensureWidgetStyles();
    container = resolveContainer(container);
    options = options || {};
    var client = this;
    var state = { tab: 'profile', user: null, sessions: [], passkeys: [], recovery: null, totp: null, codes: [] };

    function load() {
      return client.me().then(function(user) {
        state.user = user;
        return Promise.all([
          client.listSessions().then(function(data) { state.sessions = normalizeArrayPayload(data, 'sessions'); }).catch(function() { state.sessions = []; }),
          client.listPasskeys().then(function(data) { state.passkeys = normalizeArrayPayload(data, 'passkeys'); }).catch(function() { state.passkeys = normalizeArrayPayload(data, 'credentials'); }),
          client.getRecoveryCodeCount().then(function(data) { state.recovery = data; }).catch(function() { state.recovery = null; })
        ]);
      }).then(render).catch(function(err) {
        container.innerHTML = '<div class="as-card wide"><div class="as-message show error">Sign in is required to manage this profile.</div></div>';
        if (options.onError) options.onError(err);
      });
    }

    function tabs() {
      return [
        '<div class="as-tabs">',
        '<button class="as-button ' + (state.tab === 'profile' ? '' : 'secondary') + '" data-as-tab="profile" type="button">Profile</button>',
        '<button class="as-button ' + (state.tab === 'security' ? '' : 'secondary') + '" data-as-tab="security" type="button">Security</button>',
        '<button class="as-button ' + (state.tab === 'sessions' ? '' : 'secondary') + '" data-as-tab="sessions" type="button">Sessions</button>',
        '<button class="as-button ' + (state.tab === 'passkeys' ? '' : 'secondary') + '" data-as-tab="passkeys" type="button">Passkeys</button>',
        '</div>'
      ].join('');
    }

    function render() {
      var user = state.user || {};
      container.innerHTML = [
        '<div class="as-card wide as-stack">',
        '<div><div class="as-user-name"></div><div class="as-user-email"></div></div>',
        tabs(),
        '<div class="as-message" data-as-message></div>',
        '<div data-as-panel></div>',
        '</div>'
      ].join('');
      container.querySelector('.as-user-name').textContent = user.display_name || user.email || 'Account';
      container.querySelector('.as-user-email').textContent = user.email || user.id || '';
      var tabButtons = container.querySelectorAll('[data-as-tab]');
      for (var i = 0; i < tabButtons.length; i++) {
        tabButtons[i].addEventListener('click', function(event) {
          state.tab = event.currentTarget.getAttribute('data-as-tab');
          render();
        });
      }
      if (state.tab === 'profile') renderProfile();
      if (state.tab === 'security') renderSecurity();
      if (state.tab === 'sessions') renderSessions();
      if (state.tab === 'passkeys') renderPasskeys();
    }

    function renderProfile() {
      var user = state.user || {};
      container.querySelector('[data-as-panel]').innerHTML = [
        '<form class="as-stack" data-as-profile>',
        '<div class="as-grid two">',
        '<div class="as-field"><label>Display name</label><input class="as-input" data-as-display-name type="text" autocomplete="name"></div>',
        '<div class="as-field"><label>Timezone</label><input class="as-input" data-as-timezone type="text" placeholder="America/Los_Angeles"></div>',
        '</div>',
        '<button class="as-button" type="submit">Save profile</button>',
        '</form>'
      ].join('');
      container.querySelector('[data-as-display-name]').value = user.display_name || '';
      container.querySelector('[data-as-timezone]').value = user.timezone || '';
      container.querySelector('[data-as-profile]').addEventListener('submit', function(event) {
        event.preventDefault();
        widgetSetLoading(container, true);
        client.updateProfile({
          display_name: widgetValue(container, '[data-as-display-name]'),
          timezone: widgetValue(container, '[data-as-timezone]')
        }).then(function(nextUser) {
          state.user = nextUser;
          widgetMessage(container, 'Profile saved.', 'ok');
        }).catch(function(err) {
          widgetMessage(container, err.message || 'Could not save profile', 'error');
        }).then(function() {
          widgetSetLoading(container, false);
        });
      });
    }

    function renderSecurity() {
      var unused = state.recovery && typeof state.recovery.unused_count === 'number' ? state.recovery.unused_count : 0;
      container.querySelector('[data-as-panel]').innerHTML = [
        '<div class="as-stack">',
        '<div class="as-row"><div class="as-row-main"><div class="as-row-title">Authenticator app</div><div class="as-row-meta">Enroll TOTP MFA and keep recovery codes ready.</div></div><button class="as-button secondary" data-as-setup-totp type="button">Set up</button></div>',
        '<div data-as-totp-setup></div>',
        '<div class="as-row"><div class="as-row-main"><div class="as-row-title">Recovery codes</div><div class="as-row-meta">' + unused + ' unused codes</div></div><button class="as-button secondary" data-as-rotate-codes type="button">Rotate</button></div>',
        '<div data-as-codes></div>',
        '<form class="as-stack" data-as-password><div class="as-grid two"><div class="as-field"><label>Current password</label><input class="as-input" data-as-old-password type="password" autocomplete="current-password"></div><div class="as-field"><label>New password</label><input class="as-input" data-as-new-password type="password" autocomplete="new-password"></div></div><button class="as-button secondary" type="submit">Change password</button></form>',
        '</div>'
      ].join('');
      container.querySelector('[data-as-setup-totp]').addEventListener('click', function() {
        widgetSetLoading(container, true);
        client.setupTOTP().then(function(data) {
          state.totp = data;
          renderTOTPSetup();
        }).catch(function(err) {
          widgetMessage(container, err.message || 'Could not start MFA setup', 'error');
        }).then(function() {
          widgetSetLoading(container, false);
        });
      });
      container.querySelector('[data-as-rotate-codes]').addEventListener('click', function() {
        widgetSetLoading(container, true);
        client.generateRecoveryCodes().then(function(data) {
          state.codes = data.recovery_codes || [];
          renderCodes();
        }).catch(function(err) {
          widgetMessage(container, err.message || 'Could not rotate recovery codes', 'error');
        }).then(function() {
          widgetSetLoading(container, false);
        });
      });
      container.querySelector('[data-as-password]').addEventListener('submit', function(event) {
        event.preventDefault();
        widgetSetLoading(container, true);
        client.changePassword({
          old_password: widgetValue(container, '[data-as-old-password]'),
          new_password: widgetValue(container, '[data-as-new-password]')
        }).then(function() {
          widgetMessage(container, 'Password changed.', 'ok');
          container.querySelector('[data-as-password]').reset();
        }).catch(function(err) {
          widgetMessage(container, err.message || 'Could not change password', 'error');
        }).then(function() {
          widgetSetLoading(container, false);
        });
      });
    }

    function renderTOTPSetup() {
      var wrap = container.querySelector('[data-as-totp-setup]');
      if (!wrap || !state.totp) return;
      wrap.innerHTML = [
        '<div class="as-stack">',
        state.totp.qr ? '<img alt="Authenticator QR code" style="width:160px;height:160px;border:1px solid #d8dee8;border-radius:8px" src="' + state.totp.qr + '">' : '',
        '<div class="as-code"></div>',
        '<form class="as-grid two" data-as-enable-totp><div class="as-field"><label>Verification code</label><input class="as-input" data-as-totp-code inputmode="numeric" autocomplete="one-time-code"></div><button class="as-button" type="submit">Enable MFA</button></form>',
        '</div>'
      ].join('');
      wrap.querySelector('.as-code').textContent = state.totp.uri || state.totp.secret || '';
      wrap.querySelector('[data-as-enable-totp]').addEventListener('submit', function(event) {
        event.preventDefault();
        widgetSetLoading(container, true);
        client.enableTOTP(widgetValue(container, '[data-as-totp-code]')).then(function() {
          widgetMessage(container, 'MFA enabled.', 'ok');
          state.totp = null;
          return client.getRecoveryCodeCount().then(function(data) { state.recovery = data; });
        }).then(render).catch(function(err) {
          widgetMessage(container, err.message || 'Could not enable MFA', 'error');
        }).then(function() {
          widgetSetLoading(container, false);
        });
      });
    }

    function renderCodes() {
      var wrap = container.querySelector('[data-as-codes]');
      if (!wrap) return;
      wrap.innerHTML = state.codes.length ? '<pre class="as-code"></pre>' : '';
      if (state.codes.length) wrap.querySelector('pre').textContent = state.codes.join('\n');
    }

    function renderSessions() {
      var panel = container.querySelector('[data-as-panel]');
      panel.innerHTML = '<div class="as-stack" data-as-sessions></div><button class="as-button danger" data-as-revoke-all type="button">Revoke all sessions</button>';
      var list = panel.querySelector('[data-as-sessions]');
      if (!state.sessions.length) list.innerHTML = '<div class="as-muted">No active sessions were returned.</div>';
      state.sessions.forEach(function(session) {
        var row = createRow(session.user_agent || session.id || 'Session', (session.ip_address || '') + ' ' + formatDate(session.created_at || session.last_used_at), 'Revoke', 'danger');
        row.querySelector('button').addEventListener('click', function() {
          client.revokeSession(session.id).then(load);
        });
        list.appendChild(row);
      });
      panel.querySelector('[data-as-revoke-all]').addEventListener('click', function() {
        client.revokeAllSessions().then(function() {
          widgetMessage(container, 'Sessions revoked.', 'ok');
          state.sessions = [];
          renderSessions();
        }).catch(function(err) {
          widgetMessage(container, err.message || 'Could not revoke sessions', 'error');
        });
      });
    }

    function renderPasskeys() {
      var panel = container.querySelector('[data-as-panel]');
      panel.innerHTML = '<div class="as-stack"><button class="as-button" data-as-add-passkey type="button">Add passkey</button><div data-as-passkeys></div></div>';
      panel.querySelector('[data-as-add-passkey]').addEventListener('click', function() {
        widgetSetLoading(container, true);
        client.registerPasskey(options.passkeyName || 'Passkey').then(load).catch(function(err) {
          widgetMessage(container, err.message || 'Could not add passkey', 'error');
        }).then(function() {
          widgetSetLoading(container, false);
        });
      });
      var list = panel.querySelector('[data-as-passkeys]');
      if (!state.passkeys.length) list.innerHTML = '<div class="as-muted">No passkeys yet.</div>';
      state.passkeys.forEach(function(passkey) {
        var row = createRow(passkey.name || passkey.id || 'Passkey', formatDate(passkey.created_at) || passkey.id || '', 'Delete', 'danger');
        row.querySelector('button').addEventListener('click', function() {
          client.deletePasskey(passkey.id).then(load);
        });
        list.appendChild(row);
      });
    }

    load();
    return {
      refresh: load,
      destroy: function() { container.innerHTML = ''; }
    };
  };

  AuthClient.prototype.mountOrganizationSwitcher = function(container, options) {
    ensureWidgetStyles();
    container = resolveContainer(container);
    options = options || {};
    var client = this;

    function render() {
      container.innerHTML = '<div class="as-card as-stack"><div class="as-message" data-as-message></div><div data-as-orgs class="as-stack"></div><form class="as-grid two" data-as-create-org><div class="as-field"><label>Organization name</label><input class="as-input" data-as-org-name type="text"></div><div class="as-field"><label>Slug</label><input class="as-input" data-as-org-slug type="text"></div><button class="as-button secondary" type="submit">Create</button></form></div>';
      client.listOrganizations().then(function(data) {
        var rows = normalizeArrayPayload(data, 'organizations');
        var list = container.querySelector('[data-as-orgs]');
        list.innerHTML = '';
        if (!rows.length) list.innerHTML = '<div class="as-muted">No organizations yet.</div>';
        rows.forEach(function(row) {
          var org = row.organization || row;
          var membership = row.membership || {};
          var item = createRow(org.name || org.slug || org.id, [org.slug, membership.role].filter(Boolean).join(' · '), 'Switch', 'secondary');
          item.querySelector('button').addEventListener('click', function() {
            client.createOrganizationToken(org.id, { activate: true }).then(function(token) {
              widgetMessage(container, 'Organization activated.', 'ok');
              if (options.onSelect) options.onSelect(row, token);
            }).catch(function(err) {
              widgetMessage(container, err.message || 'Could not switch organization', 'error');
            });
          });
          list.appendChild(item);
        });
      }).catch(function(err) {
        widgetMessage(container, err.message || 'Could not load organizations', 'error');
      });
      container.querySelector('[data-as-create-org]').addEventListener('submit', function(event) {
        event.preventDefault();
        client.createOrganization({
          name: widgetValue(container, '[data-as-org-name]'),
          slug: widgetValue(container, '[data-as-org-slug]')
        }).then(function(org) {
          widgetMessage(container, 'Organization created.', 'ok');
          if (options.onCreate) options.onCreate(org);
          render();
        }).catch(function(err) {
          widgetMessage(container, err.message || 'Could not create organization', 'error');
        });
      });
    }

    render();
    return {
      refresh: render,
      destroy: function() { container.innerHTML = ''; }
    };
  };

  AuthClient.prototype.mountOrganizationManagement = function(container, options) {
    ensureWidgetStyles();
    container = resolveContainer(container);
    options = options || {};
    var client = this;
    var state = { organizations: [], selected: options.organizationID || '', members: [], invitations: [] };

    function load() {
      return client.listOrganizations().then(function(data) {
        state.organizations = normalizeArrayPayload(data, 'organizations');
        if (!state.selected && state.organizations[0]) {
          var first = state.organizations[0].organization || state.organizations[0];
          state.selected = first.id;
        }
        return loadOrganizationDetails();
      }).then(render).catch(function(err) {
        container.innerHTML = '<div class="as-card wide"><div class="as-message show error"></div></div>';
        container.querySelector('.as-message').textContent = err.message || 'Could not load organization management';
      });
    }

    function loadOrganizationDetails() {
      if (!state.selected) return Promise.resolve();
      return Promise.all([
        client.listOrganizationMembers(state.selected).then(function(data) { state.members = normalizeArrayPayload(data, 'members'); }).catch(function() { state.members = []; }),
        client.listOrganizationInvitations(state.selected).then(function(data) { state.invitations = normalizeArrayPayload(data, 'invitations'); }).catch(function() { state.invitations = []; })
      ]);
    }

    function render() {
      container.innerHTML = [
        '<div class="as-card wide as-stack">',
        '<div class="as-message" data-as-message></div>',
        '<div class="as-field"><label>Organization</label><select class="as-input" data-as-org-select></select></div>',
        '<form class="as-grid two" data-as-invite><div class="as-field"><label>Invite email</label><input class="as-input" data-as-invite-email type="email"></div><div class="as-field"><label>Role</label><select class="as-input" data-as-invite-role><option value="member">Member</option><option value="admin">Admin</option><option value="viewer">Viewer</option></select></div><div class="as-field"><label>Custom permissions</label><input class="as-input" data-as-invite-permissions placeholder="billing:manage, reports:read"></div><button class="as-button" type="submit">Invite</button></form>',
        '<table class="as-table"><thead><tr><th>User</th><th>Role</th><th>Permissions</th><th></th></tr></thead><tbody data-as-members></tbody></table>',
        '<div><div class="as-row-title">Pending invitations</div><div data-as-invitations class="as-stack"></div></div>',
        '</div>'
      ].join('');
      var select = container.querySelector('[data-as-org-select]');
      state.organizations.forEach(function(row) {
        var org = row.organization || row;
        var option = root.document.createElement('option');
        option.value = org.id;
        option.textContent = org.name || org.slug || org.id;
        if (org.id === state.selected) option.selected = true;
        select.appendChild(option);
      });
      select.addEventListener('change', function() {
        state.selected = select.value;
        loadOrganizationDetails().then(render);
      });
      renderMembers();
      renderInvitations();
      container.querySelector('[data-as-invite]').addEventListener('submit', function(event) {
        event.preventDefault();
        client.inviteOrganizationMember(state.selected, {
          email: widgetValue(container, '[data-as-invite-email]'),
          role: widgetValue(container, '[data-as-invite-role]'),
          permissions: listFromText(widgetValue(container, '[data-as-invite-permissions]'))
        }).then(function(invitation) {
          widgetMessage(container, 'Invitation created.', 'ok');
          if (options.onInvite) options.onInvite(invitation);
          return loadOrganizationDetails();
        }).then(render).catch(function(err) {
          widgetMessage(container, err.message || 'Could not invite member', 'error');
        });
      });
    }

    function renderMembers() {
      var tbody = container.querySelector('[data-as-members]');
      tbody.innerHTML = '';
      if (!state.members.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="as-muted">No members returned.</td></tr>';
        return;
      }
      state.members.forEach(function(member) {
        var tr = root.document.createElement('tr');
        tr.innerHTML = '<td></td><td><select class="as-input"><option value="owner">Owner</option><option value="admin">Admin</option><option value="member">Member</option><option value="viewer">Viewer</option></select></td><td><input class="as-input" placeholder="custom permissions"></td><td><button class="as-button secondary" type="button">Save</button> <button class="as-button danger" type="button">Remove</button></td>';
        tr.children[0].textContent = member.email || member.user_id || member.userId || member.id;
        var roleSelect = tr.querySelector('select');
        roleSelect.value = member.role || 'member';
        var permissionsInput = tr.querySelector('input');
        permissionsInput.value = (member.permissions || []).join(', ');
        var buttons = tr.querySelectorAll('button');
        buttons[0].addEventListener('click', function() {
          client.updateOrganizationMember(state.selected, member.user_id || member.userId || member.id, {
            role: roleSelect.value,
            permissions: listFromText(permissionsInput.value)
          }).then(function() {
            widgetMessage(container, 'Member updated.', 'ok');
          }).catch(function(err) {
            widgetMessage(container, err.message || 'Could not update member', 'error');
          });
        });
        buttons[1].addEventListener('click', function() {
          client.removeOrganizationMember(state.selected, member.user_id || member.userId || member.id).then(function() {
            return loadOrganizationDetails();
          }).then(render).catch(function(err) {
            widgetMessage(container, err.message || 'Could not remove member', 'error');
          });
        });
        tbody.appendChild(tr);
      });
    }

    function renderInvitations() {
      var list = container.querySelector('[data-as-invitations]');
      list.innerHTML = '';
      if (!state.invitations.length) {
        list.innerHTML = '<div class="as-muted">No pending invitations returned.</div>';
        return;
      }
      state.invitations.forEach(function(invitation) {
        var row = createRow(invitation.email || invitation.id, [invitation.role, invitation.status, formatDate(invitation.expires_at)].filter(Boolean).join(' · '), 'Revoke', 'danger');
        row.querySelector('button').addEventListener('click', function() {
          client.revokeOrganizationInvitation(state.selected, invitation.id).then(function() {
            return loadOrganizationDetails();
          }).then(render);
        });
        list.appendChild(row);
      });
    }

    load();
    return {
      refresh: load,
      destroy: function() { container.innerHTML = ''; }
    };
  };

  AuthClient.prototype.mountEnterpriseSetup = function(container, options) {
    ensureWidgetStyles();
    container = resolveContainer(container);
    options = options || {};
    var client = this;
    if (options.adminKey) client.adminKey = options.adminKey;
    var clientID = options.clientID || options.clientId || '';
    var state = { sso: [], scim: [] };

    function load() {
      if (!clientID) {
        container.innerHTML = '<div class="as-card wide"><div class="as-message show error">clientID is required for enterprise setup.</div></div>';
        return Promise.resolve();
      }
      return Promise.all([
        client.listSSOConnections(clientID).then(function(data) { state.sso = normalizeArrayPayload(data, 'connections'); }).catch(function() { state.sso = []; }),
        client.listSCIMDirectories(clientID).then(function(data) { state.scim = normalizeArrayPayload(data, 'directories'); }).catch(function() { state.scim = []; })
      ]).then(render).catch(function(err) {
        container.innerHTML = '<div class="as-card wide"><div class="as-message show error"></div></div>';
        container.querySelector('.as-message').textContent = err.message || 'Could not load enterprise setup';
      });
    }

    function render() {
      container.innerHTML = [
        '<div class="as-card wide as-stack">',
        '<div class="as-message" data-as-message></div>',
        '<div class="as-grid two">',
        '<form class="as-stack" data-as-sso><div class="as-row-title">SSO connection</div><div class="as-field"><label>Name</label><input class="as-input" data-as-sso-name></div><div class="as-field"><label>Domains</label><input class="as-input" data-as-sso-domains placeholder="acme.com, example.com"></div><div class="as-field"><label>Protocol</label><select class="as-input" data-as-sso-protocol><option value="oidc">OIDC</option><option value="saml">SAML</option></select></div><div class="as-field"><label>OIDC issuer</label><input class="as-input" data-as-oidc-issuer placeholder="https://idp.example.com"></div><div class="as-field"><label>OIDC client ID</label><input class="as-input" data-as-oidc-client></div><div class="as-field"><label>OIDC client secret</label><input class="as-input" data-as-oidc-secret type="password"></div><button class="as-button" type="submit">Create SSO</button></form>',
        '<form class="as-stack" data-as-scim><div class="as-row-title">SCIM directory</div><div class="as-field"><label>Name</label><input class="as-input" data-as-scim-name></div><div class="as-field"><label>Domains</label><input class="as-input" data-as-scim-domains placeholder="acme.com"></div><button class="as-button" type="submit">Create directory</button></form>',
        '</div>',
        '<div><div class="as-row-title">SSO connections</div><div data-as-sso-list class="as-stack"></div></div>',
        '<div><div class="as-row-title">SCIM directories</div><div data-as-scim-list class="as-stack"></div></div>',
        '</div>'
      ].join('');
      renderEnterpriseLists();
      container.querySelector('[data-as-sso]').addEventListener('submit', function(event) {
        event.preventDefault();
        var protocol = widgetValue(container, '[data-as-sso-protocol]');
        var body = {
          name: widgetValue(container, '[data-as-sso-name]'),
          protocol: protocol,
          status: 'active',
          domains: listFromText(widgetValue(container, '[data-as-sso-domains]')),
          enforce_for_domains: true,
          attribute_mapping: { email: 'email', name: 'name' }
        };
        if (protocol === 'oidc') {
          body.oidc = {
            issuer: widgetValue(container, '[data-as-oidc-issuer]'),
            client_id: widgetValue(container, '[data-as-oidc-client]'),
            client_secret: widgetValue(container, '[data-as-oidc-secret]'),
            scopes: ['openid', 'email', 'profile']
          };
        } else {
          body.saml = {};
        }
        client.createSSOConnection(clientID, body).then(function(connection) {
          widgetMessage(container, 'SSO connection created.', 'ok');
          if (options.onSSOCreate) options.onSSOCreate(connection);
          return load();
        }).catch(function(err) {
          widgetMessage(container, err.message || 'Could not create SSO connection', 'error');
        });
      });
      container.querySelector('[data-as-scim]').addEventListener('submit', function(event) {
        event.preventDefault();
        client.createSCIMDirectory(clientID, {
          name: widgetValue(container, '[data-as-scim-name]'),
          domains: listFromText(widgetValue(container, '[data-as-scim-domains]'))
        }).then(function(directory) {
          widgetMessage(container, 'SCIM directory created.', 'ok');
          renderSecret(directory.token || '');
          if (options.onSCIMCreate) options.onSCIMCreate(directory);
          return load();
        }).catch(function(err) {
          widgetMessage(container, err.message || 'Could not create SCIM directory', 'error');
        });
      });
    }

    function renderEnterpriseLists() {
      var ssoList = container.querySelector('[data-as-sso-list]');
      var scimList = container.querySelector('[data-as-scim-list]');
      ssoList.innerHTML = '';
      scimList.innerHTML = '';
      if (!state.sso.length) ssoList.innerHTML = '<div class="as-muted">No SSO connections yet.</div>';
      state.sso.forEach(function(connection) {
        var row = createRow(connection.name || connection.id, [connection.protocol, connection.status, (connection.domains || []).join(', ')].filter(Boolean).join(' · '), connection.status === 'active' ? 'Deactivate' : '', 'danger');
        if (row.querySelector('button')) {
          row.querySelector('button').addEventListener('click', function() {
            client.deleteSSOConnection(clientID, connection.id).then(load);
          });
        }
        ssoList.appendChild(row);
      });
      if (!state.scim.length) scimList.innerHTML = '<div class="as-muted">No SCIM directories yet.</div>';
      state.scim.forEach(function(directory) {
        var row = createRow(directory.name || directory.id, [directory.status, directory.token_prefix, (directory.domains || []).join(', ')].filter(Boolean).join(' · '), 'Rotate token', 'secondary');
        row.querySelector('button').addEventListener('click', function() {
          client.rotateSCIMDirectoryToken(clientID, directory.id).then(function(resp) {
            renderSecret(resp.token || '');
            return load();
          }).catch(function(err) {
            widgetMessage(container, err.message || 'Could not rotate SCIM token', 'error');
          });
        });
        scimList.appendChild(row);
      });
    }

    function renderSecret(secret) {
      if (!secret) return;
      var message = container.querySelector('[data-as-message]');
      if (!message) return;
      message.className = 'as-message show ok';
      message.innerHTML = '';
      var label = root.document.createElement('div');
      label.textContent = 'Secret shown once. Store it now.';
      var code = root.document.createElement('pre');
      code.className = 'as-code';
      code.textContent = secret;
      message.appendChild(label);
      message.appendChild(code);
    }

    load();
    return {
      refresh: load,
      destroy: function() { container.innerHTML = ''; }
    };
  };

  AuthClient.prototype.mountAuditLog = function(container, options) {
    ensureWidgetStyles();
    container = resolveContainer(container);
    options = options || {};
    var client = this;
    if (options.adminKey) client.adminKey = options.adminKey;
    var state = { events: [] };

    function load(params) {
      params = params || {
        client_id: widgetValue(container, '[data-as-client-id]') || options.clientID || options.clientId || '',
        user_id: widgetValue(container, '[data-as-user-id]') || '',
        event_type: widgetValue(container, '[data-as-event-type]') || '',
        limit: widgetValue(container, '[data-as-limit]') || options.limit || 50
      };
      return client.listAuditEvents(params).then(function(data) {
        state.events = normalizeArrayPayload(data, 'events');
        renderRows();
      }).catch(function(err) {
        widgetMessage(container, err.message || 'Could not load audit events', 'error');
      });
    }

    function render() {
      container.innerHTML = [
        '<div class="as-card wide as-stack">',
        '<div class="as-message" data-as-message></div>',
        '<form class="as-grid two" data-as-audit-filter><div class="as-field"><label>Client ID</label><input class="as-input" data-as-client-id></div><div class="as-field"><label>Event type</label><input class="as-input" data-as-event-type placeholder="login_failed"></div><div class="as-field"><label>User ID</label><input class="as-input" data-as-user-id></div><div class="as-field"><label>Limit</label><input class="as-input" data-as-limit type="number" min="1" max="500" value="50"></div><button class="as-button" type="submit">Filter</button><button class="as-button secondary" data-as-export type="button">Export CSV</button></form>',
        '<table class="as-table"><thead><tr><th>Time</th><th>Type</th><th>User</th><th>IP</th></tr></thead><tbody data-as-events></tbody></table>',
        '</div>'
      ].join('');
      container.querySelector('[data-as-client-id]').value = options.clientID || options.clientId || '';
      container.querySelector('[data-as-limit]').value = options.limit || 50;
      container.querySelector('[data-as-audit-filter]').addEventListener('submit', function(event) {
        event.preventDefault();
        load();
      });
      container.querySelector('[data-as-export]').addEventListener('click', exportCSV);
      load();
    }

    function auditParams() {
      return {
        client_id: widgetValue(container, '[data-as-client-id]') || '',
        user_id: widgetValue(container, '[data-as-user-id]') || '',
        event_type: widgetValue(container, '[data-as-event-type]') || '',
        limit: widgetValue(container, '[data-as-limit]') || 50,
        format: 'csv'
      };
    }

    function exportCSV() {
      client.adminRequest('/api/admin/audit-events/export', { query: auditParams() }).then(function(csv) {
        var blob = new Blob([String(csv || '')], { type: 'text/csv;charset=utf-8' });
        var url = root.URL.createObjectURL(blob);
        var link = root.document.createElement('a');
        link.href = url;
        link.download = 'authservice-audit-events.csv';
        link.click();
        root.URL.revokeObjectURL(url);
      }).catch(function(err) {
        widgetMessage(container, err.message || 'Could not export audit events', 'error');
      });
    }

    function renderRows() {
      var tbody = container.querySelector('[data-as-events]');
      if (!tbody) return;
      tbody.innerHTML = '';
      if (!state.events.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="as-muted">No audit events returned.</td></tr>';
        return;
      }
      state.events.forEach(function(event) {
        var tr = root.document.createElement('tr');
        tr.innerHTML = '<td></td><td></td><td></td><td></td>';
        tr.children[0].textContent = formatDate(event.created_at);
        tr.children[1].textContent = event.event_type || '';
        tr.children[2].textContent = event.user_id || '';
        tr.children[3].textContent = event.ip_address || '';
        tbody.appendChild(tr);
      });
    }

    render();
    return {
      refresh: load,
      destroy: function() { container.innerHTML = ''; }
    };
  };

  function createClient(options) {
    return new AuthClient(options);
  }

  return {
    version: VERSION,
    AUTH_ERROR_CODES: AUTH_ERROR_CODES.slice(),
    AuthClient: AuthClient,
    AuthServiceError: AuthServiceError,
    createClient: createClient,
    decodeJWT: decodeJWT,
    permissionFor: permissionFor,
    createPKCEVerifier: function() { return randomB64url(64); },
    createPKCEChallenge: sha256B64url,
    mountSignIn: function(container, options) {
      var client = createClient(options || {});
      return client.mountSignIn(container, options || {});
    },
    mountSignUp: function(container, options) {
      var client = createClient(options || {});
      return client.mountSignUp(container, options || {});
    },
    mountUserButton: function(container, options) {
      var client = createClient(options || {});
      return client.mountUserButton(container, options || {});
    },
    mountUserProfile: function(container, options) {
      var client = createClient(options || {});
      return client.mountUserProfile(container, options || {});
    },
    mountOrganizationSwitcher: function(container, options) {
      var client = createClient(options || {});
      return client.mountOrganizationSwitcher(container, options || {});
    },
    mountOrganizationManagement: function(container, options) {
      var client = createClient(options || {});
      return client.mountOrganizationManagement(container, options || {});
    },
    mountEnterpriseSetup: function(container, options) {
      var client = createClient(options || {});
      return client.mountEnterpriseSetup(container, options || {});
    },
    mountAuditLog: function(container, options) {
      var client = createClient(options || {});
      return client.mountAuditLog(container, options || {});
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
