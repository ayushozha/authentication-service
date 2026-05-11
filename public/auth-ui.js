(function(root) {
  'use strict';

  var AuthService = root.AuthService;
  if (!AuthService) throw new Error('auth-ui.js requires authservice.js');

  var DEFAULT_PROVIDERS = ['google', 'github', 'microsoft', 'apple'];
  var PROVIDER_LABELS = {
    google: 'Google',
    github: 'GitHub',
    microsoft: 'Microsoft',
    apple: 'Apple'
  };
  var STORAGE = {
    apiKey: 'auth_api_key',
    adminKey: 'auth_admin_key',
    clientID: 'auth_admin_client_id',
    redirectURL: 'auth_redirect_url'
  };

  var I18N = {
    en: {
      secureAccess: 'Secure access',
      visualTitle: 'Production-ready auth UI for every serious sign-in path.',
      visualCopy: 'Password, passkeys, SSO discovery, MFA recovery, organizations, and account security are ready from one hosted surface.',
      password: 'Password',
      passkey: 'Passkey',
      magic: 'Magic link',
      sso: 'SSO',
      signIn: 'Sign in',
      signUp: 'Sign up',
      createAccount: 'Create account',
      welcomeBack: 'Welcome back',
      loginSub: 'Use the method your organization trusts.',
      signupSub: 'Create a secure account with password or social login.',
      email: 'Email',
      fullName: 'Full name',
      passwordLabel: 'Password',
      confirmPassword: 'Confirm password',
      currentPassword: 'Current password',
      newPassword: 'New password',
      continueWithPasskey: 'Continue with passkey',
      sendMagic: 'Send magic link',
      discoverSSO: 'Continue with SSO',
      domain: 'Company domain',
      code: 'Authenticator code',
      recoveryCode: 'Recovery code',
      verify: 'Verify',
      forgot: 'Forgot password?',
      resetPassword: 'Reset password',
      account: 'Account',
      profile: 'Profile',
      organizations: 'Organizations',
      enterprise: 'Enterprise',
      audit: 'Audit log',
      success: 'Success.',
      working: 'Working...'
    },
    es: {
      secureAccess: 'Acceso seguro',
      visualTitle: 'Autenticacion lista para produccion en cada flujo importante.',
      visualCopy: 'Contrasena, passkeys, SSO, MFA, organizaciones y seguridad de cuenta desde una sola experiencia.',
      signIn: 'Iniciar sesion',
      signUp: 'Registrarse',
      createAccount: 'Crear cuenta',
      welcomeBack: 'Bienvenido',
      loginSub: 'Usa el metodo que tu organizacion confia.',
      signupSub: 'Crea una cuenta segura.',
      email: 'Correo',
      fullName: 'Nombre completo',
      passwordLabel: 'Contrasena',
      confirmPassword: 'Confirmar contrasena',
      continueWithPasskey: 'Continuar con passkey',
      sendMagic: 'Enviar enlace',
      discoverSSO: 'Continuar con SSO',
      domain: 'Dominio de empresa',
      verify: 'Verificar',
      forgot: 'Olvidaste tu contrasena?',
      resetPassword: 'Restablecer contrasena',
      account: 'Cuenta',
      profile: 'Perfil',
      organizations: 'Organizaciones',
      enterprise: 'Empresa',
      audit: 'Auditoria',
      working: 'Procesando...'
    }
  };

  function qs(search) {
    return new URLSearchParams(search || root.location.search || '');
  }

  function trimSlash(value) {
    return String(value || '').replace(/\/+$/, '');
  }

  function readJSON(value, fallback) {
    if (!value) return fallback;
    try {
      return JSON.parse(value);
    } catch (err) {
      return fallback;
    }
  }

  function list(value) {
    if (Array.isArray(value)) return value;
    return String(value || '').split(/[,\n]/).map(function(item) {
      return item.trim();
    }).filter(Boolean);
  }

  function first(value, fallback) {
    return value === undefined || value === null || value === '' ? fallback : value;
  }

  function escapeHTML(value) {
    return String(value || '').replace(/[&<>"']/g, function(ch) {
      return {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      }[ch];
    });
  }

  function safeLocalStorage() {
    try {
      return root.localStorage;
    } catch (err) {
      return null;
    }
  }

  function safeSessionStorage() {
    try {
      return root.sessionStorage;
    } catch (err) {
      return null;
    }
  }

  function setText(parent, selector, text) {
    var el = parent.querySelector(selector);
    if (el) el.textContent = text || '';
  }

  function value(parent, selector) {
    var el = parent.querySelector(selector);
    return el ? el.value : '';
  }

  function setBusy(parent, busy) {
    var controls = parent.querySelectorAll('button, input, select, textarea');
    for (var i = 0; i < controls.length; i++) controls[i].disabled = !!busy;
  }

  function formatDate(value) {
    if (!value) return '';
    try {
      return new Date(value).toLocaleString();
    } catch (err) {
      return String(value);
    }
  }

  function normalizeRows(payload, key) {
    if (!payload) return [];
    if (Array.isArray(payload)) return payload;
    if (Array.isArray(payload[key])) return payload[key];
    if (Array.isArray(payload.connections)) return payload.connections;
    if (Array.isArray(payload.directories)) return payload.directories;
    return [];
  }

  function validProvider(provider) {
    return /^[a-z0-9_-]+$/i.test(String(provider || ''));
  }

  function HostedAuth(rootEl, options) {
    this.root = rootEl;
    this.options = options || {};
    this.params = qs();
    this.storage = safeLocalStorage();
    this.view = this.options.view || rootEl.getAttribute('data-auth-view') || this.params.get('view') || viewFromPath(root.location.pathname);
    this.baseUrl = trimSlash(this.params.get('base_url') || this.options.baseUrl || root.location.origin);
    this.apiKey = this.params.get('api_key') || this.options.apiKey || this.getStored(STORAGE.apiKey);
    this.adminKey = this.params.get('admin_key') || this.options.adminKey || this.getStored(STORAGE.adminKey);
    this.clientID = this.params.get('client_id') || this.options.clientID || this.getStored(STORAGE.clientID);
    this.sessionMode = this.params.get('session_mode') || this.options.sessionMode || 'token';
    this.redirectURL = this.params.get('redirect_url') || this.options.redirectURL || this.getStored(STORAGE.redirectURL);
    this.locale = this.params.get('locale') || this.options.locale || 'en';
    this.ui = {};
    this.state = {
      authMode: this.params.get('mode') || 'password',
      busy: false,
      message: '',
      messageType: 'ok',
      twoFactorToken: this.params.get('two_factor_token') || '',
      useRecovery: false,
      signupComplete: false,
      activeAccountTab: this.params.get('tab') || 'profile',
      mountedWidget: null,
      autoVerified: false
    };
    this.consumeFlashMessage();
    this.client = AuthService.createClient({
      baseUrl: this.baseUrl,
      apiKey: this.apiKey,
      adminKey: this.adminKey,
      sessionMode: this.sessionMode
    });
    this.persistInitialParams();
  }

  HostedAuth.prototype.getStored = function(key) {
    return this.storage ? this.storage.getItem(key) || '' : '';
  };

  HostedAuth.prototype.setStored = function(key, value) {
    if (!this.storage) return;
    if (value) this.storage.setItem(key, value);
    else this.storage.removeItem(key);
  };

  HostedAuth.prototype.consumeFlashMessage = function() {
    var storage = safeSessionStorage();
    if (!storage) return;
    var message = storage.getItem('auth_flash_success');
    if (!message) return;
    storage.removeItem('auth_flash_success');
    this.state.message = message;
    this.state.messageType = 'ok';
  };

  HostedAuth.prototype.setFlashMessage = function(text) {
    var storage = safeSessionStorage();
    if (storage && text) storage.setItem('auth_flash_success', text);
  };

  HostedAuth.prototype.persistInitialParams = function() {
    if (this.apiKey) this.setStored(STORAGE.apiKey, this.apiKey);
    if (this.adminKey) this.setStored(STORAGE.adminKey, this.adminKey);
    if (this.clientID) this.setStored(STORAGE.clientID, this.clientID);
    if (this.redirectURL) this.setStored(STORAGE.redirectURL, this.redirectURL);
    if (this.params.get('access_token')) this.client.setAccessToken(this.params.get('access_token'));
    if (this.params.get('refresh_token')) this.client.setRefreshToken(this.params.get('refresh_token'));
  };

  HostedAuth.prototype.t = function(key) {
    var dict = I18N[this.locale] || I18N.en;
    return dict[key] || I18N.en[key] || key;
  };

  HostedAuth.prototype.start = function() {
    var self = this;
    var authCode = this.params.get('auth_code');
    if (authCode) {
      return this.client.exchangeRedirectCode(authCode).then(function(data) {
        return self.completeAuth(data);
      }).catch(function(err) {
        self.setMessage(err && err.message ? err.message : 'Could not finish sign-in.', 'error');
        self.render();
      });
    }
    if (!this.apiKey) {
      this.render();
      return Promise.resolve();
    }
    return this.client.getUIConfig().then(function(config) {
      self.config = config || {};
      self.ui = self.config.ui || {};
      self.locale = self.params.get('locale') || self.ui.locale || self.locale;
      self.applyTheme();
      self.render();
    }).catch(function(err) {
      self.setMessage(err && err.message ? err.message : '', 'error');
      self.render();
    });
  };

  HostedAuth.prototype.applyTheme = function() {
    var style = this.root.style;
    if (this.ui.primary_color) style.setProperty('--as-primary', this.ui.primary_color);
    if (this.ui.accent_color) style.setProperty('--as-accent', this.ui.accent_color);
    if (this.ui.background_color) style.setProperty('--as-page', this.ui.background_color);
    if (this.ui.text_color) style.setProperty('--as-ink', this.ui.text_color);
    if (this.ui.theme === 'dark') this.root.setAttribute('data-theme', 'dark');
    root.document.documentElement.lang = this.locale || 'en';
  };

  HostedAuth.prototype.brandName = function() {
    return this.params.get('brand') || this.ui.brand_name || (this.config && this.config.client && this.config.client.name) || 'AuthService';
  };

  HostedAuth.prototype.providerList = function() {
    var fromQuery = list(this.params.get('providers'));
    if (fromQuery.length) return fromQuery.filter(validProvider);
    if (Array.isArray(this.ui.oauth_providers) && this.ui.oauth_providers.length) return this.ui.oauth_providers.filter(validProvider);
    return DEFAULT_PROVIDERS;
  };

  HostedAuth.prototype.setMessage = function(text, type) {
    this.state.message = text || '';
    this.state.messageType = type || 'ok';
    var el = this.root.querySelector('[data-auth-message]');
    if (el) {
      el.textContent = this.state.message;
      var successAlias = this.state.message && this.state.messageType === 'ok' ? ' success' : '';
      el.className = 'as-message' + (this.state.message ? ' show ' + this.state.messageType + successAlias : '');
    }
  };

  HostedAuth.prototype.run = function(work) {
    var self = this;
    this.state.busy = true;
    setBusy(this.root, true);
    return Promise.resolve().then(work).catch(function(err) {
      self.setMessage(err.message || 'Request failed', 'error');
      throw err;
    }).finally(function() {
      self.state.busy = false;
      setBusy(self.root, false);
    });
  };

  HostedAuth.prototype.render = function() {
    if (this.state.mountedWidget && this.state.mountedWidget.destroy) {
      this.state.mountedWidget.destroy();
      this.state.mountedWidget = null;
    }
    if (this.view === 'signup') return this.renderSignup();
    if (this.view === 'forgot') return this.renderForgot();
    if (this.view === 'reset') return this.renderReset();
    if (this.view === 'verify') return this.renderVerifyEmail();
    if (this.view === 'mfa') return this.renderMFA();
    if (this.view === 'account') return this.renderAccount();
    return this.renderLogin();
  };

  HostedAuth.prototype.shell = function(title, subtitle, body, foot, wide) {
    var brand = this.brandName();
    var logoURL = escapeHTML(this.ui.logo_url || '');
    var logo = logoURL ? '<img class="as-logo-img" alt="" src="' + logoURL + '">' : '<div class="as-logo" aria-hidden="true">' + escapeHTML(brand.charAt(0).toUpperCase()) + '</div>';
    this.root.innerHTML = [
      '<a class="as-skip" href="#auth-main">Skip to form</a>',
      '<div class="as-shell">',
      '<aside class="as-visual" aria-label="' + escapeHTML(this.t('secureAccess')) + '">',
      '<div class="as-brand">' + logo + '<div class="as-brand-text"><div class="as-brand-name"></div><div class="as-brand-sub">' + this.t('secureAccess') + '</div></div></div>',
      '<div class="as-visual-copy"><h1>' + this.t('visualTitle') + '</h1><p>' + this.t('visualCopy') + '</p></div>',
      '<div class="as-signal-grid" aria-hidden="true">',
      '<div class="as-signal"><b>Passkey-first</b><span>Conditional UI, platform authenticators, and fallback methods.</span></div>',
      '<div class="as-signal"><b>Enterprise-ready</b><span>SSO discovery, SCIM setup, org roles, and audit evidence.</span></div>',
      '<div class="as-signal"><b>Recovery built in</b><span>MFA challenges, recovery codes, password reset, and sessions.</span></div>',
      '<div class="as-signal"><b>Tenant-branded</b><span>Custom domains, colors, logo, locale, and accessible markup.</span></div>',
      '</div>',
      '</aside>',
      '<main id="auth-main" class="as-main">',
      '<section class="as-panel ' + (wide ? 'as-panel-wide' : '') + '" aria-labelledby="auth-title">',
      '<header class="as-panel-head"><h2 id="auth-title"></h2><p></p></header>',
      '<div class="as-panel-body"><div id="msg" class="as-message" data-auth-message></div>' + body + '</div>',
      foot ? '<footer class="as-panel-foot">' + foot + '</footer>' : '',
      '</section>',
      '</main>',
      '</div>'
    ].join('');
    setText(this.root, '.as-brand-name', brand);
    setText(this.root, '#auth-title', title);
    setText(this.root, '.as-panel-head p', subtitle);
    this.setMessage(this.state.message, this.state.messageType);
  };

  HostedAuth.prototype.authNav = function(active) {
    return [
      '<div class="as-segment" role="tablist" aria-label="Authentication view">',
      '<button type="button" data-auth-view-switch="login" aria-selected="' + (active === 'login') + '">' + this.t('signIn') + '</button>',
      '<button type="button" data-auth-view-switch="signup" aria-selected="' + (active === 'signup') + '">' + this.t('signUp') + '</button>',
      '</div>'
    ].join('');
  };

  HostedAuth.prototype.bindAuthNav = function() {
    var self = this;
    var buttons = this.root.querySelectorAll('[data-auth-view-switch]');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener('click', function(event) {
        var next = event.currentTarget.getAttribute('data-auth-view-switch');
        root.location.href = next === 'signup' ? buildRelativeURL('signup.html', self.params) : buildRelativeURL('login.html', self.params);
      });
    }
  };

  HostedAuth.prototype.renderLogin = function() {
    if (this.state.twoFactorToken) return this.renderMFA();
    var providers = this.providerList();
    var providerButtons = providers.map(function(provider) {
      var label = PROVIDER_LABELS[provider] || provider;
      return '<button class="as-provider" type="button" data-provider="' + provider + '">' + label + '</button>';
    }).join('');
    var body = [
      this.authNav('login'),
      '<div class="as-actions">',
      '<button class="as-button full" data-passkey-login type="button">' + this.t('continueWithPasskey') + '</button>',
      '</div>',
      '<form id="loginForm" class="as-stack" data-password-login>',
      '<div class="as-field"><label for="email">' + this.t('email') + '</label><input id="email" name="email" type="email" autocomplete="username webauthn" required></div>',
      '<div class="as-field"><label for="password">' + this.t('passwordLabel') + '</label><input id="password" name="password" type="password" autocomplete="current-password" required></div>',
      '<button id="loginBtn" class="as-button full" type="submit">' + this.t('signIn') + '</button>',
      '</form>',
      '<div class="as-divider">or</div>',
      '<div class="as-provider-grid">' + providerButtons + '</div>',
      '<details class="as-stack"><summary id="magicLinkToggle">' + this.t('magic') + '</summary><div id="magicSection"><form id="magicForm" class="as-stack" data-magic-login><div class="as-field"><label for="magicEmail">' + this.t('email') + '</label><input id="magicEmail" type="email" data-magic-email autocomplete="email" required></div><button class="as-button secondary" type="submit">' + this.t('sendMagic') + '</button></form></div></details>',
      '<details class="as-stack"><summary>' + this.t('sso') + '</summary><form class="as-stack" data-sso-login><div class="as-field"><label>' + this.t('domain') + '</label><input data-sso-domain placeholder="acme.com" autocomplete="organization"></div><button class="as-button secondary" type="submit">' + this.t('discoverSSO') + '</button></form></details>'
    ].join('');
    this.shell(this.t('welcomeBack'), this.t('loginSub'), body, '<a href="forgot-password.html">' + this.t('forgot') + '</a>', false);
    this.bindAuthNav();
    this.bindLoginEvents();
    this.startConditionalPasskey();
  };

  HostedAuth.prototype.bindLoginEvents = function() {
    var self = this;
    this.root.querySelector('[data-password-login]').addEventListener('submit', function(event) {
      event.preventDefault();
      self.setMessage('');
      self.run(function() {
        return self.client.login({
          email: value(self.root, '#email'),
          password: value(self.root, '#password')
        }).then(function(data) {
          if (data && data.requires_2fa) {
            self.state.twoFactorToken = data.two_factor_token;
            self.renderMFA();
            return data;
          }
          return self.completeAuth(data);
        });
      }).catch(function() {});
    });
    this.root.querySelector('[data-passkey-login]').addEventListener('click', function() {
      self.setMessage('');
      self.run(function() {
        return self.client.loginWithPasskey().then(function(data) {
          return self.completeAuth(data);
        });
      }).catch(function() {});
    });
    this.root.querySelector('[data-magic-login]').addEventListener('submit', function(event) {
      event.preventDefault();
      self.setMessage('');
      self.run(function() {
        return self.client.sendMagicLink(value(self.root, '[data-magic-email]')).then(function() {
          self.setMessage('Magic link sent. Check your email.', 'ok');
        });
      }).catch(function() {});
    });
    this.root.querySelector('[data-sso-login]').addEventListener('submit', function(event) {
      event.preventDefault();
      self.client.startSSO({ domain: value(self.root, '[data-sso-domain]') });
    });
    var providers = this.root.querySelectorAll('[data-provider]');
    for (var i = 0; i < providers.length; i++) {
      providers[i].addEventListener('click', function(event) {
        self.client.startOAuth(event.currentTarget.getAttribute('data-provider'));
      });
    }
  };

  HostedAuth.prototype.startConditionalPasskey = function() {
    var self = this;
    if (this.params.get('conditional_passkey') === 'false') return;
    if (!root.AbortController) return;
    var controller = new AbortController();
    var email = this.root.querySelector('#email');
    if (email) email.addEventListener('input', function() { controller.abort(); }, { once: true });
    this.client.startConditionalPasskeyLogin({ signal: controller.signal }).then(function(data) {
      if (data) self.completeAuth(data);
    }).catch(function() {});
  };

  HostedAuth.prototype.renderSignup = function() {
    var providers = this.providerList();
    var providerButtons = providers.map(function(provider) {
      var label = PROVIDER_LABELS[provider] || provider;
      return '<button class="as-provider" type="button" data-provider="' + provider + '">' + label + '</button>';
    }).join('');
    var body = [
      this.authNav('signup'),
      this.state.signupComplete ? '<div class="as-message show ok">Account created. Add a passkey for faster future sign-ins.</div><button class="as-button full" data-add-passkey type="button">Add passkey</button>' : '',
      '<form id="signupForm" class="as-stack ' + (this.state.signupComplete ? 'as-hidden' : '') + '" data-signup>',
      '<div class="as-field"><label for="name">' + this.t('fullName') + '</label><input id="name" data-name type="text" autocomplete="name" required></div>',
      '<div class="as-field"><label for="email">' + this.t('email') + '</label><input id="email" data-email type="email" autocomplete="email" required></div>',
      '<div class="as-grid as-grid-2"><div class="as-field"><label for="password">' + this.t('passwordLabel') + '</label><input id="password" data-password type="password" autocomplete="new-password" minlength="8" required></div><div class="as-field"><label for="confirmPassword">' + this.t('confirmPassword') + '</label><input id="confirmPassword" data-confirm type="password" autocomplete="new-password" minlength="8" required></div></div>',
      '<label class="as-check"><input id="tos" type="checkbox" required> <span>I agree to the terms.</span></label>',
      '<button id="signupBtn" class="as-button full" type="submit">' + this.t('createAccount') + '</button>',
      '</form>',
      '<div class="as-divider">or</div><div class="as-provider-grid">' + providerButtons + '</div>'
    ].join('');
    this.shell(this.t('createAccount'), this.t('signupSub'), body, '<a href="login.html">' + this.t('signIn') + '</a>', false);
    this.bindAuthNav();
    this.bindSignupEvents();
  };

  HostedAuth.prototype.bindSignupEvents = function() {
    var self = this;
    var form = this.root.querySelector('[data-signup]');
    if (form) {
      form.addEventListener('submit', function(event) {
        event.preventDefault();
        if (value(self.root, '[data-password]') !== value(self.root, '[data-confirm]')) {
          self.setMessage('Passwords do not match.', 'error');
          return;
        }
        self.run(function() {
          return self.client.signup({
            display_name: value(self.root, '[data-name]'),
            email: value(self.root, '[data-email]'),
            password: value(self.root, '[data-password]')
          }).then(function(data) {
            self.state.signupComplete = true;
            self.setMessage('Account created.', 'ok');
            self.renderSignup();
            return data;
          });
        }).catch(function() {});
      });
    }
    var passkey = this.root.querySelector('[data-add-passkey]');
    if (passkey) {
      passkey.addEventListener('click', function() {
        self.run(function() {
          return self.client.registerPasskey('Primary passkey').then(function() {
            return self.completeAuth({});
          });
        }).catch(function() {});
      });
    }
    var providers = this.root.querySelectorAll('[data-provider]');
    for (var i = 0; i < providers.length; i++) {
      providers[i].addEventListener('click', function(event) {
        self.client.startOAuth(event.currentTarget.getAttribute('data-provider'));
      });
    }
  };

  HostedAuth.prototype.renderMFA = function() {
    var label = this.state.useRecovery ? this.t('recoveryCode') : this.t('code');
    var body = [
      '<form id="totpSection" class="as-stack" data-mfa>',
      '<div class="as-field"><label for="totpCode">' + label + '</label><input id="totpCode" data-mfa-code inputmode="numeric" autocomplete="one-time-code" required></div>',
      '<button id="totpBtn" class="as-button full" type="submit">' + this.t('verify') + '</button>',
      '<button class="as-button ghost" data-toggle-recovery type="button">' + (this.state.useRecovery ? 'Use authenticator code' : 'Use recovery code') + '</button>',
      '</form>'
    ].join('');
    this.shell('Two-step verification', 'Enter a code to finish signing in.', body, '<a href="login.html">' + this.t('signIn') + '</a>', false);
    this.bindMFAEvents();
  };

  HostedAuth.prototype.bindMFAEvents = function() {
    var self = this;
    this.root.querySelector('[data-toggle-recovery]').addEventListener('click', function() {
      self.state.useRecovery = !self.state.useRecovery;
      self.renderMFA();
    });
    this.root.querySelector('[data-mfa]').addEventListener('submit', function(event) {
      event.preventDefault();
      var payload = { two_factor_token: self.state.twoFactorToken, code: value(self.root, '[data-mfa-code]') };
      self.run(function() {
        var work = self.state.useRecovery ? self.client.verifyRecoveryCode(payload) : self.client.verifyTOTP(payload);
        return work.then(function(data) { return self.completeAuth(data); });
      }).catch(function() {});
    });
  };

  HostedAuth.prototype.renderForgot = function() {
    var body = '<form id="forgotForm" class="as-stack" data-forgot><div class="as-field"><label for="email">' + this.t('email') + '</label><input id="email" data-email type="email" autocomplete="email" required></div><button id="submitBtn" class="as-button full" type="submit">' + this.t('sendMagic') + '</button></form>';
    this.shell(this.t('forgot'), 'We will send account recovery instructions if the account exists.', body, '<a href="login.html">' + this.t('signIn') + '</a>', false);
    var self = this;
    this.root.querySelector('[data-forgot]').addEventListener('submit', function(event) {
      event.preventDefault();
      self.run(function() {
        return self.client.forgotPassword(value(self.root, '[data-email]')).then(function() {
          self.setMessage('Recovery email sent if the account exists.', 'ok');
        });
      }).catch(function() {});
    });
  };

  HostedAuth.prototype.renderReset = function() {
    var token = this.params.get('token') || '';
    var body = [
      '<form id="resetForm" class="as-stack" data-reset>',
      '<div class="as-field"><label>Reset token</label><input data-token required></div>',
      '<div class="as-grid as-grid-2"><div class="as-field"><label for="password">' + this.t('newPassword') + '</label><input id="password" data-password type="password" autocomplete="new-password" required minlength="8"></div><div class="as-field"><label for="confirmPassword">' + this.t('confirmPassword') + '</label><input id="confirmPassword" data-confirm type="password" autocomplete="new-password" required minlength="8"></div></div>',
      '<button id="resetBtn" class="as-button full" type="submit">' + this.t('resetPassword') + '</button>',
      '</form>'
    ].join('');
    this.shell(this.t('resetPassword'), 'Choose a new password for this account.', body, '<a href="login.html">' + this.t('signIn') + '</a>', false);
    this.root.querySelector('[data-token]').value = token;
    var self = this;
    this.root.querySelector('[data-reset]').addEventListener('submit', function(event) {
      event.preventDefault();
      if (value(self.root, '[data-password]') !== value(self.root, '[data-confirm]')) {
        self.setMessage('Passwords do not match.', 'error');
        return;
      }
      self.run(function() {
        return self.client.resetPassword({
          token: value(self.root, '[data-token]'),
          new_password: value(self.root, '[data-password]')
        }).then(function() {
          self.setMessage('Password reset. You can sign in now.', 'ok');
        });
      }).catch(function() {});
    });
  };

  HostedAuth.prototype.renderVerifyEmail = function() {
    var token = this.params.get('token') || '';
    var body = '<div id="iconSuccess" class="as-message ok success" hidden>Email verified.</div><form class="as-stack" data-verify><div class="as-field"><label>Email verification token</label><input data-token required></div><button class="as-button full" type="submit">' + this.t('verify') + '</button></form>';
    this.shell('Verify email', 'Confirm this email address for the account.', body, '<a href="account.html">' + this.t('account') + '</a>', false);
    this.root.querySelector('[data-token]').value = token;
    var self = this;
    this.root.querySelector('[data-verify]').addEventListener('submit', function(event) {
      event.preventDefault();
      self.run(function() {
        return self.client.verifyEmail(value(self.root, '[data-token]')).then(function() {
          self.setMessage('Email verified.', 'ok');
          var icon = self.root.querySelector('#iconSuccess');
          if (icon) {
            icon.hidden = false;
            icon.classList.add('show');
          }
        });
      }).catch(function() {});
    });
    if (token && !this.state.autoVerified) {
      this.state.autoVerified = true;
      this.root.querySelector('[data-verify]').dispatchEvent(new Event('submit'));
    }
  };

  HostedAuth.prototype.renderAccount = function() {
    var body = [
      '<div class="as-account-layout">',
      '<nav class="as-account-nav" aria-label="Account sections">',
      this.accountTabButton('profile', this.t('profile')),
      this.accountTabButton('organizations', this.t('organizations')),
      this.accountTabButton('enterprise', this.t('enterprise')),
      this.accountTabButton('audit', this.t('audit')),
      '</nav>',
      '<div id="account-pane" class="as-stack"></div>',
      '</div>'
    ].join('');
    this.shell(this.t('account'), 'Manage profile, MFA, passkeys, organizations, SSO, SCIM, and audit evidence.', body, '', true);
    this.bindAccountNav();
    this.mountAccountTab();
  };

  HostedAuth.prototype.accountTabButton = function(tab, label) {
    var active = this.state.activeAccountTab === tab;
    return '<button class="as-button ' + (active ? '' : 'secondary') + '" data-account-tab="' + tab + '" type="button" aria-selected="' + active + '">' + label + '</button>';
  };

  HostedAuth.prototype.bindAccountNav = function() {
    var self = this;
    var buttons = this.root.querySelectorAll('[data-account-tab]');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener('click', function(event) {
        self.state.activeAccountTab = event.currentTarget.getAttribute('data-account-tab');
        self.renderAccount();
      });
    }
  };

  HostedAuth.prototype.mountAccountTab = function() {
    var pane = this.root.querySelector('#account-pane');
    if (!pane) return;
    var tab = this.state.activeAccountTab;
    if (tab === 'profile') {
      this.state.mountedWidget = this.client.mountUserProfile(pane);
      return;
    }
    if (tab === 'organizations') {
      pane.innerHTML = '<div id="org-switcher"></div><div id="org-management"></div>';
      this.client.mountOrganizationSwitcher('#org-switcher');
      this.state.mountedWidget = this.client.mountOrganizationManagement('#org-management');
      return;
    }
    if (tab === 'enterprise') {
      this.mountAdminGate(pane, 'enterprise');
      return;
    }
    if (tab === 'audit') {
      this.mountAdminGate(pane, 'audit');
    }
  };

  HostedAuth.prototype.mountAdminGate = function(pane, kind) {
    var self = this;
    pane.innerHTML = [
      '<form class="as-grid as-grid-2" data-admin-gate>',
      '<div class="as-field"><label>Client ID</label><input data-client-id required></div>',
      '<div class="as-field"><label>Admin key</label><input data-admin-key type="password" required></div>',
      '<button class="as-button" type="submit">Load</button>',
      '</form>',
      '<div id="admin-widget"></div>'
    ].join('');
    pane.querySelector('[data-client-id]').value = this.clientID || '';
    pane.querySelector('[data-admin-key]').value = this.adminKey || '';
    pane.querySelector('[data-admin-gate]').addEventListener('submit', function(event) {
      event.preventDefault();
      self.clientID = value(pane, '[data-client-id]');
      self.adminKey = value(pane, '[data-admin-key]');
      self.client.adminKey = self.adminKey;
      self.setStored(STORAGE.clientID, self.clientID);
      self.setStored(STORAGE.adminKey, self.adminKey);
      self.mountAdminWidget(kind);
    });
    if (this.clientID && this.adminKey) this.mountAdminWidget(kind);
  };

  HostedAuth.prototype.mountAdminWidget = function(kind) {
    var target = this.root.querySelector('#admin-widget');
    if (!target) return;
    if (this.state.mountedWidget && this.state.mountedWidget.destroy) this.state.mountedWidget.destroy();
    if (kind === 'enterprise') {
      this.state.mountedWidget = this.client.mountEnterpriseSetup(target, { clientID: this.clientID, adminKey: this.adminKey });
    } else {
      this.state.mountedWidget = this.client.mountAuditLog(target, { clientID: this.clientID, adminKey: this.adminKey, limit: 50 });
    }
  };

  HostedAuth.prototype.completeAuth = function(data) {
    this.client.setSession(data || {});
    this.setMessage(this.t('success'), 'ok');
    var redirect = this.safeRedirect();
    if (redirect) {
      this.setFlashMessage(this.t('success'));
      root.location.assign(redirect);
      return data;
    }
    this.setFlashMessage(this.t('success'));
    root.location.assign(buildRelativeURL('account.html', this.params));
    return data;
  };

  HostedAuth.prototype.safeRedirect = function() {
    var candidate = this.redirectURL || this.ui.redirect_url || '';
    if (!candidate) return '';
    try {
      var parsed = new URL(candidate, root.location.origin);
      if (parsed.origin === root.location.origin) return parsed.href;
      var origins = this.config && this.config.client ? this.config.client.allowed_origins || [] : [];
      for (var i = 0; i < origins.length; i++) {
        if (new URL(origins[i], root.location.origin).origin === parsed.origin) return parsed.href;
      }
    } catch (err) {
      return '';
    }
    return '';
  };

  function viewFromPath(path) {
    if (/signup\.html$/.test(path)) return 'signup';
    if (/forgot-password\.html$/.test(path)) return 'forgot';
    if (/reset-password\.html$/.test(path)) return 'reset';
    if (/verify-email\.html$/.test(path)) return 'verify';
    if (/2fa\.html$/.test(path)) return 'mfa';
    if (/account\.html$/.test(path) || /profile\.html$/.test(path)) return 'account';
    return 'login';
  }

  function buildRelativeURL(path, params) {
    var next = new URLSearchParams();
    ['api_key', 'base_url', 'redirect_url', 'locale', 'providers', 'session_mode'].forEach(function(key) {
      if (params.get(key)) next.set(key, params.get(key));
    });
    var encoded = next.toString();
    return path + (encoded ? '?' + encoded : '');
  }

  function initHosted(options) {
    var rootEl = (options && options.root) || root.document.querySelector('[data-auth-hosted]') || root.document.getElementById('authservice-hosted');
    if (!rootEl) return null;
    var app = new HostedAuth(rootEl, options || {});
    app.start();
    return app;
  }

  root.AuthServiceUI = {
    HostedAuth: HostedAuth,
    initHosted: initHosted
  };

  if (root.document && root.document.readyState === 'loading') {
    root.document.addEventListener('DOMContentLoaded', function() { initHosted(); });
  } else if (root.document) {
    initHosted();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
