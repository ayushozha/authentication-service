(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory;
  } else {
    root.AuthServiceVue = factory(root.AuthService);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createAuthServiceVue(AuthService) {
  'use strict';

  if (!AuthService) throw new Error('AuthService Vue bindings require authservice.js');

  var injectionKey = 'AuthServiceVue';

  function createAuthServicePlugin(options) {
    var client = options && options.client ? options.client : AuthService.createClient(options || {});
    return {
      install: function(app) {
        app.provide(injectionKey, client);
        app.config.globalProperties.$authService = client;
      },
      client: client
    };
  }

  function useAuthService(inject) {
    if (!inject) throw new Error('Pass Vue inject to useAuthService(inject)');
    var client = inject(injectionKey);
    if (!client) throw new Error('AuthService plugin is not installed');
    return client;
  }

  function widgetComponent(name, method) {
    return {
      name: name,
      props: {
        options: { type: Object, default: function() { return {}; } }
      },
      inject: [injectionKey],
      mounted: function() {
        var client = this[injectionKey];
        this.__authWidget = client[method](this.$el, this.options || {});
      },
      beforeUnmount: function() {
        if (this.__authWidget && this.__authWidget.destroy) this.__authWidget.destroy();
      },
      template: '<div></div>'
    };
  }

  return {
    AuditLog: widgetComponent('AuthServiceAuditLog', 'mountAuditLog'),
    EnterpriseSetup: widgetComponent('AuthServiceEnterpriseSetup', 'mountEnterpriseSetup'),
    OrganizationManagement: widgetComponent('AuthServiceOrganizationManagement', 'mountOrganizationManagement'),
    OrganizationSwitcher: widgetComponent('AuthServiceOrganizationSwitcher', 'mountOrganizationSwitcher'),
    SignIn: widgetComponent('AuthServiceSignIn', 'mountSignIn'),
    SignUp: widgetComponent('AuthServiceSignUp', 'mountSignUp'),
    UserProfile: widgetComponent('AuthServiceUserProfile', 'mountUserProfile'),
    createAuthServicePlugin: createAuthServicePlugin,
    injectionKey: injectionKey,
    useAuthService: useAuthService
  };
});
