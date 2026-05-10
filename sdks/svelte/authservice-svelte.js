(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory;
  } else {
    root.AuthServiceSvelte = factory(root.AuthService);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createAuthServiceSvelte(AuthService) {
  'use strict';

  if (!AuthService) throw new Error('AuthService Svelte bindings require authservice.js');

  function createClient(options) {
    return options && options.client ? options.client : AuthService.createClient(options || {});
  }

  function action(method, defaultOptions) {
    defaultOptions = defaultOptions || {};
    return function(node, options) {
      var current = Object.assign({}, defaultOptions, options || {});
      var client = current.client || createClient(current);
      var widget = client[method](node, current);
      return {
        update: function(nextOptions) {
          current = Object.assign({}, defaultOptions, nextOptions || {});
          if (widget && widget.destroy) widget.destroy();
          client = current.client || createClient(current);
          widget = client[method](node, current);
        },
        destroy: function() {
          if (widget && widget.destroy) widget.destroy();
        }
      };
    };
  }

  return {
    auditLog: action('mountAuditLog'),
    enterpriseSetup: action('mountEnterpriseSetup'),
    organizationManagement: action('mountOrganizationManagement'),
    organizationSwitcher: action('mountOrganizationSwitcher'),
    signIn: action('mountSignIn'),
    signUp: action('mountSignUp'),
    userProfile: action('mountUserProfile'),
    createClient: createClient
  };
});
