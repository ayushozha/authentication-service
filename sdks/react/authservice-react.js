(function(root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory;
  } else {
    root.AuthServiceReact = factory(root.React, root.AuthService);
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function createAuthServiceReact(React, AuthService) {
  'use strict';

  if (!React) throw new Error('AuthService React bindings require React');
  if (!AuthService) throw new Error('AuthService React bindings require authservice.js');

  var AuthServiceContext = React.createContext(null);

  function useAuthService() {
    var value = React.useContext(AuthServiceContext);
    if (!value) throw new Error('useAuthService must be used inside AuthServiceProvider');
    return value;
  }

  function useAccessClaims() {
    var auth = useAuthService();
    var token = auth.client.getAccessToken ? auth.client.getAccessToken() : '';
    return React.useMemo(function() {
      return auth.client.getAccessClaims ? auth.client.getAccessClaims(token) : null;
    }, [auth.client, token]);
  }

  function useOrganizationPermission(permission) {
    var auth = useAuthService();
    var claims = useAccessClaims();
    return React.useMemo(function() {
      if (!auth.client.hasOrganizationPermission) return false;
      return auth.client.hasOrganizationPermission(permission, claims);
    }, [auth.client, claims, permission]);
  }

  function useOIDCCallback(options) {
    options = options || {};
    var auth = useAuthService();
    var state = React.useState({ loading: false, error: null, result: null });
    var callbackState = state[0];
    var setCallbackState = state[1];
    var handleCallback = React.useCallback(function(override) {
      if (!auth.client.handleOIDCCallback) {
        var missing = new Error('OIDC callback helpers require an updated authservice.js client');
        setCallbackState({ loading: false, error: missing, result: null });
        return Promise.reject(missing);
      }
      setCallbackState({ loading: true, error: null, result: null });
      return auth.client.handleOIDCCallback(Object.assign({}, options, override || {})).then(function(result) {
        setCallbackState({ loading: false, error: null, result: result });
        if (auth.refreshUser) auth.refreshUser();
        return result;
      }).catch(function(error) {
        setCallbackState({ loading: false, error: error, result: null });
        throw error;
      });
    }, [auth, options]);
    return Object.assign({ handleCallback: handleCallback }, callbackState);
  }

  function AuthServiceProvider(props) {
    var client = React.useMemo(function() {
      return props.client || AuthService.createClient(props);
    }, [props.client, props.baseUrl, props.apiKey, props.adminKey, props.clientId, props.oidcClientId, props.sessionMode]);
    var state = React.useState(null);
    var user = state[0];
    var setUser = state[1];
    var loadingState = React.useState(false);
    var loading = loadingState[0];
    var setLoading = loadingState[1];

    var refreshUser = React.useCallback(function() {
      if (!client.getAccessToken()) {
        setUser(null);
        return Promise.resolve(null);
      }
      setLoading(true);
      return client.me().then(function(nextUser) {
        setUser(nextUser);
        return nextUser;
      }).catch(function() {
        setUser(null);
        return null;
      }).finally(function() {
        setLoading(false);
      });
    }, [client]);

    React.useEffect(function() {
      refreshUser();
    }, [refreshUser]);

    var value = React.useMemo(function() {
      return {
        client: client,
        user: user,
        loading: loading,
        isSignedIn: !!user,
        refreshUser: refreshUser,
        signOut: function() {
          return client.logout().finally(function() {
            setUser(null);
          });
        }
      };
    }, [client, user, loading, refreshUser]);

    return React.createElement(AuthServiceContext.Provider, { value: value }, props.children);
  }

  function useMountedWidget(method, props, afterSuccessRefresh) {
    props = props || {};
    var auth = useAuthService();
    var ref = React.useRef(null);
    React.useEffect(function() {
      if (!ref.current || !auth.client[method]) return undefined;
      var widgetProps = {};
      Object.keys(props).forEach(function(key) {
        if (key !== 'className' && key !== 'style') widgetProps[key] = props[key];
      });
      var userSuccess = widgetProps.onSuccess;
      if (afterSuccessRefresh) {
        widgetProps.onSuccess = function(data) {
          return auth.refreshUser().then(function() {
            if (userSuccess) return userSuccess(data);
            return data;
          });
        };
      }
      var widget = auth.client[method](ref.current, widgetProps);
      return function() {
        if (widget && widget.destroy) widget.destroy();
      };
    }, [auth.client, method, props.refreshKey]);
    return ref;
  }

  function SignIn(props) {
    var ref = useMountedWidget('mountSignIn', props, true);
    return React.createElement('div', { ref: ref, className: props && props.className, style: props && props.style });
  }

  function SignUp(props) {
    var ref = useMountedWidget('mountSignUp', props, true);
    return React.createElement('div', { ref: ref, className: props && props.className, style: props && props.style });
  }

  function UserProfile(props) {
    var ref = useMountedWidget('mountUserProfile', props, false);
    return React.createElement('div', { ref: ref, className: props && props.className, style: props && props.style });
  }

  function OrganizationSwitcher(props) {
    var ref = useMountedWidget('mountOrganizationSwitcher', props, false);
    return React.createElement('div', { ref: ref, className: props && props.className, style: props && props.style });
  }

  function OrganizationManagement(props) {
    var ref = useMountedWidget('mountOrganizationManagement', props, false);
    return React.createElement('div', { ref: ref, className: props && props.className, style: props && props.style });
  }

  function EnterpriseSetup(props) {
    var ref = useMountedWidget('mountEnterpriseSetup', props, false);
    return React.createElement('div', { ref: ref, className: props && props.className, style: props && props.style });
  }

  function AuditLog(props) {
    var ref = useMountedWidget('mountAuditLog', props, false);
    return React.createElement('div', { ref: ref, className: props && props.className, style: props && props.style });
  }

  function UserButton(props) {
    props = props || {};
    var auth = useAuthService();
    if (auth.loading) return React.createElement('span', null, props.loadingText || 'Loading');
    if (!auth.user) return React.createElement('button', { type: 'button', onClick: props.onSignIn }, props.signedOutText || 'Sign in');
    return React.createElement('button', {
      type: 'button',
      onClick: function() {
        auth.signOut();
        if (props.onSignOut) props.onSignOut();
      }
    }, props.label || auth.user.display_name || auth.user.email || 'Account');
  }

  function SignedIn(props) {
    var auth = useAuthService();
    return auth.user ? React.createElement(React.Fragment, null, props.children) : null;
  }

  function SignedOut(props) {
    var auth = useAuthService();
    return auth.user ? null : React.createElement(React.Fragment, null, props.children);
  }

  function Protect(props) {
    var auth = useAuthService();
    var claims = useAccessClaims();
    var allowed = !!auth.user;
    if (props.permission) allowed = auth.client.hasOrganizationPermission(props.permission, claims);
    if (props.scope) allowed = auth.client.hasScope(props.scope, claims);
    if (!allowed) return props.fallback || null;
    return React.createElement(React.Fragment, null, props.children);
  }

  return {
    AuthServiceContext: AuthServiceContext,
    AuthServiceProvider: AuthServiceProvider,
    AuditLog: AuditLog,
    EnterpriseSetup: EnterpriseSetup,
    OrganizationList: OrganizationSwitcher,
    OrganizationManagement: OrganizationManagement,
    OrganizationSwitcher: OrganizationSwitcher,
    Protect: Protect,
    SignIn: SignIn,
    SignUp: SignUp,
    SignedIn: SignedIn,
    SignedOut: SignedOut,
    UserButton: UserButton,
    UserProfile: UserProfile,
    useAccessClaims: useAccessClaims,
    useAuthService: useAuthService,
    useOIDCCallback: useOIDCCallback,
    useOrganizationPermission: useOrganizationPermission
  };
});
