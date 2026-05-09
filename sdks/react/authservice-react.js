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

  function AuthServiceProvider(props) {
    var client = React.useMemo(function() {
      return props.client || AuthService.createClient(props);
    }, [props.client, props.baseUrl, props.apiKey, props.sessionMode]);
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

  function SignIn(props) {
    props = props || {};
    var auth = useAuthService();
    var emailState = React.useState('');
    var email = emailState[0];
    var setEmail = emailState[1];
    var passwordState = React.useState('');
    var password = passwordState[0];
    var setPassword = passwordState[1];
    var twoFactorState = React.useState('');
    var twoFactorToken = twoFactorState[0];
    var setTwoFactorToken = twoFactorState[1];
    var codeState = React.useState('');
    var code = codeState[0];
    var setCode = codeState[1];
    var recoveryState = React.useState(false);
    var useRecoveryCode = recoveryState[0];
    var setUseRecoveryCode = recoveryState[1];
    var errorState = React.useState('');
    var error = errorState[0];
    var setError = errorState[1];
    var busyState = React.useState(false);
    var busy = busyState[0];
    var setBusy = busyState[1];

    function complete(data) {
      return auth.refreshUser().then(function() {
        if (props.onSuccess) props.onSuccess(data);
      });
    }

    function submit(event) {
      event.preventDefault();
      setBusy(true);
      setError('');
      var work;
      if (twoFactorToken) {
        var payload = { two_factor_token: twoFactorToken, code: code };
        work = useRecoveryCode ? auth.client.verifyRecoveryCode(payload) : auth.client.verifyTOTP(payload);
      } else {
        work = auth.client.login({ email: email, password: password });
      }
      work.then(function(data) {
        if (data && data.requires_2fa) {
          setTwoFactorToken(data.two_factor_token);
          return;
        }
        return complete(data);
      }).catch(function(err) {
        setError(err.message || 'Sign in failed');
        if (props.onError) props.onError(err);
      }).finally(function() {
        setBusy(false);
      });
    }

    return React.createElement('form', { className: props.className || 'authservice-signin', onSubmit: submit },
      error ? React.createElement('div', { role: 'alert' }, error) : null,
      twoFactorToken ? null : React.createElement('input', {
        type: 'email',
        autoComplete: 'username webauthn',
        value: email,
        placeholder: props.emailPlaceholder || 'Email',
        onChange: function(event) { setEmail(event.target.value); }
      }),
      twoFactorToken ? null : React.createElement('input', {
        type: 'password',
        autoComplete: 'current-password',
        value: password,
        placeholder: props.passwordPlaceholder || 'Password',
        onChange: function(event) { setPassword(event.target.value); }
      }),
      twoFactorToken ? React.createElement('input', {
        type: 'text',
        autoComplete: 'one-time-code',
        value: code,
        placeholder: useRecoveryCode ? 'Recovery code' : 'Authenticator code',
        onChange: function(event) { setCode(event.target.value); }
      }) : null,
      twoFactorToken ? React.createElement('button', {
        type: 'button',
        onClick: function() { setUseRecoveryCode(!useRecoveryCode); }
      }, useRecoveryCode ? 'Use authenticator code' : 'Use recovery code') : null,
      React.createElement('button', { type: 'submit', disabled: busy }, busy ? 'Working...' : twoFactorToken ? 'Verify' : 'Sign in')
    );
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

  function OrganizationList(props) {
    props = props || {};
    var auth = useAuthService();
    var state = React.useState([]);
    var orgs = state[0];
    var setOrgs = state[1];
    React.useEffect(function() {
      auth.client.listOrganizations().then(function(data) {
        setOrgs(data.organizations || []);
      }).catch(function() {
        setOrgs([]);
      });
    }, [auth.client]);
    return React.createElement('div', { className: props.className || 'authservice-org-list' },
      orgs.map(function(row) {
        var org = row.organization || row;
        return React.createElement('button', {
          key: org.id,
          type: 'button',
          onClick: function() {
            if (props.onSelect) props.onSelect(row);
          }
        }, org.name || org.slug || org.id);
      })
    );
  }

  return {
    AuthServiceContext: AuthServiceContext,
    AuthServiceProvider: AuthServiceProvider,
    OrganizationList: OrganizationList,
    SignIn: SignIn,
    UserButton: UserButton,
    useAuthService: useAuthService
  };
});
