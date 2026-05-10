'use strict';

function base64urlDecode(value) {
  value = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  while (value.length % 4) value += '=';
  if (typeof Buffer !== 'undefined') return Buffer.from(value, 'base64').toString('utf8');
  return atob(value);
}

function base64urlBytes(value) {
  value = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  while (value.length % 4) value += '=';
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(value, 'base64'));
  var raw = atob(value);
  var out = new Uint8Array(raw.length);
  for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function decodeJwt(token) {
  try {
    var parts = String(token || '').split('.');
    if (parts.length < 2) return null;
    return JSON.parse(base64urlDecode(parts[1]));
  } catch (err) {
    return null;
  }
}

function decodeHeader(token) {
  try {
    var parts = String(token || '').split('.');
    if (parts.length < 2) return null;
    return JSON.parse(base64urlDecode(parts[0]));
  } catch (err) {
    return null;
  }
}

function textBytes(value) {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(value);
  return new Uint8Array(Buffer.from(value));
}

async function importRSAKey(jwk) {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error('Web Crypto is required to verify RS256 JWTs');
  }
  return globalThis.crypto.subtle.importKey(
    'jwk',
    Object.assign({}, jwk, { alg: 'RS256', ext: true }),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
}

async function fetchJWKS(jwksUrl, fetchImpl) {
  var res = await (fetchImpl || fetch)(jwksUrl, { cache: 'force-cache' });
  if (!res.ok) throw new Error('Could not load AuthService JWKS');
  return res.json();
}

async function verifyJWT(token, options) {
  options = options || {};
  var header = decodeHeader(token);
  var claims = decodeJwt(token);
  if (!header || !claims) return null;
  if (header.alg !== 'RS256') {
    if (options.allowUnverifiedHS256) return claims;
    throw new Error('Only RS256 JWT verification is supported by the Next.js helper');
  }

  var now = Math.floor(Date.now() / 1000);
  if (claims.exp && claims.exp < now) return null;
  if (claims.nbf && claims.nbf > now) return null;
  if (options.clientId && claims.client_id !== options.clientId) return null;
  if (options.issuer && claims.iss !== options.issuer) return null;
  if (options.audience) {
    var aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (aud.indexOf(options.audience) === -1) return null;
  }

  var jwksUrl = options.jwksUrl || (String(options.baseUrl || '').replace(/\/+$/, '') + '/.well-known/jwks.json' + (options.clientId ? '?client_id=' + encodeURIComponent(options.clientId) : ''));
  var jwks = await fetchJWKS(jwksUrl, options.fetch);
  var keys = jwks.keys || [];
  var jwk = null;
  for (var i = 0; i < keys.length; i++) {
    if (!header.kid || keys[i].kid === header.kid) {
      jwk = keys[i];
      break;
    }
  }
  if (!jwk) return null;
  var key = await importRSAKey(jwk);
  var parts = token.split('.');
  var valid = await globalThis.crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    key,
    base64urlBytes(parts[2]),
    textBytes(parts[0] + '.' + parts[1])
  );
  return valid ? claims : null;
}

function cookieValue(cookies, name) {
  if (!cookies) return '';
  if (typeof cookies.get === 'function') {
    var value = cookies.get(name);
    return value && typeof value === 'object' ? value.value : value || '';
  }
  return cookies[name] || '';
}

function tokenFromRequest(request, options) {
  options = options || {};
  var cookieName = options.tokenCookie || 'auth_access_token';
  var auth = request && request.headers && request.headers.get ? request.headers.get('authorization') : '';
  if (auth && /^bearer /i.test(auth)) return auth.replace(/^bearer /i, '');
  if (request && request.cookies) return cookieValue(request.cookies, cookieName);
  return '';
}

async function loadSession(request, options) {
  options = options || {};
  var token = options.token || tokenFromRequest(request, options);
  if (!token) return { user: null, claims: null, accessToken: '' };
  var claims = options.verify === false ? decodeJwt(token) : await verifyJWT(token, options);
  if (!claims) return { user: null, claims: null, accessToken: '' };

  if (options.loadUser === false) {
    return { user: null, claims: claims, accessToken: token };
  }

  var baseUrl = String(options.baseUrl || '').replace(/\/+$/, '');
  if (!baseUrl || !options.apiKey) {
    return { user: null, claims: claims, accessToken: token };
  }
  var res = await (options.fetch || fetch)(baseUrl + '/api/auth/me', {
    headers: {
      Authorization: 'Bearer ' + token,
      'X-API-Key': options.apiKey
    },
    cache: 'no-store'
  });
  if (!res.ok) return { user: null, claims: claims, accessToken: token };
  return { user: await res.json(), claims: claims, accessToken: token };
}

function createRouteGuard(options) {
  options = options || {};
  return async function requireAuth(request) {
    var session = await loadSession(request, options);
    if (!session.claims) {
      return {
        ok: false,
        redirect: options.loginPath || '/login',
        session: session
      };
    }
    if (options.permission && session.claims.org_role !== 'owner') {
      var permissions = session.claims.org_permissions || [];
      if (permissions.indexOf(options.permission) === -1) {
        return { ok: false, status: 403, session: session };
      }
    }
    return { ok: true, session: session };
  };
}

function pathIsPublic(pathname, publicRoutes) {
  publicRoutes = publicRoutes || [];
  for (var i = 0; i < publicRoutes.length; i++) {
    var route = publicRoutes[i];
    if (route instanceof RegExp && route.test(pathname)) return true;
    if (typeof route === 'string' && (pathname === route || pathname.indexOf(route + '/') === 0)) return true;
  }
  return false;
}

function createMiddleware(options) {
  options = options || {};
  var guard = createRouteGuard(options);
  return async function authMiddleware(request) {
    var pathname = request.nextUrl ? request.nextUrl.pathname : new URL(request.url).pathname;
    if (pathIsPublic(pathname, options.publicRoutes || [])) {
      return options.NextResponse ? options.NextResponse.next() : undefined;
    }
    var result = await guard(request);
    if (result.ok) {
      if (options.NextResponse) {
        var next = options.NextResponse.next();
        if (result.session.claims && result.session.claims.sub) next.headers.set('x-auth-user-id', result.session.claims.sub);
        return next;
      }
      return undefined;
    }
    var loginURL = new URL(result.redirect || options.loginPath || '/login', request.url);
    loginURL.searchParams.set('redirect_url', request.url);
    return options.NextResponse ? options.NextResponse.redirect(loginURL) : Response.redirect(loginURL);
  };
}

module.exports = {
  createMiddleware: createMiddleware,
  createRouteGuard: createRouteGuard,
  decodeJwt: decodeJwt,
  loadSession: loadSession,
  tokenFromRequest: tokenFromRequest,
  verifyJWT: verifyJWT
};
