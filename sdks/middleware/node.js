'use strict';

function permissionFor(resource, action) {
  resource = String(resource || '').trim().toLowerCase();
  action = String(action || '').trim().toLowerCase();
  return resource && action ? resource + ':' + action : '';
}

function isAuthorized(claims, resource, action) {
  claims = claims || {};
  if (claims.org_role === 'owner') return true;
  const permission = permissionFor(resource, action);
  return Array.isArray(claims.org_permissions) && claims.org_permissions.includes(permission);
}

function requireAuthorization(resource, action, options) {
  options = options || {};
  const getClaims = options.getClaims || ((req) => req.auth || req.user || req.claims);
  const onDenied = options.onDenied || ((req, res) => res.status(403).json({ error: 'forbidden' }));

  return function authServiceAuthorizationMiddleware(req, res, next) {
    if (!isAuthorized(getClaims(req), resource, action)) {
      return onDenied(req, res, next);
    }
    return next();
  };
}

module.exports = {
  permissionFor,
  isAuthorized,
  requireAuthorization
};
