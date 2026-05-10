import hmac
import time
from hashlib import sha256

import jwt
from jwt import PyJWKClient


def has_scope(claims, scope):
    scopes = claims.get("scopes")
    if not isinstance(scopes, list):
        scopes = str(claims.get("scope", "")).split()
    return scope in scopes


def has_org_permission(claims, permission):
    if claims.get("org_role") == "owner":
        return True
    permissions = claims.get("org_permissions") or []
    return permission in permissions


class AuthServiceJwtVerifier:
    def __init__(self, jwks_url, issuer=None, audience=None, client_id=None, token_use=None, required_scopes=None, required_org_permissions=None, leeway=60):
        self.jwks = PyJWKClient(jwks_url)
        self.issuer = issuer
        self.audience = audience
        self.client_id = client_id
        self.token_use = token_use
        self.required_scopes = required_scopes or []
        self.required_org_permissions = required_org_permissions or []
        self.leeway = leeway

    def verify(self, token):
        key = self.jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(token, key.key, algorithms=["RS256"], issuer=self.issuer, audience=self.audience, leeway=self.leeway)
        if self.client_id and claims.get("client_id") != self.client_id:
            raise jwt.InvalidTokenError("token client mismatch")
        if self.token_use and claims.get("token_use") != self.token_use:
            raise jwt.InvalidTokenError("token_use mismatch")
        for scope in self.required_scopes:
            if not has_scope(claims, scope):
                raise jwt.InvalidTokenError("missing required scope: " + scope)
        for permission in self.required_org_permissions:
            if not has_org_permission(claims, permission):
                raise jwt.InvalidTokenError("missing required organization permission: " + permission)
        return claims


def verify_webhook_signature(secret, timestamp, signature, body, tolerance_seconds=300):
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(int(time.time()) - ts) > tolerance_seconds:
        return False
    if isinstance(body, str):
        body = body.encode()
    expected = "v1=" + hmac.new(secret.encode(), timestamp.encode() + b"." + body, sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")
