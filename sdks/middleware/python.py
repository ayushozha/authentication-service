def permission_for(resource: str, action: str) -> str:
    resource = (resource or "").strip().lower()
    action = (action or "").strip().lower()
    return f"{resource}:{action}" if resource and action else ""


def is_authorized(claims: dict, resource: str, action: str) -> bool:
    claims = claims or {}
    if claims.get("org_role") == "owner":
        return True
    return permission_for(resource, action) in (claims.get("org_permissions") or [])


class AuthorizationError(PermissionError):
    pass


def require_authorization(claims: dict, resource: str, action: str) -> None:
    if not is_authorized(claims, resource, action):
        raise AuthorizationError("forbidden")


def fastapi_dependency(resource: str, action: str, claims_dependency):
    async def dependency(claims=claims_dependency):
        require_authorization(claims, resource, action)
        return claims

    return dependency


class WSGIAuthorizationMiddleware:
    def __init__(self, app, resource, action, claims_getter):
        self.app = app
        self.resource = resource
        self.action = action
        self.claims_getter = claims_getter

    def __call__(self, environ, start_response):
        claims = self.claims_getter(environ)
        if not is_authorized(claims, self.resource, self.action):
            start_response("403 Forbidden", [("Content-Type", "application/json")])
            return [b'{"error":"forbidden"}']
        return self.app(environ, start_response)
