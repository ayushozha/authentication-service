from .jwt import AuthServiceJwtVerifier


def _bearer(header):
    parts = str(header or "").split(" ", 1)
    return parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else ""


def fastapi_dependency(verifier: AuthServiceJwtVerifier):
    async def dependency(request):
        claims = verifier.verify(_bearer(request.headers.get("authorization")))
        request.state.authservice = claims
        return claims
    return dependency


def flask_before_request(verifier: AuthServiceJwtVerifier):
    def middleware():
        from flask import g, request
        g.authservice = verifier.verify(_bearer(request.headers.get("authorization")))
    return middleware


class DjangoAuthServiceMiddleware:
    def __init__(self, get_response, verifier: AuthServiceJwtVerifier):
        self.get_response = get_response
        self.verifier = verifier

    def __call__(self, request):
        request.authservice = self.verifier.verify(_bearer(request.headers.get("authorization")))
        return self.get_response(request)
