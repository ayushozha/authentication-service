import json
from urllib.parse import urlencode

import requests


class AuthServiceError(Exception):
    def __init__(self, message, status=0, response=None):
        super().__init__(message)
        self.status = status
        self.response = response


class MemoryTokenStore:
    def __init__(self):
        self.access_token = ""
        self.refresh_token = ""

    def get_access_token(self):
        return self.access_token or None

    def set_access_token(self, token=None):
        self.access_token = token or ""

    def get_refresh_token(self):
        return self.refresh_token or None

    def set_refresh_token(self, token=None):
        self.refresh_token = token or ""


class AuthServiceClient:
    def __init__(self, base_url, api_key=None, admin_key=None, session_mode="token", token_store=None, session=None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.admin_key = admin_key
        self.session_mode = session_mode
        self.token_store = token_store or MemoryTokenStore()
        self.session = session or requests.Session()

    def request(self, path, method="GET", body=None, headers=None, admin=False, auth=True):
        headers = dict(headers or {})
        if admin and self.admin_key:
            headers["X-Admin-Key"] = self.admin_key
        elif self.api_key:
            headers["X-API-Key"] = self.api_key
        token = self.token_store.get_access_token()
        if auth and token:
            headers["Authorization"] = "Bearer " + token
        data = None
        if body is not None:
            if isinstance(body, str):
                data = body
            else:
                headers.setdefault("Content-Type", "application/json")
                data = json.dumps(body)
        response = self.session.request(method, self.base_url + path, headers=headers, data=data)
        text = response.text
        try:
            payload = response.json() if text else None
        except ValueError:
            payload = text
        if response.status_code >= 400:
            message = payload.get("error") if isinstance(payload, dict) and payload.get("error") else response.reason
            raise AuthServiceError(message, response.status_code, payload)
        return payload

    def _with_session_mode(self, body=None):
        body = dict(body or {})
        if self.session_mode == "token" and "session_mode" not in body:
            body["session_mode"] = "token"
        return body

    def _persist(self, payload):
        if isinstance(payload, dict):
            if payload.get("access_token"):
                self.token_store.set_access_token(payload["access_token"])
            if payload.get("refresh_token"):
                self.token_store.set_refresh_token(payload["refresh_token"])
        return payload

    def signup(self, **params):
        return self._persist(self.request("/api/auth/signup", "POST", self._with_session_mode(params), auth=False))

    def login(self, **params):
        return self._persist(self.request("/api/auth/login", "POST", self._with_session_mode(params), auth=False))

    def refresh(self, **params):
        body = self._with_session_mode(params)
        if self.session_mode == "token" and not body.get("refresh_token"):
            body["refresh_token"] = self.token_store.get_refresh_token()
        return self._persist(self.request("/api/auth/refresh", "POST", body, auth=False))

    def logout(self):
        try:
            return self.request("/api/auth/logout", "POST", {"refresh_token": self.token_store.get_refresh_token()}, auth=False)
        finally:
            self.token_store.set_access_token()
            self.token_store.set_refresh_token()

    def me(self):
        return self.request("/api/auth/me")

    def update_profile(self, **params):
        return self.request("/api/auth/me", "PATCH", params)

    def list_organizations(self):
        return self.request("/api/auth/organizations")

    def create_organization(self, **params):
        return self.request("/api/auth/organizations", "POST", params)

    def organization_token(self, organization_id, activate=False):
        payload = self.request(f"/api/auth/organizations/{organization_id}/token", "POST", {})
        if activate and isinstance(payload, dict) and payload.get("access_token"):
            self.token_store.set_access_token(payload["access_token"])
        return payload

    def client_credentials(self, client_id, client_secret, scope=None):
        body = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
        if scope:
            body["scope"] = scope
        return self.request("/oauth/token", "POST", urlencode(body), {"Content-Type": "application/x-www-form-urlencoded"}, auth=False)

    def introspect(self, token):
        return self.request("/oauth/introspect", "POST", urlencode({"token": token}), {"Content-Type": "application/x-www-form-urlencoded"}, auth=False)

    def list_clients(self):
        return self.request("/api/admin/clients", admin=True, auth=False)

    def create_client(self, **params):
        return self.request("/api/admin/clients", "POST", params, admin=True, auth=False)

    def update_client(self, client_id, **params):
        return self.request(f"/api/admin/clients/{client_id}", "PATCH", params, admin=True, auth=False)

    def rotate_client_api_key(self, client_id):
        return self.request(f"/api/admin/clients/{client_id}/rotate-api-key", "POST", admin=True, auth=False)

    def rotate_client_jwt_secret(self, client_id):
        return self.request(f"/api/admin/clients/{client_id}/rotate-jwt", "POST", admin=True, auth=False)

    def list_service_accounts(self, client_id):
        return self.request(f"/api/admin/clients/{client_id}/service-accounts", admin=True, auth=False)

    def create_service_account(self, client_id, **params):
        return self.request(f"/api/admin/clients/{client_id}/service-accounts", "POST", params, admin=True, auth=False)

    def create_sso_connection(self, client_id, **params):
        return self.request(f"/api/admin/clients/{client_id}/sso-connections", "POST", params, admin=True, auth=False)

    def create_scim_directory(self, client_id, **params):
        return self.request(f"/api/admin/clients/{client_id}/scim-directories", "POST", params, admin=True, auth=False)

    def audit_export(self, **params):
        return self.request("/api/admin/audit-events/export?" + urlencode(params), admin=True, auth=False)
