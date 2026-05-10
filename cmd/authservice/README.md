# AuthService CLI

Install locally:

```bash
go install github.com/Ayush10/authentication-service/cmd/authservice
```

Core workflows:

```bash
authservice --base-url https://auth.example.com --api-key "$AUTHSERVICE_API_KEY" login --email user@example.com --password "$PASSWORD"
authservice token inspect "$ACCESS_TOKEN" --jwks-url https://auth.example.com/.well-known/jwks.json --client-id "$CLIENT_ID" --token-use access
authservice --admin-key "$AUTHSERVICE_ADMIN_KEY" clients create --name "Acme App" --slug acme-app --allowed-origins https://app.acme.com
authservice --admin-key "$AUTHSERVICE_ADMIN_KEY" service-accounts create --client-id "$CLIENT_ID" --name worker --scopes jobs:read,jobs:write
authservice --admin-key "$AUTHSERVICE_ADMIN_KEY" sso setup --client-id "$CLIENT_ID" --name Okta --protocol oidc --domains acme.com --issuer https://acme.okta.com/oauth2/default --idp-client-id "$OKTA_CLIENT_ID" --idp-client-secret "$OKTA_CLIENT_SECRET"
authservice --admin-key "$AUTHSERVICE_ADMIN_KEY" scim setup --client-id "$CLIENT_ID" --name Okta --domains acme.com
authservice --admin-key "$AUTHSERVICE_ADMIN_KEY" audit export --client-id "$CLIENT_ID" --format jsonl --output audit.ndjson
authservice --admin-key "$AUTHSERVICE_ADMIN_KEY" key-rotation client-api-key "$CLIENT_ID"
```

Configuration can also come from `AUTHSERVICE_BASE_URL`, `AUTHSERVICE_API_KEY`, `AUTHSERVICE_ADMIN_KEY`, and `AUTHSERVICE_ACCESS_TOKEN`.
