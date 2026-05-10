# AuthService Terraform Provider

Repeatable provisioning for AuthService clients, service accounts, SSO connections, SCIM directories, and organizations.

## Provider

```hcl
provider "authservice" {
  base_url     = "https://auth.example.com"
  admin_key    = var.authservice_admin_key
  api_key      = var.authservice_api_key
  access_token = var.authservice_access_token
}
```

`admin_key` is required for client, service-account, SSO, and SCIM resources. `api_key` plus `access_token` are required for organization resources because organization APIs are user-authorized.

## Example

```hcl
resource "authservice_client" "app" {
  name            = "Acme App"
  slug            = "acme-app"
  allowed_origins = ["https://app.acme.com"]
  webhook_url     = "https://app.acme.com/webhooks/auth"
}

resource "authservice_service_account" "worker" {
  client_id   = authservice_client.app.id
  name        = "worker"
  description = "Background jobs"
  scopes      = ["jobs:read", "jobs:write"]
}

resource "authservice_scim_directory" "okta" {
  client_id = authservice_client.app.id
  name      = "Okta"
  domains   = ["acme.com"]
}

resource "authservice_sso_connection" "okta_oidc" {
  client_id = authservice_client.app.id
  name      = "Okta OIDC"
  protocol  = "oidc"
  domains   = ["acme.com"]
  oidc = {
    issuer        = "https://acme.okta.com/oauth2/default"
    client_id     = var.okta_client_id
    client_secret = var.okta_client_secret
  }
}
```
