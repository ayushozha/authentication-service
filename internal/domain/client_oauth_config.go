package domain

import "time"

// ClientOAuthConfig is a per-client override of an OAuth provider's
// application credentials. When a row exists for a (client_id, provider)
// pair, the auth service uses these credentials (the client's own OAuth App)
// instead of the global env-var fallback, so the provider's consent screen
// shows the client's own app name and logo.
//
// The redirect/callback URL is never stored: it is derived from BASE_URL.
type ClientOAuthConfig struct {
	ClientID               string    `json:"client_id"`
	Provider               string    `json:"provider"`
	ClientIDPlain          string    `json:"oauth_client_id"`
	ClientSecretCiphertext []byte    `json:"-"`
	ClientSecretNonce      []byte    `json:"-"`
	SecretLastFour         string    `json:"secret_last_four"`
	Scopes                 string    `json:"scopes,omitempty"`
	Enabled                bool      `json:"enabled"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

// IsUsable reports whether the config carries enough to drive a login flow:
// it must be enabled and carry both an OAuth client id and an encrypted
// secret. Otherwise the resolver falls back to the global env config.
func (c *ClientOAuthConfig) IsUsable() bool {
	return c != nil && c.Enabled && c.ClientIDPlain != "" &&
		len(c.ClientSecretCiphertext) > 0 && len(c.ClientSecretNonce) > 0
}
