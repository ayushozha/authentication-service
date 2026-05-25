package domain

import "time"

// ClientEmailConfig is a per-client override of the auth service's default
// email transport and URL templates. When no row exists for a client, the
// service falls back to the global env-var Resend config.
type ClientEmailConfig struct {
	ClientID                  string    `json:"client_id"`
	Provider                  string    `json:"provider"`
	APIKeyCiphertext          []byte    `json:"-"`
	APIKeyNonce               []byte    `json:"-"`
	APIKeyLastFour            string    `json:"api_key_last_four"`
	FromAddress               string    `json:"from_address"`
	FromName                  string    `json:"from_name"`
	ReplyTo                   string    `json:"reply_to,omitempty"`
	ResetPasswordURLTemplate  string    `json:"reset_password_url_template,omitempty"`
	VerifyEmailURLTemplate    string    `json:"verify_email_url_template,omitempty"`
	MagicLinkURLTemplate      string    `json:"magic_link_url_template,omitempty"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
}

// HasOwnTransport reports whether the config carries its own API key. Some
// configs may only override URL templates while letting the global Resend
// account handle delivery.
func (c *ClientEmailConfig) HasOwnTransport() bool {
	return c != nil && len(c.APIKeyCiphertext) > 0 && len(c.APIKeyNonce) > 0 && c.FromAddress != ""
}
