package application

import (
	"context"
	"log"
	"net/url"
	"strings"

	"github.com/Ayush10/authentication-service/internal/domain"
)

// EmailURLBuilder resolves the URL that goes inside an outgoing auth email
// (password reset, email verification, magic link). If a client has set a
// custom URL template on its email config, the builder substitutes `{token}`
// into that template; otherwise it falls back to the auth service's hosted
// pages under BASE_URL.
//
// Per-client templates let downstream apps land users on their own domain
// (e.g. https://paervo.com/reset-password?t={token}) instead of the shared
// authservice.ayushojha.com hosted page.
type EmailURLBuilder struct {
	configs EmailConfigRepository
	baseURL string
}

func NewEmailURLBuilder(configs EmailConfigRepository, baseURL string) *EmailURLBuilder {
	return &EmailURLBuilder{configs: configs, baseURL: strings.TrimRight(baseURL, "/")}
}

func (b *EmailURLBuilder) ResetPasswordURL(ctx context.Context, clientID, token string) string {
	if tmpl := b.template(ctx, clientID, func(c *domain.ClientEmailConfig) string {
		return c.ResetPasswordURLTemplate
	}); tmpl != "" {
		return renderTokenTemplate(tmpl, token)
	}
	return b.baseURL + "/reset-password.html?token=" + url.QueryEscape(token)
}

func (b *EmailURLBuilder) VerifyEmailURL(ctx context.Context, clientID, token string) string {
	if tmpl := b.template(ctx, clientID, func(c *domain.ClientEmailConfig) string {
		return c.VerifyEmailURLTemplate
	}); tmpl != "" {
		return renderTokenTemplate(tmpl, token)
	}
	return b.baseURL + "/verify-email.html?token=" + url.QueryEscape(token)
}

func (b *EmailURLBuilder) MagicLinkURL(ctx context.Context, clientID, token string) string {
	if tmpl := b.template(ctx, clientID, func(c *domain.ClientEmailConfig) string {
		return c.MagicLinkURLTemplate
	}); tmpl != "" {
		return renderTokenTemplate(tmpl, token)
	}
	return b.baseURL + "/api/auth/magic-link/verify?token=" + url.QueryEscape(token)
}

func (b *EmailURLBuilder) template(ctx context.Context, clientID string, pick func(*domain.ClientEmailConfig) string) string {
	if b == nil || b.configs == nil || clientID == "" {
		return ""
	}
	cfg, err := b.configs.Get(ctx, clientID)
	if err != nil {
		log.Printf("email url builder: lookup config for client %s: %v", clientID, err)
		return ""
	}
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(pick(cfg))
}

// renderTokenTemplate substitutes {token} with the URL-escaped token value.
// Any other placeholders are left untouched so the template author can keep
// static query strings (?utm_source=auth&token={token}).
func renderTokenTemplate(tmpl, token string) string {
	return strings.ReplaceAll(tmpl, "{token}", url.QueryEscape(token))
}
