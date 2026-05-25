package email

import (
	"context"
	"log"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

// RouterMailer is the production application.EmailSender. For each outgoing
// email it picks between:
//
//  1. A per-client override (decrypted Resend key + the client's own
//     from-address) if one is configured in client_email_configs.
//  2. The auth service's global fallback transport, built from
//     RESEND_API_KEY / EMAIL_FROM_ADDRESS / EMAIL_FROM_NAME env vars.
//
// If neither is available, sends return ErrEmailNotConfigured. Callers
// (forgot-password, magic-link) are expected to fail-soft and not leak that
// fact to the caller — they already log-and-swallow to preserve enumeration
// resistance.
type RouterMailer struct {
	configs  application.EmailConfigRepository
	crypto   *SecretCrypto
	fallback *resendTransport
}

// NewRouterMailer wires the router. fallbackAPIKey / fallbackFrom may be
// empty: in that case the router refuses to deliver for any client that
// hasn't configured its own transport, which matches the legacy behavior
// when RESEND_API_KEY was unset.
func NewRouterMailer(configs application.EmailConfigRepository, crypto *SecretCrypto, fallbackAPIKey, fallbackFrom, fallbackReplyTo string) *RouterMailer {
	return &RouterMailer{
		configs:  configs,
		crypto:   crypto,
		fallback: newResendTransport(fallbackAPIKey, fallbackFrom, fallbackReplyTo),
	}
}

func (m *RouterMailer) Send(ctx context.Context, clientID, to, subject, htmlBody string) error {
	t := m.transportFor(ctx, clientID)
	if t == nil {
		return domain.ErrEmailNotConfigured
	}
	return t.Send(to, subject, htmlBody)
}

func (m *RouterMailer) SendVerifyEmail(ctx context.Context, clientID, to, displayName, verifyURL string) error {
	t := m.transportFor(ctx, clientID)
	if t == nil {
		return domain.ErrEmailNotConfigured
	}
	return t.SendVerifyEmail(to, displayName, verifyURL)
}

func (m *RouterMailer) SendPasswordReset(ctx context.Context, clientID, to, displayName, resetURL string) error {
	t := m.transportFor(ctx, clientID)
	if t == nil {
		return domain.ErrEmailNotConfigured
	}
	return t.SendPasswordReset(to, displayName, resetURL)
}

func (m *RouterMailer) SendMagicLink(ctx context.Context, clientID, to, magicURL string) error {
	t := m.transportFor(ctx, clientID)
	if t == nil {
		return domain.ErrEmailNotConfigured
	}
	return t.SendMagicLink(to, magicURL)
}

// transportFor resolves the per-client transport, falling back to the global
// one. A nil return means there's no way to deliver mail for this client.
func (m *RouterMailer) transportFor(ctx context.Context, clientID string) *resendTransport {
	if m == nil {
		return nil
	}
	if cfg := m.lookupConfig(ctx, clientID); cfg != nil && cfg.HasOwnTransport() {
		if m.crypto == nil {
			log.Printf("router mailer: client %s has own transport but EMAIL_CONFIG_KMS_KEY is not set; falling back", clientID)
		} else {
			apiKey, err := m.crypto.Decrypt(cfg.APIKeyCiphertext, cfg.APIKeyNonce)
			if err != nil {
				log.Printf("router mailer: decrypt api key for client %s: %v; falling back", clientID, err)
			} else {
				from := cfg.FromAddress
				if cfg.FromName != "" {
					from = cfg.FromName + " <" + cfg.FromAddress + ">"
				}
				if t := newResendTransport(apiKey, from, cfg.ReplyTo); t != nil {
					return t
				}
			}
		}
	}
	return m.fallback
}

func (m *RouterMailer) lookupConfig(ctx context.Context, clientID string) *domain.ClientEmailConfig {
	if m.configs == nil || clientID == "" {
		return nil
	}
	cfg, err := m.configs.Get(ctx, clientID)
	if err != nil {
		log.Printf("router mailer: lookup config for client %s: %v", clientID, err)
		return nil
	}
	return cfg
}
