package application

import (
	"context"
	"fmt"
	"strings"

	"github.com/Ayush10/authentication-service/internal/domain"
)

// EmailSecretCrypto is the minimal contract ClientEmailConfigService needs to
// encrypt provider API keys at rest. Implemented by the email infra package.
type EmailSecretCrypto interface {
	Encrypt(plaintext string) (ciphertext, nonce []byte, err error)
}

// ClientEmailConfigService handles admin-facing CRUD on per-client email
// transport overrides. Provider API keys are encrypted before storage; the
// service never returns them in cleartext.
type ClientEmailConfigService struct {
	clients ClientRepository
	configs EmailConfigRepository
	crypto  EmailSecretCrypto
}

func NewClientEmailConfigService(clients ClientRepository, configs EmailConfigRepository, crypto EmailSecretCrypto) *ClientEmailConfigService {
	return &ClientEmailConfigService{clients: clients, configs: configs, crypto: crypto}
}

// SetEmailConfigRequest is the admin upsert payload. All fields are optional;
// fields left zero-valued preserve their existing values on the row. APIKey
// is plaintext — the service encrypts it before persisting.
type SetEmailConfigRequest struct {
	Provider                 *string `json:"provider,omitempty"`
	APIKey                   *string `json:"api_key,omitempty"`
	FromAddress              *string `json:"from_address,omitempty"`
	FromName                 *string `json:"from_name,omitempty"`
	ReplyTo                  *string `json:"reply_to,omitempty"`
	ResetPasswordURLTemplate *string `json:"reset_password_url_template,omitempty"`
	VerifyEmailURLTemplate   *string `json:"verify_email_url_template,omitempty"`
	MagicLinkURLTemplate     *string `json:"magic_link_url_template,omitempty"`
}

// EmailConfigResponse is the public view of a per-client config. API key is
// redacted to its last four characters — full key never leaves the service.
type EmailConfigResponse struct {
	ClientID                 string `json:"client_id"`
	Provider                 string `json:"provider"`
	APIKeyLastFour           string `json:"api_key_last_four"`
	HasAPIKey                bool   `json:"has_api_key"`
	FromAddress              string `json:"from_address"`
	FromName                 string `json:"from_name"`
	ReplyTo                  string `json:"reply_to,omitempty"`
	ResetPasswordURLTemplate string `json:"reset_password_url_template,omitempty"`
	VerifyEmailURLTemplate   string `json:"verify_email_url_template,omitempty"`
	MagicLinkURLTemplate     string `json:"magic_link_url_template,omitempty"`
}

func (s *ClientEmailConfigService) Get(ctx context.Context, clientID string) (*EmailConfigResponse, error) {
	if _, err := s.clients.GetByID(ctx, clientID); err != nil {
		return nil, err
	}
	cfg, err := s.configs.Get(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, domain.ErrNotFound
	}
	return toResponse(cfg), nil
}

func (s *ClientEmailConfigService) Set(ctx context.Context, clientID string, req SetEmailConfigRequest) (*EmailConfigResponse, error) {
	if _, err := s.clients.GetByID(ctx, clientID); err != nil {
		return nil, err
	}

	existing, err := s.configs.Get(ctx, clientID)
	if err != nil {
		return nil, err
	}
	cfg := &domain.ClientEmailConfig{ClientID: clientID, Provider: "resend"}
	if existing != nil {
		cfg = existing
		cfg.ClientID = clientID
	}

	if req.Provider != nil {
		provider := strings.TrimSpace(*req.Provider)
		if provider == "" {
			provider = "resend"
		}
		if provider != "resend" {
			return nil, fmt.Errorf("%w: unsupported provider %q", domain.ErrInvalidEmailConfig, provider)
		}
		cfg.Provider = provider
	}
	if req.APIKey != nil {
		apiKey := strings.TrimSpace(*req.APIKey)
		if apiKey == "" {
			cfg.APIKeyCiphertext = nil
			cfg.APIKeyNonce = nil
			cfg.APIKeyLastFour = ""
		} else {
			if s.crypto == nil {
				return nil, fmt.Errorf("%w: email crypto not configured on server", domain.ErrInvalidEmailConfig)
			}
			ct, nonce, err := s.crypto.Encrypt(apiKey)
			if err != nil {
				return nil, fmt.Errorf("encrypt api key: %w", err)
			}
			cfg.APIKeyCiphertext = ct
			cfg.APIKeyNonce = nonce
			cfg.APIKeyLastFour = lastFour(apiKey)
		}
	}
	if req.FromAddress != nil {
		cfg.FromAddress = strings.TrimSpace(*req.FromAddress)
	}
	if req.FromName != nil {
		cfg.FromName = strings.TrimSpace(*req.FromName)
	}
	if req.ReplyTo != nil {
		cfg.ReplyTo = strings.TrimSpace(*req.ReplyTo)
	}
	if req.ResetPasswordURLTemplate != nil {
		cfg.ResetPasswordURLTemplate = strings.TrimSpace(*req.ResetPasswordURLTemplate)
	}
	if req.VerifyEmailURLTemplate != nil {
		cfg.VerifyEmailURLTemplate = strings.TrimSpace(*req.VerifyEmailURLTemplate)
	}
	if req.MagicLinkURLTemplate != nil {
		cfg.MagicLinkURLTemplate = strings.TrimSpace(*req.MagicLinkURLTemplate)
	}

	// A row that overrides transport must carry both API key and from-address.
	// URL-template-only rows are valid (carry no key, no from): they only
	// rewrite link URLs and leave delivery to the fallback transport.
	hasKey := len(cfg.APIKeyCiphertext) > 0
	hasFrom := cfg.FromAddress != ""
	if hasKey != hasFrom {
		return nil, fmt.Errorf("%w: api_key and from_address must be set together", domain.ErrInvalidEmailConfig)
	}

	if err := s.configs.Upsert(ctx, cfg); err != nil {
		return nil, err
	}
	return toResponse(cfg), nil
}

func (s *ClientEmailConfigService) Delete(ctx context.Context, clientID string) error {
	if _, err := s.clients.GetByID(ctx, clientID); err != nil {
		return err
	}
	return s.configs.Delete(ctx, clientID)
}

func toResponse(cfg *domain.ClientEmailConfig) *EmailConfigResponse {
	return &EmailConfigResponse{
		ClientID:                 cfg.ClientID,
		Provider:                 cfg.Provider,
		APIKeyLastFour:           cfg.APIKeyLastFour,
		HasAPIKey:                len(cfg.APIKeyCiphertext) > 0,
		FromAddress:              cfg.FromAddress,
		FromName:                 cfg.FromName,
		ReplyTo:                  cfg.ReplyTo,
		ResetPasswordURLTemplate: cfg.ResetPasswordURLTemplate,
		VerifyEmailURLTemplate:   cfg.VerifyEmailURLTemplate,
		MagicLinkURLTemplate:     cfg.MagicLinkURLTemplate,
	}
}

func lastFour(s string) string {
	if len(s) < 8 {
		return s
	}
	return s[len(s)-4:]
}

