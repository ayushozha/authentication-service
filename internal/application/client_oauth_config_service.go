package application

import (
	"context"
	"fmt"
	"strings"

	"github.com/Ayush10/authentication-service/internal/domain"
)

// supportedOAuthConfigProviders are the providers that accept per-client
// credential overrides. Apple is excluded (private-key/JWT secret flow).
var supportedOAuthConfigProviders = map[string]bool{
	"github":    true,
	"google":    true,
	"microsoft": true,
}

// IsConfigurableOAuthProvider reports whether a provider supports per-client
// credential overrides.
func IsConfigurableOAuthProvider(provider string) bool {
	return supportedOAuthConfigProviders[strings.ToLower(strings.TrimSpace(provider))]
}

// ClientOAuthConfigService handles admin-facing CRUD on per-client OAuth
// provider credential overrides. Client secrets are encrypted before storage;
// the service never returns them in cleartext.
type ClientOAuthConfigService struct {
	clients ClientRepository
	configs OAuthConfigRepository
	crypto  SecretCipher
}

func NewClientOAuthConfigService(clients ClientRepository, configs OAuthConfigRepository, crypto SecretCipher) *ClientOAuthConfigService {
	return &ClientOAuthConfigService{clients: clients, configs: configs, crypto: crypto}
}

// SetOAuthConfigRequest is the admin upsert payload. OAuthClientID and
// ClientSecret are the provider's app credentials; ClientSecret is plaintext
// and is encrypted before persisting. Fields left nil preserve existing values.
type SetOAuthConfigRequest struct {
	OAuthClientID *string `json:"oauth_client_id,omitempty"`
	ClientSecret  *string `json:"client_secret,omitempty"`
	Scopes        *string `json:"scopes,omitempty"`
	Enabled       *bool   `json:"enabled,omitempty"`
}

// OAuthConfigResponse is the public view of a per-client OAuth config. The
// client secret is redacted to its last four characters.
type OAuthConfigResponse struct {
	ClientID       string `json:"client_id"`
	Provider       string `json:"provider"`
	OAuthClientID  string `json:"oauth_client_id"`
	SecretLastFour string `json:"secret_last_four"`
	HasSecret      bool   `json:"has_secret"`
	Scopes         string `json:"scopes,omitempty"`
	Enabled        bool   `json:"enabled"`
}

func normalizeOAuthProvider(provider string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(provider))
	if !supportedOAuthConfigProviders[p] {
		return "", fmt.Errorf("%w: unsupported provider %q", domain.ErrInvalidOAuthConfig, provider)
	}
	return p, nil
}

func (s *ClientOAuthConfigService) List(ctx context.Context, clientID string) ([]*OAuthConfigResponse, error) {
	if _, err := s.clients.GetByID(ctx, clientID); err != nil {
		return nil, err
	}
	configs, err := s.configs.List(ctx, clientID)
	if err != nil {
		return nil, err
	}
	out := make([]*OAuthConfigResponse, 0, len(configs))
	for _, cfg := range configs {
		out = append(out, toOAuthResponse(cfg))
	}
	return out, nil
}

func (s *ClientOAuthConfigService) Get(ctx context.Context, clientID, provider string) (*OAuthConfigResponse, error) {
	provider, err := normalizeOAuthProvider(provider)
	if err != nil {
		return nil, err
	}
	if _, err := s.clients.GetByID(ctx, clientID); err != nil {
		return nil, err
	}
	cfg, err := s.configs.Get(ctx, clientID, provider)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, domain.ErrNotFound
	}
	return toOAuthResponse(cfg), nil
}

func (s *ClientOAuthConfigService) Set(ctx context.Context, clientID, provider string, req SetOAuthConfigRequest) (*OAuthConfigResponse, error) {
	provider, err := normalizeOAuthProvider(provider)
	if err != nil {
		return nil, err
	}
	if _, err := s.clients.GetByID(ctx, clientID); err != nil {
		return nil, err
	}

	existing, err := s.configs.Get(ctx, clientID, provider)
	if err != nil {
		return nil, err
	}
	cfg := &domain.ClientOAuthConfig{ClientID: clientID, Provider: provider, Enabled: true}
	if existing != nil {
		cfg = existing
		cfg.ClientID = clientID
		cfg.Provider = provider
	}

	if req.OAuthClientID != nil {
		cfg.ClientIDPlain = strings.TrimSpace(*req.OAuthClientID)
	}
	if req.ClientSecret != nil {
		secret := strings.TrimSpace(*req.ClientSecret)
		if secret == "" {
			cfg.ClientSecretCiphertext = nil
			cfg.ClientSecretNonce = nil
			cfg.SecretLastFour = ""
		} else {
			if s.crypto == nil {
				return nil, fmt.Errorf("%w: oauth secret crypto not configured on server", domain.ErrInvalidOAuthConfig)
			}
			ct, nonce, err := s.crypto.Encrypt(secret)
			if err != nil {
				return nil, fmt.Errorf("encrypt client secret: %w", err)
			}
			cfg.ClientSecretCiphertext = ct
			cfg.ClientSecretNonce = nonce
			cfg.SecretLastFour = lastFour(secret)
		}
	}
	if req.Scopes != nil {
		cfg.Scopes = strings.TrimSpace(*req.Scopes)
	}
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}

	// A usable override must carry both an OAuth client id and a secret.
	hasID := cfg.ClientIDPlain != ""
	hasSecret := len(cfg.ClientSecretCiphertext) > 0
	if hasID != hasSecret {
		return nil, fmt.Errorf("%w: oauth_client_id and client_secret must be set together", domain.ErrInvalidOAuthConfig)
	}
	if !hasID {
		return nil, fmt.Errorf("%w: oauth_client_id and client_secret are required", domain.ErrInvalidOAuthConfig)
	}

	if err := s.configs.Upsert(ctx, cfg); err != nil {
		return nil, err
	}
	return toOAuthResponse(cfg), nil
}

func (s *ClientOAuthConfigService) Delete(ctx context.Context, clientID, provider string) error {
	provider, err := normalizeOAuthProvider(provider)
	if err != nil {
		return err
	}
	if _, err := s.clients.GetByID(ctx, clientID); err != nil {
		return err
	}
	return s.configs.Delete(ctx, clientID, provider)
}

func toOAuthResponse(cfg *domain.ClientOAuthConfig) *OAuthConfigResponse {
	return &OAuthConfigResponse{
		ClientID:       cfg.ClientID,
		Provider:       cfg.Provider,
		OAuthClientID:  cfg.ClientIDPlain,
		SecretLastFour: cfg.SecretLastFour,
		HasSecret:      len(cfg.ClientSecretCiphertext) > 0,
		Scopes:         cfg.Scopes,
		Enabled:        cfg.Enabled,
	}
}
