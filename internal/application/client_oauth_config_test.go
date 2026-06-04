package application

import (
	"context"
	"errors"
	"testing"

	"github.com/Ayush10/authentication-service/internal/domain"
)

// --- minimal fakes -------------------------------------------------------

type oauthFakeClientRepo struct {
	client *domain.Client
}

func (r *oauthFakeClientRepo) Create(context.Context, *domain.Client) error { return nil }
func (r *oauthFakeClientRepo) GetByID(_ context.Context, id string) (*domain.Client, error) {
	if r.client != nil && r.client.ID == id {
		return r.client, nil
	}
	return nil, domain.ErrNotFound
}
func (r *oauthFakeClientRepo) GetBySlug(context.Context, string) (*domain.Client, error) {
	return nil, domain.ErrNotFound
}
func (r *oauthFakeClientRepo) GetByAPIKeyHash(context.Context, string) (*domain.Client, error) {
	return nil, domain.ErrNotFound
}
func (r *oauthFakeClientRepo) List(context.Context) ([]*domain.Client, error)         { return nil, nil }
func (r *oauthFakeClientRepo) Update(context.Context, *domain.Client) error           { return nil }
func (r *oauthFakeClientRepo) UpdateJWTSecret(context.Context, string, string) error  { return nil }
func (r *oauthFakeClientRepo) UpdateAPIKeyHash(context.Context, string, string) error { return nil }

type oauthFakeConfigRepo struct {
	rows map[string]*domain.ClientOAuthConfig // key: clientID|provider
}

func newOAuthFakeConfigRepo() *oauthFakeConfigRepo {
	return &oauthFakeConfigRepo{rows: map[string]*domain.ClientOAuthConfig{}}
}
func (r *oauthFakeConfigRepo) key(c, p string) string { return c + "|" + p }
func (r *oauthFakeConfigRepo) Get(_ context.Context, clientID, provider string) (*domain.ClientOAuthConfig, error) {
	return r.rows[r.key(clientID, provider)], nil
}
func (r *oauthFakeConfigRepo) List(_ context.Context, clientID string) ([]*domain.ClientOAuthConfig, error) {
	var out []*domain.ClientOAuthConfig
	for _, v := range r.rows {
		if v.ClientID == clientID {
			out = append(out, v)
		}
	}
	return out, nil
}
func (r *oauthFakeConfigRepo) Upsert(_ context.Context, cfg *domain.ClientOAuthConfig) error {
	r.rows[r.key(cfg.ClientID, cfg.Provider)] = cfg
	return nil
}
func (r *oauthFakeConfigRepo) Delete(_ context.Context, clientID, provider string) error {
	delete(r.rows, r.key(clientID, provider))
	return nil
}

// reversibleCipher is a trivial test cipher: ciphertext == plaintext bytes.
type reversibleCipher struct{}

func (reversibleCipher) Encrypt(pt string) ([]byte, []byte, error) {
	return []byte(pt), []byte("nonce"), nil
}
func (reversibleCipher) Decrypt(ct, _ []byte) (string, error) { return string(ct), nil }

// --- tests ---------------------------------------------------------------

func newOAuthConfigTestEnv() (*oauthFakeClientRepo, *oauthFakeConfigRepo, *ClientOAuthConfigService) {
	clients := &oauthFakeClientRepo{client: &domain.Client{ID: "client-1"}}
	repo := newOAuthFakeConfigRepo()
	svc := NewClientOAuthConfigService(clients, repo, reversibleCipher{})
	return clients, repo, svc
}

func strptr(s string) *string { return &s }

func TestOAuthConfigServiceSetEncryptsAndRedacts(t *testing.T) {
	_, repo, svc := newOAuthConfigTestEnv()
	resp, err := svc.Set(context.Background(), "client-1", "github", SetOAuthConfigRequest{
		OAuthClientID: strptr("Iv23liABCDEF"),
		ClientSecret:  strptr("supersecret-value-1234"),
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if resp.OAuthClientID != "Iv23liABCDEF" || !resp.HasSecret {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.SecretLastFour != "1234" {
		t.Fatalf("expected last four 1234, got %q", resp.SecretLastFour)
	}
	// The stored row must not contain the plaintext anywhere queryable except ciphertext.
	row := repo.rows["client-1|github"]
	if row == nil || string(row.ClientSecretCiphertext) != "supersecret-value-1234" {
		t.Fatalf("secret not persisted via cipher")
	}
	if !row.Enabled {
		t.Fatalf("expected enabled by default")
	}
}

func TestOAuthConfigServiceRejectsUnsupportedProvider(t *testing.T) {
	_, _, svc := newOAuthConfigTestEnv()
	_, err := svc.Set(context.Background(), "client-1", "apple", SetOAuthConfigRequest{
		OAuthClientID: strptr("x"), ClientSecret: strptr("y"),
	})
	if !errors.Is(err, domain.ErrInvalidOAuthConfig) {
		t.Fatalf("expected ErrInvalidOAuthConfig, got %v", err)
	}
}

func TestOAuthConfigServiceRequiresIDAndSecretTogether(t *testing.T) {
	_, _, svc := newOAuthConfigTestEnv()
	_, err := svc.Set(context.Background(), "client-1", "github", SetOAuthConfigRequest{
		OAuthClientID: strptr("only-id"),
	})
	if !errors.Is(err, domain.ErrInvalidOAuthConfig) {
		t.Fatalf("expected ErrInvalidOAuthConfig, got %v", err)
	}
}

func TestResolveProviderConfigPerClientWins(t *testing.T) {
	clients, repo, _ := newOAuthConfigTestEnv()
	repo.rows["client-1|github"] = &domain.ClientOAuthConfig{
		ClientID: "client-1", Provider: "github", ClientIDPlain: "client-app-id",
		ClientSecretCiphertext: []byte("client-app-secret"), ClientSecretNonce: []byte("nonce"),
		Enabled: true,
	}
	// Global github with different creds — must be overridden.
	global := map[string]*OAuthProviderConfig{
		"github": mustBuild(t, "github", "GLOBAL-ID", "GLOBAL-SECRET"),
	}

	svc := NewOAuthService(nil, nil, nil, nil, nil, nil)
	svc.SetOAuthResolution(global, "https://authservice.example.com/")
	svc.SetPerClientOAuthStore(repo, reversibleCipher{})

	cfg, err := svc.ResolveProviderConfig(context.Background(), clients.client, "github")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cfg.OAuth2Config.ClientID != "client-app-id" {
		t.Fatalf("expected per-client id, got %q", cfg.OAuth2Config.ClientID)
	}
	if cfg.OAuth2Config.ClientSecret != "client-app-secret" {
		t.Fatalf("secret not decrypted correctly: %q", cfg.OAuth2Config.ClientSecret)
	}
	if cfg.OAuth2Config.RedirectURL != "https://authservice.example.com/api/auth/oauth/github/callback" {
		t.Fatalf("unexpected derived callback: %q", cfg.OAuth2Config.RedirectURL)
	}
}

func TestResolveProviderConfigFallsBackToGlobal(t *testing.T) {
	clients, repo, _ := newOAuthConfigTestEnv()
	global := map[string]*OAuthProviderConfig{
		"github": mustBuild(t, "github", "GLOBAL-ID", "GLOBAL-SECRET"),
	}
	svc := NewOAuthService(nil, nil, nil, nil, nil, nil)
	svc.SetOAuthResolution(global, "https://authservice.example.com")
	svc.SetPerClientOAuthStore(repo, reversibleCipher{})

	cfg, err := svc.ResolveProviderConfig(context.Background(), clients.client, "github")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cfg.OAuth2Config.ClientID != "GLOBAL-ID" {
		t.Fatalf("expected global fallback, got %q", cfg.OAuth2Config.ClientID)
	}
}

func TestResolveProviderConfigUnconfigured(t *testing.T) {
	clients, repo, _ := newOAuthConfigTestEnv()
	svc := NewOAuthService(nil, nil, nil, nil, nil, nil)
	svc.SetOAuthResolution(map[string]*OAuthProviderConfig{}, "https://authservice.example.com")
	svc.SetPerClientOAuthStore(repo, reversibleCipher{})

	_, err := svc.ResolveProviderConfig(context.Background(), clients.client, "github")
	if !errors.Is(err, domain.ErrOAuthProviderNotConfigured) {
		t.Fatalf("expected ErrOAuthProviderNotConfigured, got %v", err)
	}
}

func mustBuild(t *testing.T, provider, id, secret string) *OAuthProviderConfig {
	t.Helper()
	cfg, err := BuildProviderConfig(provider, id, secret, "https://x/callback", nil)
	if err != nil {
		t.Fatalf("BuildProviderConfig: %v", err)
	}
	return cfg
}
