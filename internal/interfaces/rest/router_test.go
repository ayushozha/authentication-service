package rest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type signingKeyRepoRouteStub struct {
	keys map[string][]*domain.SigningKey
}

func (s *signingKeyRepoRouteStub) Create(ctx context.Context, key *domain.SigningKey) error {
	if s.keys == nil {
		s.keys = map[string][]*domain.SigningKey{}
	}
	s.keys[key.ClientID] = append(s.keys[key.ClientID], key)
	return nil
}

func (s *signingKeyRepoRouteStub) GetActiveByClient(ctx context.Context, clientID string) (*domain.SigningKey, error) {
	for _, key := range s.keys[clientID] {
		if key.Status == "active" {
			return key, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *signingKeyRepoRouteStub) GetByClientAndKID(ctx context.Context, clientID, kid string) (*domain.SigningKey, error) {
	for _, key := range s.keys[clientID] {
		if key.KID == kid {
			return key, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *signingKeyRepoRouteStub) ListActive(ctx context.Context) ([]*domain.SigningKey, error) {
	keys := make([]*domain.SigningKey, 0)
	for _, list := range s.keys {
		for _, key := range list {
			if key.Status == "active" {
				keys = append(keys, key)
			}
		}
	}
	return keys, nil
}

func (s *signingKeyRepoRouteStub) ListActiveByClient(ctx context.Context, clientID string) ([]*domain.SigningKey, error) {
	keys := make([]*domain.SigningKey, 0)
	for _, key := range s.keys[clientID] {
		if key.Status == "active" {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

type clientRepoRouteStub struct {
	byID     map[string]*domain.Client
	byAPIKey map[string]*domain.Client
}

func (s *clientRepoRouteStub) Create(ctx context.Context, client *domain.Client) error {
	return nil
}

func (s *clientRepoRouteStub) GetByID(ctx context.Context, id string) (*domain.Client, error) {
	client := s.byID[id]
	if client == nil {
		return nil, domain.ErrNotFound
	}
	return client, nil
}

func (s *clientRepoRouteStub) GetBySlug(ctx context.Context, slug string) (*domain.Client, error) {
	return nil, domain.ErrNotFound
}

func (s *clientRepoRouteStub) GetByAPIKeyHash(ctx context.Context, hash string) (*domain.Client, error) {
	client := s.byAPIKey[hash]
	if client == nil {
		return nil, domain.ErrNotFound
	}
	return client, nil
}

func (s *clientRepoRouteStub) List(ctx context.Context) ([]*domain.Client, error) {
	out := make([]*domain.Client, 0, len(s.byID))
	for _, client := range s.byID {
		out = append(out, client)
	}
	return out, nil
}

func (s *clientRepoRouteStub) Update(ctx context.Context, client *domain.Client) error {
	return nil
}

func (s *clientRepoRouteStub) UpdateJWTSecret(ctx context.Context, id, newSecret string) error {
	return nil
}

func (s *clientRepoRouteStub) UpdateAPIKeyHash(ctx context.Context, id, newHash string) error {
	return nil
}

func TestJWKSRouteReturnsIssuerKeysWithoutClientHint(t *testing.T) {
	router, _ := newJWKSRouterForTest(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	router.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(payload.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(payload.Keys))
	}
}

func TestJWKSRouteCanBeScopedByClientID(t *testing.T) {
	router, clients := newJWKSRouterForTest(t)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json?client_id="+clients[0].ID, nil)
	rec := httptest.NewRecorder()
	router.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Keys []map[string]interface{} `json:"keys"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(payload.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(payload.Keys))
	}
}

func newJWKSRouterForTest(t *testing.T) (*Router, []*domain.Client) {
	t.Helper()

	signingRepo := &signingKeyRepoRouteStub{}
	application.SetSigningKeyRepository(signingRepo)
	t.Cleanup(func() { application.SetSigningKeyRepository(nil) })

	clients := []*domain.Client{
		{ID: "client-a", TokenMode: "v2_jwks", Status: "active"},
		{ID: "client-b", TokenMode: "v2_jwks", Status: "active"},
	}

	for idx, client := range clients {
		user := &domain.User{
			ID:            "user-" + string(rune('a'+idx)),
			ClientID:      client.ID,
			Email:         client.ID + "@example.com",
			Role:          "user",
			EmailVerified: true,
		}
		if _, err := application.CreateAccessToken(context.Background(), client, 5*time.Minute, user); err != nil {
			t.Fatalf("seed signing key for %s: %v", client.ID, err)
		}
	}

	clientRepo := &clientRepoRouteStub{
		byID:     map[string]*domain.Client{},
		byAPIKey: map[string]*domain.Client{},
	}
	for _, client := range clients {
		clientRepo.byID[client.ID] = client
		clientRepo.byAPIKey[hashAPIKeyForTest(client.ID+"-api-key")] = client
	}

	router := NewRouter(
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		application.NewClientService(clientRepo),
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		&HandlerConfig{AllowOrigin: "*"},
		"admin-key",
		false,
		"",
	)
	return router, clients
}

func hashAPIKeyForTest(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}
