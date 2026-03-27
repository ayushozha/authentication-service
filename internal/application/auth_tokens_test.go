package application

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type signingKeyRepoStub struct {
	keys map[string][]*domain.SigningKey
}

func (s *signingKeyRepoStub) Create(ctx context.Context, key *domain.SigningKey) error {
	if s.keys == nil {
		s.keys = map[string][]*domain.SigningKey{}
	}
	s.keys[key.ClientID] = append(s.keys[key.ClientID], key)
	return nil
}

func (s *signingKeyRepoStub) GetActiveByClient(ctx context.Context, clientID string) (*domain.SigningKey, error) {
	list := s.keys[clientID]
	for _, key := range list {
		if key.Status == "active" {
			return key, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *signingKeyRepoStub) GetByClientAndKID(ctx context.Context, clientID, kid string) (*domain.SigningKey, error) {
	list := s.keys[clientID]
	for _, key := range list {
		if key.KID == kid {
			return key, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *signingKeyRepoStub) ListActive(ctx context.Context) ([]*domain.SigningKey, error) {
	out := make([]*domain.SigningKey, 0)
	for _, list := range s.keys {
		for _, key := range list {
			if key.Status == "active" {
				out = append(out, key)
			}
		}
	}
	return out, nil
}

func (s *signingKeyRepoStub) ListActiveByClient(ctx context.Context, clientID string) ([]*domain.SigningKey, error) {
	list := s.keys[clientID]
	out := make([]*domain.SigningKey, 0)
	for _, key := range list {
		if key.Status == "active" {
			out = append(out, key)
		}
	}
	return out, nil
}

func TestCreateAndValidateAccessTokenHS256(t *testing.T) {
	ctx := context.Background()
	client := &domain.Client{
		ID:        "client-hs",
		JWTSecret: "test-secret",
		TokenMode: "v1_hs256",
	}
	user := &domain.User{
		ID:            "user-1",
		ClientID:      client.ID,
		Email:         "user@example.com",
		Role:          "user",
		EmailVerified: true,
	}

	token, err := CreateAccessToken(ctx, client, 5*time.Minute, user)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	claims, err := ValidateAccessToken(ctx, client, token)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if claims.Subject != user.ID {
		t.Fatalf("unexpected subject: %s", claims.Subject)
	}
}

func TestCreateAndValidateAccessTokenJWKS(t *testing.T) {
	ctx := context.Background()
	repo := &signingKeyRepoStub{}
	SetSigningKeyRepository(repo)
	t.Cleanup(func() { SetSigningKeyRepository(nil) })

	client := &domain.Client{
		ID:        "client-rs",
		TokenMode: "v2_jwks",
	}
	user := &domain.User{
		ID:            "user-rs",
		ClientID:      client.ID,
		Email:         "rs@example.com",
		Role:          "user",
		EmailVerified: true,
	}

	token, err := CreateAccessToken(ctx, client, 5*time.Minute, user)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if parts := strings.Split(token, "."); len(parts) != 3 {
		t.Fatalf("token is not jwt")
	}

	claims, err := ValidateAccessToken(ctx, client, token)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if claims.ClientID != client.ID {
		t.Fatalf("unexpected client id: %s", claims.ClientID)
	}

	jwks, err := ClientJWKS(ctx, client.ID)
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	keys, ok := jwks["keys"].([]map[string]interface{})
	if ok && len(keys) == 0 {
		t.Fatalf("expected at least one jwk")
	}
}

func TestJWKSReturnsAllActiveKeysAcrossClients(t *testing.T) {
	ctx := context.Background()
	repo := &signingKeyRepoStub{}
	SetSigningKeyRepository(repo)
	t.Cleanup(func() { SetSigningKeyRepository(nil) })

	clientA := &domain.Client{ID: "client-a", TokenMode: "v2_jwks"}
	clientB := &domain.Client{ID: "client-b", TokenMode: "v2_jwks"}

	for _, tc := range []struct {
		client *domain.Client
		user   *domain.User
	}{
		{
			client: clientA,
			user: &domain.User{
				ID:            "user-a",
				ClientID:      clientA.ID,
				Email:         "a@example.com",
				Role:          "user",
				EmailVerified: true,
			},
		},
		{
			client: clientB,
			user: &domain.User{
				ID:            "user-b",
				ClientID:      clientB.ID,
				Email:         "b@example.com",
				Role:          "user",
				EmailVerified: true,
			},
		},
	} {
		if _, err := CreateAccessToken(ctx, tc.client, 5*time.Minute, tc.user); err != nil {
			t.Fatalf("create token for %s: %v", tc.client.ID, err)
		}
	}

	jwks, err := JWKS(ctx)
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	keys, ok := jwks["keys"].([]map[string]interface{})
	if !ok {
		t.Fatalf("unexpected jwks payload type")
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}
