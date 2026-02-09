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
