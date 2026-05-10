package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestAuthorizeUserRPCRequiresClientAndMatchingBearerToken(t *testing.T) {
	client := &domain.Client{
		ID:         "client-a",
		Name:       "Client A",
		Slug:       "client-a",
		JWTSecret:  "test-secret",
		Status:     "active",
		TokenMode:  "v1_hs256",
		APIKeyHash: hashTestKey("client-api-key"),
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	user := &domain.User{
		ID:            "user-a",
		ClientID:      client.ID,
		Email:         "user@example.com",
		EmailVerified: true,
		Role:          "user",
		Status:        "active",
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	token, err := application.CreateAccessToken(context.Background(), client, time.Minute, user)
	if err != nil {
		t.Fatalf("create access token: %v", err)
	}

	server := &AuthServer{
		clients: application.NewClientService(&grpcClientRepoStub{client: client}),
	}

	if _, err := server.authorizeUserRPC(context.Background(), "", "", user.ID); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected missing credentials to be unauthenticated, got %v", err)
	}
	if _, err := server.authorizeUserRPC(context.Background(), "client-api-key", token, "other-user"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected mismatched subject to be permission denied, got %v", err)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-api-key", "client-api-key",
		"authorization", "Bearer "+token,
	))
	claims, err := server.authorizeUserRPC(ctx, "", "", user.ID)
	if err != nil {
		t.Fatalf("authorize matching user from metadata: %v", err)
	}
	if claims.Subject != user.ID || claims.ClientID != client.ID {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

type grpcClientRepoStub struct {
	client *domain.Client
}

func (r *grpcClientRepoStub) Create(ctx context.Context, client *domain.Client) error {
	r.client = client
	return nil
}

func (r *grpcClientRepoStub) GetByID(ctx context.Context, id string) (*domain.Client, error) {
	if r.client != nil && r.client.ID == id {
		return r.client, nil
	}
	return nil, domain.ErrNotFound
}

func (r *grpcClientRepoStub) GetBySlug(ctx context.Context, slug string) (*domain.Client, error) {
	if r.client != nil && r.client.Slug == slug {
		return r.client, nil
	}
	return nil, domain.ErrNotFound
}

func (r *grpcClientRepoStub) GetByAPIKeyHash(ctx context.Context, hash string) (*domain.Client, error) {
	if r.client != nil && r.client.APIKeyHash == hash {
		return r.client, nil
	}
	return nil, domain.ErrNotFound
}

func (r *grpcClientRepoStub) List(ctx context.Context) ([]*domain.Client, error) {
	if r.client == nil {
		return nil, nil
	}
	return []*domain.Client{r.client}, nil
}

func (r *grpcClientRepoStub) Update(ctx context.Context, client *domain.Client) error {
	r.client = client
	return nil
}

func (r *grpcClientRepoStub) UpdateJWTSecret(ctx context.Context, id, newSecret string) error {
	if r.client == nil || r.client.ID != id {
		return domain.ErrNotFound
	}
	r.client.JWTSecret = newSecret
	return nil
}

func (r *grpcClientRepoStub) UpdateAPIKeyHash(ctx context.Context, id, newHash string) error {
	if r.client == nil || r.client.ID != id {
		return domain.ErrNotFound
	}
	r.client.APIKeyHash = newHash
	return nil
}

func hashTestKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}
