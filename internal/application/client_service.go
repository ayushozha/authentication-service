package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type ClientService struct {
	clients ClientRepository
}

func NewClientService(clients ClientRepository) *ClientService {
	return &ClientService{clients: clients}
}

type CreateClientRequest struct {
	Name           string   `json:"name"`
	Slug           string   `json:"slug"`
	AllowedOrigins []string `json:"allowed_origins"`
	WebhookURL     string   `json:"webhook_url"`
}

type CreateClientResponse struct {
	Client *domain.Client `json:"client"`
	APIKey string         `json:"api_key"`
}

func (s *ClientService) CreateClient(ctx context.Context, req CreateClientRequest) (*CreateClientResponse, error) {
	apiKey, err := generateSecureKey(32)
	if err != nil {
		return nil, fmt.Errorf("generate api key: %w", err)
	}
	jwtSecret, err := generateSecureKey(32)
	if err != nil {
		return nil, fmt.Errorf("generate jwt secret: %w", err)
	}

	client := &domain.Client{
		Name:           req.Name,
		Slug:           req.Slug,
		JWTSecret:      jwtSecret,
		AllowedOrigins: req.AllowedOrigins,
		WebhookURL:     req.WebhookURL,
		Settings:       map[string]interface{}{},
		Status:         "active",
		APIKeyHash:     hashKey(apiKey),
	}

	if err := s.clients.Create(ctx, client); err != nil {
		return nil, err
	}

	return &CreateClientResponse{Client: client, APIKey: apiKey}, nil
}

func (s *ClientService) GetClient(ctx context.Context, id string) (*domain.Client, error) {
	return s.clients.GetByID(ctx, id)
}

func (s *ClientService) ListClients(ctx context.Context) ([]*domain.Client, error) {
	return s.clients.List(ctx)
}

func (s *ClientService) GetClientByAPIKey(ctx context.Context, apiKey string) (*domain.Client, error) {
	hash := hashKey(apiKey)
	client, err := s.clients.GetByAPIKeyHash(ctx, hash)
	if err != nil {
		return nil, domain.ErrInvalidClient
	}
	if client == nil {
		return nil, domain.ErrInvalidClient
	}
	if client.Status != "active" {
		return nil, domain.ErrClientSuspended
	}
	return client, nil
}

func (s *ClientService) RotateJWTSecret(ctx context.Context, clientID string) (*domain.Client, error) {
	newSecret, err := generateSecureKey(32)
	if err != nil {
		return nil, err
	}
	if err := s.clients.UpdateJWTSecret(ctx, clientID, newSecret); err != nil {
		return nil, err
	}
	return s.clients.GetByID(ctx, clientID)
}

func (s *ClientService) RotateAPIKey(ctx context.Context, clientID string) (string, *domain.Client, error) {
	newKey, err := generateSecureKey(32)
	if err != nil {
		return "", nil, err
	}
	if err := s.clients.UpdateAPIKeyHash(ctx, clientID, hashKey(newKey)); err != nil {
		return "", nil, err
	}
	client, err := s.clients.GetByID(ctx, clientID)
	return newKey, client, err
}

func generateSecureKey(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}
