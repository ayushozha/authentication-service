package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
)

type ClientService struct {
	clients ClientRepository
}

func NewClientService(clients ClientRepository) *ClientService {
	return &ClientService{clients: clients}
}

type CreateClientRequest struct {
	Name           string                 `json:"name"`
	Slug           string                 `json:"slug"`
	AllowedOrigins []string               `json:"allowed_origins"`
	WebhookURL     string                 `json:"webhook_url"`
	Settings       map[string]interface{} `json:"settings"`
}

type UpdateClientRequest struct {
	Name           *string                `json:"name"`
	AllowedOrigins []string               `json:"allowed_origins"`
	WebhookURL     *string                `json:"webhook_url"`
	Settings       map[string]interface{} `json:"settings"`
	Status         *string                `json:"status"`
}

type CreateClientResponse struct {
	Client    *domain.Client `json:"client"`
	APIKey    string         `json:"api_key"`
	JWTSecret string         `json:"jwt_secret"`
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

	now := time.Now().UTC()
	client := &domain.Client{
		ID:             uuid.New().String(),
		Name:           req.Name,
		Slug:           req.Slug,
		JWTSecret:      jwtSecret,
		AllowedOrigins: req.AllowedOrigins,
		WebhookURL:     req.WebhookURL,
		Settings:       cloneSettings(req.Settings),
		Status:         "active",
		TokenMode:      "v2_jwks",
		APIKeyHash:     hashKey(apiKey),
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.clients.Create(ctx, client); err != nil {
		return nil, err
	}

	return &CreateClientResponse{Client: client, APIKey: apiKey, JWTSecret: jwtSecret}, nil
}

func (s *ClientService) UpdateClient(ctx context.Context, clientID string, req UpdateClientRequest) (*domain.Client, error) {
	client, err := s.clients.GetByID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if req.Name != nil {
		client.Name = *req.Name
	}
	if req.AllowedOrigins != nil {
		client.AllowedOrigins = append([]string(nil), req.AllowedOrigins...)
	}
	if req.WebhookURL != nil {
		client.WebhookURL = *req.WebhookURL
	}
	if req.Settings != nil {
		client.Settings = cloneSettings(req.Settings)
	}
	if req.Status != nil {
		client.Status = *req.Status
	}
	client.UpdatedAt = time.Now().UTC()
	if err := s.clients.Update(ctx, client); err != nil {
		return nil, err
	}
	return s.clients.GetByID(ctx, clientID)
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

func (s *ClientService) RotateJWTSecret(ctx context.Context, clientID string) (string, *domain.Client, error) {
	newSecret, err := generateSecureKey(32)
	if err != nil {
		return "", nil, err
	}
	if err := s.clients.UpdateJWTSecret(ctx, clientID, newSecret); err != nil {
		return "", nil, err
	}
	client, err := s.clients.GetByID(ctx, clientID)
	return newSecret, client, err
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

func cloneSettings(settings map[string]interface{}) map[string]interface{} {
	if settings == nil {
		return map[string]interface{}{}
	}
	clone := make(map[string]interface{}, len(settings))
	for key, value := range settings {
		clone[key] = value
	}
	return clone
}
