package application

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
)

type M2MService struct {
	accounts ServiceAccountRepository
	clients  ClientRepository
	audit    AuditRepository
}

func NewM2MService(accounts ServiceAccountRepository, clients ClientRepository, audit AuditRepository) *M2MService {
	return &M2MService{accounts: accounts, clients: clients, audit: audit}
}

type CreateServiceAccountRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Scopes      []string `json:"scopes"`
}

type UpdateServiceAccountRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Scopes      []string `json:"scopes"`
	Status      string   `json:"status"`
}

type CreateServiceAccountKeyRequest struct {
	Name           string   `json:"name"`
	Scopes         []string `json:"scopes"`
	ExpiresInHours int      `json:"expires_in_hours"`
}

type ClientCredentialsRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
}

type TokenIntrospectionRequest struct {
	Token        string `json:"token"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type M2MTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type M2MIntrospectionResponse struct {
	Active             bool     `json:"active"`
	ClientID           string   `json:"client_id,omitempty"`
	Subject            string   `json:"sub,omitempty"`
	TokenUse           string   `json:"token_use,omitempty"`
	Scope              string   `json:"scope,omitempty"`
	Scopes             []string `json:"scopes,omitempty"`
	ServiceAccountID   string   `json:"service_account_id,omitempty"`
	ServiceAccountName string   `json:"service_account_name,omitempty"`
	ExpiresAt          int64    `json:"exp,omitempty"`
	IssuedAt           int64    `json:"iat,omitempty"`
	JWTID              string   `json:"jti,omitempty"`
	Error              string   `json:"error,omitempty"`
}

type validatedServiceCredential struct {
	client  *domain.Client
	account *domain.ServiceAccount
	key     *domain.ServiceAccountKey
	scopes  []string
}

func (s *M2MService) CreateServiceAccount(ctx context.Context, clientID string, req CreateServiceAccountRequest, ip, ua string) (*domain.ServiceAccountKeyWithSecret, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("service account name is required")
	}
	if len(name) > 128 {
		return nil, fmt.Errorf("service account name must be 128 characters or fewer")
	}
	description := strings.TrimSpace(req.Description)
	if len(description) > 512 {
		return nil, fmt.Errorf("service account description must be 512 characters or fewer")
	}
	scopes, err := domain.NormalizeScopes(req.Scopes)
	if err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		return nil, fmt.Errorf("at least one scope is required")
	}

	now := time.Now().UTC()
	account := &domain.ServiceAccount{
		ID:          uuid.NewString(),
		ClientID:    clientID,
		Name:        name,
		Description: description,
		Scopes:      scopes,
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.accounts.CreateServiceAccount(ctx, account); err != nil {
		return nil, err
	}
	keyWithSecret, err := s.createKey(ctx, account, CreateServiceAccountKeyRequest{Name: "default", Scopes: scopes})
	if err != nil {
		return nil, err
	}
	keyWithSecret.ServiceAccount = account
	s.log(ctx, clientID, "service_account_created", ip, ua, map[string]interface{}{
		"service_account_id": account.ID,
		"scopes":             scopes,
	})
	return keyWithSecret, nil
}

func (s *M2MService) ListServiceAccounts(ctx context.Context, clientID string) ([]*domain.ServiceAccount, error) {
	return s.accounts.ListServiceAccounts(ctx, clientID)
}

func (s *M2MService) GetServiceAccount(ctx context.Context, clientID, serviceAccountID string) (*domain.ServiceAccount, error) {
	return s.accounts.GetServiceAccount(ctx, clientID, serviceAccountID)
}

func (s *M2MService) UpdateServiceAccount(ctx context.Context, clientID, serviceAccountID string, req UpdateServiceAccountRequest, ip, ua string) (*domain.ServiceAccount, error) {
	account, err := s.accounts.GetServiceAccount(ctx, clientID, serviceAccountID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Name) != "" {
		account.Name = strings.TrimSpace(req.Name)
	}
	if len(account.Name) > 128 {
		return nil, fmt.Errorf("service account name must be 128 characters or fewer")
	}
	if strings.TrimSpace(req.Description) != "" {
		account.Description = strings.TrimSpace(req.Description)
	}
	if len(account.Description) > 512 {
		return nil, fmt.Errorf("service account description must be 512 characters or fewer")
	}
	if req.Scopes != nil {
		scopes, err := domain.NormalizeScopes(req.Scopes)
		if err != nil {
			return nil, err
		}
		if len(scopes) == 0 {
			return nil, fmt.Errorf("at least one scope is required")
		}
		account.Scopes = scopes
	}
	if strings.TrimSpace(req.Status) != "" {
		status := strings.ToLower(strings.TrimSpace(req.Status))
		if status != "active" && status != "disabled" {
			return nil, fmt.Errorf("status must be active or disabled")
		}
		account.Status = status
	}
	if err := s.accounts.UpdateServiceAccount(ctx, account); err != nil {
		return nil, err
	}
	s.log(ctx, clientID, "service_account_updated", ip, ua, map[string]interface{}{"service_account_id": serviceAccountID})
	return account, nil
}

func (s *M2MService) CreateServiceAccountKey(ctx context.Context, clientID, serviceAccountID string, req CreateServiceAccountKeyRequest, ip, ua string) (*domain.ServiceAccountKeyWithSecret, error) {
	account, err := s.accounts.GetServiceAccount(ctx, clientID, serviceAccountID)
	if err != nil {
		return nil, err
	}
	if account.Status != "active" {
		return nil, domain.ErrForbidden
	}
	keyWithSecret, err := s.createKey(ctx, account, req)
	if err != nil {
		return nil, err
	}
	s.log(ctx, clientID, "service_account_key_created", ip, ua, map[string]interface{}{
		"service_account_id": serviceAccountID,
		"key_id":             keyWithSecret.Key.ID,
	})
	return keyWithSecret, nil
}

func (s *M2MService) ListServiceAccountKeys(ctx context.Context, clientID, serviceAccountID string) ([]*domain.ServiceAccountKey, error) {
	if _, err := s.accounts.GetServiceAccount(ctx, clientID, serviceAccountID); err != nil {
		return nil, err
	}
	return s.accounts.ListServiceAccountKeys(ctx, clientID, serviceAccountID)
}

func (s *M2MService) GetServiceAccountKey(ctx context.Context, clientID, serviceAccountID, keyID string) (*domain.ServiceAccountKey, error) {
	if _, err := s.accounts.GetServiceAccount(ctx, clientID, serviceAccountID); err != nil {
		return nil, err
	}
	return s.accounts.GetServiceAccountKey(ctx, clientID, serviceAccountID, keyID)
}

func (s *M2MService) RotateServiceAccountKey(ctx context.Context, clientID, serviceAccountID, keyID string, ip, ua string) (*domain.ServiceAccountKeyWithSecret, error) {
	oldKey, err := s.accounts.GetServiceAccountKey(ctx, clientID, serviceAccountID, keyID)
	if err != nil {
		return nil, err
	}
	keyWithSecret, err := s.CreateServiceAccountKey(ctx, clientID, serviceAccountID, CreateServiceAccountKeyRequest{
		Name:   oldKey.Name + " rotated",
		Scopes: oldKey.Scopes,
	}, ip, ua)
	if err != nil {
		return nil, err
	}
	if err := s.accounts.RevokeServiceAccountKey(ctx, clientID, serviceAccountID, keyID); err != nil {
		return nil, err
	}
	s.log(ctx, clientID, "service_account_key_rotated", ip, ua, map[string]interface{}{
		"service_account_id": serviceAccountID,
		"old_key_id":         keyID,
		"new_key_id":         keyWithSecret.Key.ID,
	})
	return keyWithSecret, nil
}

func (s *M2MService) RevokeServiceAccountKey(ctx context.Context, clientID, serviceAccountID, keyID, ip, ua string) error {
	if err := s.accounts.RevokeServiceAccountKey(ctx, clientID, serviceAccountID, keyID); err != nil {
		return err
	}
	s.log(ctx, clientID, "service_account_key_revoked", ip, ua, map[string]interface{}{
		"service_account_id": serviceAccountID,
		"key_id":             keyID,
	})
	return nil
}

func (s *M2MService) IssueClientCredentialsToken(ctx context.Context, req ClientCredentialsRequest, ip, ua string, ttl time.Duration) (*M2MTokenResponse, error) {
	if strings.TrimSpace(req.GrantType) != "client_credentials" {
		return nil, fmt.Errorf("unsupported grant_type")
	}
	requestedScopes, err := parseScopeString(req.Scope)
	if err != nil {
		return nil, err
	}
	credential, err := s.validateClientCredentials(ctx, req.ClientID, req.ClientSecret, requestedScopes)
	if err != nil {
		return nil, err
	}
	token, err := CreateMachineAccessToken(ctx, credential.client, ttl, credential.account, credential.scopes)
	if err != nil {
		return nil, err
	}
	_ = s.accounts.UpdateServiceAccountLastUsed(ctx, credential.account.ID)
	_ = s.accounts.UpdateServiceAccountKeyLastUsed(ctx, credential.key.ID)
	s.log(ctx, credential.client.ID, "m2m_token_issued", ip, ua, map[string]interface{}{
		"service_account_id": credential.account.ID,
		"key_id":             credential.key.ID,
		"scopes":             credential.scopes,
	})
	return &M2MTokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(ttl.Seconds()),
		Scope:       domain.ScopeString(credential.scopes),
	}, nil
}

func (s *M2MService) IntrospectToken(ctx context.Context, req TokenIntrospectionRequest, ip, ua string) (*M2MIntrospectionResponse, error) {
	if strings.TrimSpace(req.Token) == "" {
		return &M2MIntrospectionResponse{Active: false, Error: "token is required"}, nil
	}
	credential, err := s.validateClientCredentials(ctx, req.ClientID, req.ClientSecret, nil)
	if err != nil {
		return nil, err
	}
	claims, err := ValidateAccessToken(ctx, credential.client, req.Token)
	if err != nil {
		return &M2MIntrospectionResponse{Active: false, Error: err.Error()}, nil
	}
	if claims.ClientID != credential.client.ID {
		return &M2MIntrospectionResponse{Active: false, Error: "token does not belong to this client"}, nil
	}
	resp := &M2MIntrospectionResponse{
		Active:             true,
		ClientID:           claims.ClientID,
		Subject:            claims.Subject,
		TokenUse:           claims.TokenUse,
		Scope:              claims.Scope,
		Scopes:             claims.Scopes,
		ServiceAccountID:   claims.ServiceAccountID,
		ServiceAccountName: claims.ServiceAccountName,
		JWTID:              claims.ID,
	}
	if claims.ExpiresAt != nil {
		resp.ExpiresAt = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		resp.IssuedAt = claims.IssuedAt.Unix()
	}
	s.log(ctx, credential.client.ID, "m2m_token_introspected", ip, ua, map[string]interface{}{
		"service_account_id": credential.account.ID,
		"active":             true,
	})
	return resp, nil
}

func (s *M2MService) createKey(ctx context.Context, account *domain.ServiceAccount, req CreateServiceAccountKeyRequest) (*domain.ServiceAccountKeyWithSecret, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "default"
	}
	if len(name) > 128 {
		return nil, fmt.Errorf("service account key name must be 128 characters or fewer")
	}
	scopes := req.Scopes
	if scopes == nil {
		scopes = account.Scopes
	}
	normalizedScopes, err := domain.NormalizeScopes(scopes)
	if err != nil {
		return nil, err
	}
	if len(normalizedScopes) == 0 {
		return nil, fmt.Errorf("at least one scope is required")
	}
	if !domain.ScopesContainAll(account.Scopes, normalizedScopes) {
		return nil, domain.ErrInvalidScope
	}
	expiresAt := serviceAccountKeyExpiry(req.ExpiresInHours)
	rawSecret, err := GenerateToken(32)
	if err != nil {
		return nil, err
	}
	clientSecret := "m2m_" + rawSecret
	prefix := clientSecret
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	now := time.Now().UTC()
	key := &domain.ServiceAccountKey{
		ID:               uuid.NewString(),
		ClientID:         account.ClientID,
		ServiceAccountID: account.ID,
		Name:             name,
		KeyPrefix:        prefix,
		SecretHash:       HashToken(clientSecret),
		Scopes:           normalizedScopes,
		Status:           "active",
		ExpiresAt:        expiresAt,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := s.accounts.CreateServiceAccountKey(ctx, key); err != nil {
		return nil, err
	}
	return &domain.ServiceAccountKeyWithSecret{
		Key:          key,
		ClientID:     account.ID,
		ClientSecret: clientSecret,
	}, nil
}

func (s *M2MService) validateClientCredentials(ctx context.Context, serviceAccountID, secret string, requestedScopes []string) (*validatedServiceCredential, error) {
	serviceAccountID = strings.TrimSpace(serviceAccountID)
	secret = strings.TrimSpace(secret)
	if serviceAccountID == "" || secret == "" {
		return nil, domain.ErrInvalidClientCredentials
	}
	key, err := s.accounts.GetServiceAccountKeyBySecretHash(ctx, serviceAccountID, HashToken(secret))
	if err != nil {
		return nil, domain.ErrInvalidClientCredentials
	}
	if key.Status != "active" || key.RevokedAt != nil {
		return nil, domain.ErrInvalidClientCredentials
	}
	if key.ExpiresAt != nil && time.Now().UTC().After(*key.ExpiresAt) {
		return nil, domain.ErrInvalidClientCredentials
	}
	account, err := s.accounts.GetServiceAccount(ctx, key.ClientID, serviceAccountID)
	if err != nil || account.Status != "active" {
		return nil, domain.ErrInvalidClientCredentials
	}
	client, err := s.clients.GetByID(ctx, account.ClientID)
	if err != nil || client.Status != "active" {
		return nil, domain.ErrInvalidClientCredentials
	}
	allowedScopes := domain.IntersectScopes(account.Scopes, key.Scopes)
	if len(allowedScopes) == 0 {
		allowedScopes = nil
	}
	scopes := requestedScopes
	if len(scopes) == 0 {
		scopes = allowedScopes
	}
	if !domain.ScopesContainAll(allowedScopes, scopes) {
		return nil, domain.ErrInvalidScope
	}
	return &validatedServiceCredential{client: client, account: account, key: key, scopes: scopes}, nil
}

func parseScopeString(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	return domain.NormalizeScopes(strings.Fields(raw))
}

func serviceAccountKeyExpiry(hours int) *time.Time {
	if hours <= 0 {
		return nil
	}
	expiresAt := time.Now().UTC().Add(time.Duration(hours) * time.Hour)
	return &expiresAt
}

func (s *M2MService) log(ctx context.Context, clientID, eventType, ip, ua string, metadata map[string]interface{}) {
	if s.audit != nil {
		s.audit.Log(ctx, clientID, nil, eventType, ip, ua, metadata)
	}
}
