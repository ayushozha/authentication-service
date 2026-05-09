package application

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"math/big"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type EnterpriseSSOService struct {
	sso      EnterpriseSSORepository
	users    UserRepository
	clients  ClientRepository
	sessions SessionRepository
	cache    CacheClient
	audit    AuditRepository
}

func NewEnterpriseSSOService(sso EnterpriseSSORepository, users UserRepository, clients ClientRepository, sessions SessionRepository, cache CacheClient, audit AuditRepository) *EnterpriseSSOService {
	return &EnterpriseSSOService{sso: sso, users: users, clients: clients, sessions: sessions, cache: cache, audit: audit}
}

type CreateEnterpriseSSOConnectionRequest struct {
	Name              string                         `json:"name"`
	Slug              string                         `json:"slug"`
	Protocol          string                         `json:"protocol"`
	Status            string                         `json:"status"`
	Domains           []string                       `json:"domains"`
	EnforceForDomains bool                           `json:"enforce_for_domains"`
	OIDC              domain.EnterpriseSSOOIDCConfig `json:"oidc,omitempty"`
	SAML              domain.EnterpriseSSOSAMLConfig `json:"saml,omitempty"`
	AttributeMapping  map[string]string              `json:"attribute_mapping,omitempty"`
}

type UpdateEnterpriseSSOConnectionRequest struct {
	Name              *string                         `json:"name,omitempty"`
	Slug              *string                         `json:"slug,omitempty"`
	Status            *string                         `json:"status,omitempty"`
	Domains           []string                        `json:"domains,omitempty"`
	EnforceForDomains *bool                           `json:"enforce_for_domains,omitempty"`
	OIDC              *domain.EnterpriseSSOOIDCConfig `json:"oidc,omitempty"`
	SAML              *domain.EnterpriseSSOSAMLConfig `json:"saml,omitempty"`
	AttributeMapping  map[string]string               `json:"attribute_mapping,omitempty"`
}

type BeginEnterpriseSSOLoginRequest struct {
	ConnectionID string `json:"connection_id,omitempty"`
	Domain       string `json:"domain,omitempty"`
	SessionMode  string `json:"session_mode,omitempty"`
}

type enterpriseSSOStatePayload struct {
	ClientID     string `json:"client_id"`
	ConnectionID string `json:"connection_id"`
	Protocol     string `json:"protocol"`
	RedirectURI  string `json:"redirect_uri"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	RequestID    string `json:"request_id"`
	SessionMode  string `json:"session_mode"`
	CreatedAt    int64  `json:"created_at"`
}

type enterpriseSSOProfile struct {
	ExternalID    string
	Email         string
	EmailVerified bool
	DisplayName   string
	AvatarURL     string
	RawProfile    []byte
}

func (s *EnterpriseSSOService) CreateConnection(ctx context.Context, clientID string, req CreateEnterpriseSSOConnectionRequest, baseURL string) (*domain.EnterpriseSSOConnection, error) {
	now := time.Now().UTC()
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	slug := normalizeSlug(req.Slug)
	if slug == "" {
		slug = normalizeSlug(name)
	}
	protocol := strings.ToLower(strings.TrimSpace(req.Protocol))
	if protocol != domain.SSOProtocolOIDC && protocol != domain.SSOProtocolSAML {
		return nil, domain.ErrInvalidSSOConnection
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status == "" {
		status = domain.SSOConnectionStatusActive
	}
	if status != domain.SSOConnectionStatusActive && status != domain.SSOConnectionStatusInactive {
		return nil, domain.ErrInvalidSSOConnection
	}

	connection := &domain.EnterpriseSSOConnection{
		ID:                uuid.NewString(),
		ClientID:          clientID,
		Name:              name,
		Slug:              slug,
		Protocol:          protocol,
		Status:            status,
		Domains:           domain.NormalizeSSODomains(req.Domains),
		EnforceForDomains: req.EnforceForDomains,
		AttributeMapping:  normalizeSSOAttributeMapping(req.AttributeMapping),
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	switch protocol {
	case domain.SSOProtocolOIDC:
		oidcConfig, err := normalizeOIDCConfig(req.OIDC)
		if err != nil {
			return nil, err
		}
		connection.OIDC = oidcConfig
	case domain.SSOProtocolSAML:
		samlConfig, err := normalizeSAMLConfig(req.SAML, baseURL, connection.ID)
		if err != nil {
			return nil, err
		}
		connection.SAML = samlConfig
	}

	if err := s.sso.CreateConnection(ctx, connection); err != nil {
		return nil, err
	}
	if s.audit != nil {
		s.audit.Log(ctx, clientID, nil, "enterprise_sso_connection_created", "", "", map[string]interface{}{"connection_id": connection.ID, "protocol": connection.Protocol})
	}
	return connection, nil
}

func (s *EnterpriseSSOService) ListConnections(ctx context.Context, clientID string) ([]*domain.EnterpriseSSOConnection, error) {
	return s.sso.ListConnections(ctx, clientID)
}

func (s *EnterpriseSSOService) GetConnection(ctx context.Context, clientID, connectionID string) (*domain.EnterpriseSSOConnection, error) {
	return s.sso.GetConnection(ctx, clientID, connectionID)
}

func (s *EnterpriseSSOService) UpdateConnection(ctx context.Context, clientID, connectionID string, req UpdateEnterpriseSSOConnectionRequest, baseURL string) (*domain.EnterpriseSSOConnection, error) {
	connection, err := s.sso.GetConnection(ctx, clientID, connectionID)
	if err != nil {
		return nil, err
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			return nil, fmt.Errorf("name is required")
		}
		connection.Name = name
	}
	if req.Slug != nil {
		slug := normalizeSlug(*req.Slug)
		if slug == "" {
			return nil, fmt.Errorf("slug is required")
		}
		connection.Slug = slug
	}
	if req.Status != nil {
		status := strings.ToLower(strings.TrimSpace(*req.Status))
		if status != domain.SSOConnectionStatusActive && status != domain.SSOConnectionStatusInactive {
			return nil, domain.ErrInvalidSSOConnection
		}
		connection.Status = status
	}
	if req.Domains != nil {
		connection.Domains = domain.NormalizeSSODomains(req.Domains)
	}
	if req.EnforceForDomains != nil {
		connection.EnforceForDomains = *req.EnforceForDomains
	}
	if req.AttributeMapping != nil {
		connection.AttributeMapping = normalizeSSOAttributeMapping(req.AttributeMapping)
	}
	if req.OIDC != nil {
		if connection.Protocol != domain.SSOProtocolOIDC {
			return nil, domain.ErrInvalidSSOConnection
		}
		oidcConfig := *req.OIDC
		if strings.TrimSpace(oidcConfig.ClientSecret) == "" {
			oidcConfig.ClientSecret = connection.OIDC.ClientSecret
		}
		connection.OIDC, err = normalizeOIDCConfig(oidcConfig)
		if err != nil {
			return nil, err
		}
	}
	if req.SAML != nil {
		if connection.Protocol != domain.SSOProtocolSAML {
			return nil, domain.ErrInvalidSSOConnection
		}
		samlConfig := *req.SAML
		if strings.TrimSpace(samlConfig.SPPrivateKeyPEM) == "" {
			samlConfig.SPPrivateKeyPEM = connection.SAML.SPPrivateKeyPEM
		}
		if strings.TrimSpace(samlConfig.SPCertificatePEM) == "" {
			samlConfig.SPCertificatePEM = connection.SAML.SPCertificatePEM
		}
		connection.SAML, err = normalizeSAMLConfig(samlConfig, baseURL, connection.ID)
		if err != nil {
			return nil, err
		}
	}
	connection.UpdatedAt = time.Now().UTC()
	if err := s.sso.UpdateConnection(ctx, connection); err != nil {
		return nil, err
	}
	if s.audit != nil {
		s.audit.Log(ctx, clientID, nil, "enterprise_sso_connection_updated", "", "", map[string]interface{}{"connection_id": connection.ID})
	}
	return connection, nil
}

func (s *EnterpriseSSOService) DeactivateConnection(ctx context.Context, clientID, connectionID string) error {
	if err := s.sso.DeactivateConnection(ctx, clientID, connectionID); err != nil {
		return err
	}
	if s.audit != nil {
		s.audit.Log(ctx, clientID, nil, "enterprise_sso_connection_deactivated", "", "", map[string]interface{}{"connection_id": connectionID})
	}
	return nil
}

func (s *EnterpriseSSOService) BeginLogin(ctx context.Context, client *domain.Client, req BeginEnterpriseSSOLoginRequest, baseURL string) (string, error) {
	if s.cache == nil {
		return "", domain.ErrRedisRequired
	}
	connection, err := s.resolveConnection(ctx, client.ID, req)
	if err != nil {
		return "", err
	}
	if connection.Status != domain.SSOConnectionStatusActive {
		return "", domain.ErrInvalidSSOConnection
	}

	state, err := GenerateToken(18)
	if err != nil {
		return "", err
	}
	payload := enterpriseSSOStatePayload{
		ClientID:     client.ID,
		ConnectionID: connection.ID,
		Protocol:     connection.Protocol,
		SessionMode:  strings.ToLower(strings.TrimSpace(req.SessionMode)),
		CreatedAt:    time.Now().UTC().Unix(),
	}

	switch connection.Protocol {
	case domain.SSOProtocolOIDC:
		payload.RedirectURI = callbackURL(baseURL, connection.ID)
		payload.Nonce, err = GenerateToken(16)
		if err != nil {
			return "", err
		}
		payload.CodeVerifier, err = GenerateToken(32)
		if err != nil {
			return "", err
		}
		if err := s.storeState(ctx, state, payload); err != nil {
			return "", err
		}
		return oidcRedirectURL(ctx, connection, state, payload.Nonce, payload.CodeVerifier, payload.RedirectURI)
	case domain.SSOProtocolSAML:
		sp, err := s.samlServiceProvider(connection)
		if err != nil {
			return "", err
		}
		authnReq, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
		if err != nil {
			return "", err
		}
		payload.RequestID = authnReq.ID
		if err := s.storeState(ctx, state, payload); err != nil {
			return "", err
		}
		redirectURL, err := authnReq.Redirect(state, sp)
		if err != nil {
			return "", err
		}
		return redirectURL.String(), nil
	default:
		return "", domain.ErrInvalidSSOConnection
	}
}

func (s *EnterpriseSSOService) HandleOIDCCallback(ctx context.Context, connectionID, code, state, ip, ua string, accessTTL, refreshTTL time.Duration) (*AuthResponse, string, error) {
	if strings.TrimSpace(code) == "" || strings.TrimSpace(state) == "" {
		return nil, "", domain.ErrInvalidToken
	}
	payload, err := s.consumeState(ctx, state)
	if err != nil {
		return nil, "", err
	}
	if payload.ConnectionID != connectionID || payload.Protocol != domain.SSOProtocolOIDC {
		return nil, "", domain.ErrInvalidToken
	}
	client, connection, err := s.loadCallbackContext(ctx, payload.ClientID, connectionID)
	if err != nil {
		return nil, "", err
	}

	profile, err := exchangeOIDCProfile(ctx, connection, code, payload.CodeVerifier, payload.Nonce, payload.RedirectURI)
	if err != nil {
		return nil, "", err
	}
	return s.completeLogin(ctx, client, connection, profile, ip, ua, accessTTL, refreshTTL)
}

func (s *EnterpriseSSOService) HandleSAMLCallback(ctx context.Context, r *http.Request, connectionID, ip, ua string, accessTTL, refreshTTL time.Duration) (*AuthResponse, string, error) {
	if s.cache == nil {
		return nil, "", domain.ErrRedisRequired
	}
	if err := r.ParseForm(); err != nil {
		return nil, "", domain.ErrInvalidToken
	}
	state := r.FormValue("RelayState")
	payload, err := s.consumeState(ctx, state)
	if err != nil {
		return nil, "", err
	}
	if payload.ConnectionID != connectionID || payload.Protocol != domain.SSOProtocolSAML {
		return nil, "", domain.ErrInvalidToken
	}
	client, connection, err := s.loadCallbackContext(ctx, payload.ClientID, connectionID)
	if err != nil {
		return nil, "", err
	}
	sp, err := s.samlServiceProvider(connection)
	if err != nil {
		return nil, "", err
	}
	assertion, err := sp.ParseResponse(r, []string{payload.RequestID})
	if err != nil {
		return nil, "", fmt.Errorf("saml_response_invalid")
	}
	profile, err := samlProfile(connection, assertion)
	if err != nil {
		return nil, "", err
	}
	return s.completeLogin(ctx, client, connection, profile, ip, ua, accessTTL, refreshTTL)
}

func (s *EnterpriseSSOService) SAMLMetadata(ctx context.Context, connectionID string) ([]byte, error) {
	connection, err := s.sso.GetConnectionByID(ctx, connectionID)
	if err != nil {
		return nil, err
	}
	if connection.Protocol != domain.SSOProtocolSAML {
		return nil, domain.ErrInvalidSSOConnection
	}
	sp, err := s.samlServiceProvider(connection)
	if err != nil {
		return nil, err
	}
	return xml.MarshalIndent(sp.Metadata(), "", "  ")
}

func (s *EnterpriseSSOService) resolveConnection(ctx context.Context, clientID string, req BeginEnterpriseSSOLoginRequest) (*domain.EnterpriseSSOConnection, error) {
	if domainName := domain.NormalizeSSODomains([]string{req.Domain}); len(domainName) == 1 {
		return s.sso.GetActiveConnectionByDomain(ctx, clientID, domainName[0])
	}
	connectionID := strings.TrimSpace(req.ConnectionID)
	if connectionID == "" {
		return nil, domain.ErrInvalidSSOConnection
	}
	connection, err := s.sso.GetConnection(ctx, clientID, connectionID)
	if err == domain.ErrNotFound {
		return s.sso.GetConnectionBySlug(ctx, clientID, normalizeSlug(connectionID))
	}
	return connection, err
}

func (s *EnterpriseSSOService) storeState(ctx context.Context, state string, payload enterpriseSSOStatePayload) error {
	serialized, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.cache.Set(ctx, "sso_state:"+HashToken(state), string(serialized), 10*time.Minute)
}

func (s *EnterpriseSSOService) consumeState(ctx context.Context, state string) (enterpriseSSOStatePayload, error) {
	var payload enterpriseSSOStatePayload
	if strings.TrimSpace(state) == "" {
		return payload, domain.ErrInvalidToken
	}
	cacheKey := "sso_state:" + HashToken(state)
	raw, err := s.cache.Get(ctx, cacheKey)
	if err != nil || raw == "" {
		return payload, domain.ErrInvalidToken
	}
	_ = s.cache.Del(ctx, cacheKey)
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return payload, domain.ErrInvalidToken
	}
	return payload, nil
}

func (s *EnterpriseSSOService) loadCallbackContext(ctx context.Context, clientID, connectionID string) (*domain.Client, *domain.EnterpriseSSOConnection, error) {
	client, err := s.clients.GetByID(ctx, clientID)
	if err != nil || client == nil || client.Status != "active" {
		return nil, nil, domain.ErrInvalidClient
	}
	connection, err := s.sso.GetConnection(ctx, clientID, connectionID)
	if err != nil {
		return nil, nil, err
	}
	if connection.Status != domain.SSOConnectionStatusActive {
		return nil, nil, domain.ErrInvalidSSOConnection
	}
	return client, connection, nil
}

func (s *EnterpriseSSOService) completeLogin(ctx context.Context, client *domain.Client, connection *domain.EnterpriseSSOConnection, profile enterpriseSSOProfile, ip, ua string, accessTTL, refreshTTL time.Duration) (*AuthResponse, string, error) {
	profile.Email = strings.ToLower(strings.TrimSpace(profile.Email))
	if profile.ExternalID == "" || profile.Email == "" {
		return nil, "", domain.ErrInvalidSSOConnection
	}
	if _, err := mail.ParseAddress(profile.Email); err != nil {
		return nil, "", domain.ErrInvalidSSOConnection
	}
	if !domain.SSODomainAllowed(profile.Email, connection.Domains) {
		return nil, "", domain.ErrSSODomainNotAllowed
	}

	identity, err := s.sso.FindIdentity(ctx, client.ID, connection.ID, profile.ExternalID)
	if err != nil && err != domain.ErrNotFound {
		return nil, "", err
	}

	var user *domain.User
	if identity != nil {
		user, err = s.users.GetByID(ctx, identity.UserID)
		if err != nil {
			return nil, "", err
		}
	} else {
		user, _ = s.users.GetByEmail(ctx, client.ID, profile.Email)
		if user == nil {
			displayName := strings.TrimSpace(profile.DisplayName)
			if displayName == "" {
				displayName = strings.Split(profile.Email, "@")[0]
			}
			user, err = s.users.CreateOAuth(ctx, client.ID, profile.Email, displayName, profile.AvatarURL)
			if err != nil {
				return nil, "", err
			}
			uid := user.ID
			if s.audit != nil {
				s.audit.Log(ctx, client.ID, &uid, "signup", ip, ua, map[string]interface{}{"method": "enterprise_sso", "connection_id": connection.ID, "protocol": connection.Protocol})
			}
		}
	}
	if user.Status != "active" {
		return nil, "", domain.ErrAccountSuspended
	}
	if !user.EmailVerified && profile.EmailVerified {
		_ = s.users.VerifyEmail(ctx, user.ID)
	}

	rawProfile := profile.RawProfile
	if len(rawProfile) == 0 {
		rawProfile = []byte("{}")
	}
	if err := s.sso.UpsertIdentity(ctx, &domain.EnterpriseSSOIdentity{
		ClientID:     client.ID,
		ConnectionID: connection.ID,
		UserID:       user.ID,
		ExternalID:   profile.ExternalID,
		Email:        profile.Email,
		RawProfile:   rawProfile,
	}); err != nil {
		return nil, "", err
	}

	_ = s.users.UpdateLastLogin(ctx, user.ID)
	uid := user.ID
	if s.audit != nil {
		s.audit.Log(ctx, client.ID, &uid, "login_success", ip, ua, map[string]interface{}{"method": "enterprise_sso", "connection_id": connection.ID, "protocol": connection.Protocol})
	}

	accessToken, err := CreateAccessToken(ctx, client, accessTTL, user)
	if err != nil {
		return nil, "", err
	}
	refreshToken, err := s.sessions.Create(ctx, user.ID, client.ID, ip, ua, refreshTTL)
	if err != nil {
		return nil, "", err
	}
	return &AuthResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(accessTTL.Seconds()),
		User:        user,
	}, refreshToken, nil
}

func (s *EnterpriseSSOService) samlServiceProvider(connection *domain.EnterpriseSSOConnection) (*saml.ServiceProvider, error) {
	if connection.Protocol != domain.SSOProtocolSAML {
		return nil, domain.ErrInvalidSSOConnection
	}
	spKey, err := parseRSAPrivateKey(connection.SAML.SPPrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	spCert, err := parseCertificatePEM(connection.SAML.SPCertificatePEM)
	if err != nil {
		return nil, err
	}
	metadataURL, err := url.Parse(connection.SAML.SPMetadataURL)
	if err != nil {
		return nil, err
	}
	acsURL, err := url.Parse(connection.SAML.ACSURL)
	if err != nil {
		return nil, err
	}
	idpMetadata, err := samlIDPMetadata(connection.SAML)
	if err != nil {
		return nil, err
	}
	var idpCert *string
	if strings.TrimSpace(connection.SAML.IDPCertificate) != "" {
		cert := connection.SAML.IDPCertificate
		idpCert = &cert
	}
	return &saml.ServiceProvider{
		EntityID:              connection.SAML.SPEntityID,
		Key:                   spKey,
		Certificate:           spCert,
		MetadataURL:           *metadataURL,
		AcsURL:                *acsURL,
		IDPMetadata:           idpMetadata,
		IDPCertificate:        idpCert,
		AuthnNameIDFormat:     saml.PersistentNameIDFormat,
		AllowIDPInitiated:     false,
		MetadataValidDuration: 24 * time.Hour,
	}, nil
}

func oidcRedirectURL(ctx context.Context, connection *domain.EnterpriseSSOConnection, state, nonce, codeVerifier, redirectURI string) (string, error) {
	provider, err := oidc.NewProvider(ctx, connection.OIDC.Issuer)
	if err != nil {
		return "", err
	}
	config := oauth2.Config{
		ClientID:     connection.OIDC.ClientID,
		ClientSecret: connection.OIDC.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       connection.OIDC.Scopes,
	}
	return config.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(codeVerifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

func exchangeOIDCProfile(ctx context.Context, connection *domain.EnterpriseSSOConnection, code, codeVerifier, nonce, redirectURI string) (enterpriseSSOProfile, error) {
	provider, err := oidc.NewProvider(ctx, connection.OIDC.Issuer)
	if err != nil {
		return enterpriseSSOProfile{}, err
	}
	config := oauth2.Config{
		ClientID:     connection.OIDC.ClientID,
		ClientSecret: connection.OIDC.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       connection.OIDC.Scopes,
	}
	token, err := config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return enterpriseSSOProfile{}, fmt.Errorf("oidc_exchange_failed")
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return enterpriseSSOProfile{}, fmt.Errorf("oidc_missing_id_token")
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: connection.OIDC.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return enterpriseSSOProfile{}, fmt.Errorf("oidc_id_token_invalid")
	}
	if idToken.Nonce != nonce {
		return enterpriseSSOProfile{}, fmt.Errorf("oidc_nonce_invalid")
	}

	var claims struct {
		Subject           string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Picture           string `json:"picture"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return enterpriseSSOProfile{}, err
	}
	rawClaims, _ := json.Marshal(claims)
	profile := enterpriseSSOProfile{
		ExternalID:    firstNonEmpty(claims.Subject, idToken.Subject),
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		DisplayName:   firstNonEmpty(claims.Name, claims.PreferredUsername),
		AvatarURL:     claims.Picture,
		RawProfile:    rawClaims,
	}
	if profile.Email == "" {
		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err == nil && userInfo != nil {
			var infoClaims struct {
				Name              string `json:"name"`
				PreferredUsername string `json:"preferred_username"`
				Picture           string `json:"picture"`
			}
			_ = userInfo.Claims(&infoClaims)
			profile.Email = userInfo.Email
			profile.EmailVerified = userInfo.EmailVerified
			profile.DisplayName = firstNonEmpty(profile.DisplayName, infoClaims.Name, infoClaims.PreferredUsername)
			profile.AvatarURL = firstNonEmpty(profile.AvatarURL, infoClaims.Picture)
			profile.RawProfile, _ = json.Marshal(map[string]interface{}{
				"id_token": claims,
				"userinfo": infoClaims,
				"subject":  userInfo.Subject,
				"email":    userInfo.Email,
				"verified": userInfo.EmailVerified,
			})
		}
	}
	return profile, nil
}

func samlProfile(connection *domain.EnterpriseSSOConnection, assertion *saml.Assertion) (enterpriseSSOProfile, error) {
	attrs := map[string]string{}
	for _, statement := range assertion.AttributeStatements {
		for _, attr := range statement.Attributes {
			value := ""
			if len(attr.Values) > 0 {
				value = strings.TrimSpace(attr.Values[0].Value)
			}
			if value == "" {
				continue
			}
			if attr.Name != "" {
				attrs[attr.Name] = value
			}
			if attr.FriendlyName != "" {
				attrs[attr.FriendlyName] = value
			}
		}
	}

	nameID := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		nameID = strings.TrimSpace(assertion.Subject.NameID.Value)
	}
	mapping := normalizeSSOAttributeMapping(connection.AttributeMapping)
	email := firstNonEmpty(
		attrs[mapping["email"]],
		attrs["email"],
		attrs["Email"],
		attrs["mail"],
		attrs["urn:oid:0.9.2342.19200300.100.1.3"],
		attrs["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"],
	)
	displayName := firstNonEmpty(
		attrs[mapping["name"]],
		attrs["name"],
		attrs["displayName"],
		attrs["cn"],
		attrs["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"],
	)
	externalID := firstNonEmpty(
		attrs[mapping["external_id"]],
		attrs["uid"],
		attrs["NameID"],
		nameID,
		email,
	)
	rawProfile, _ := json.Marshal(attrs)
	return enterpriseSSOProfile{
		ExternalID:    externalID,
		Email:         email,
		EmailVerified: true,
		DisplayName:   displayName,
		RawProfile:    rawProfile,
	}, nil
}

func normalizeOIDCConfig(cfg domain.EnterpriseSSOOIDCConfig) (domain.EnterpriseSSOOIDCConfig, error) {
	cfg.Issuer = strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.ClientSecret = strings.TrimSpace(cfg.ClientSecret)
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return cfg, domain.ErrInvalidSSOConnection
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	scopes, err := domain.NormalizeScopes(cfg.Scopes)
	if err != nil {
		return cfg, err
	}
	cfg.Scopes = scopes
	if !domain.ScopesContainAll(cfg.Scopes, []string{"openid"}) {
		cfg.Scopes = append([]string{"openid"}, cfg.Scopes...)
	}
	return cfg, nil
}

func normalizeSAMLConfig(cfg domain.EnterpriseSSOSAMLConfig, baseURL, connectionID string) (domain.EnterpriseSSOSAMLConfig, error) {
	cfg.IDPEntityID = strings.TrimSpace(cfg.IDPEntityID)
	cfg.IDPSSOURL = strings.TrimSpace(cfg.IDPSSOURL)
	cfg.IDPMetadataXML = strings.TrimSpace(cfg.IDPMetadataXML)
	cfg.SPEntityID = strings.TrimSpace(cfg.SPEntityID)
	cfg.SPMetadataURL = strings.TrimSpace(cfg.SPMetadataURL)
	cfg.ACSURL = strings.TrimSpace(cfg.ACSURL)

	if cfg.IDPMetadataXML != "" {
		metadata, err := samlsp.ParseMetadata([]byte(cfg.IDPMetadataXML))
		if err != nil {
			return cfg, err
		}
		cfg.IDPEntityID = firstNonEmpty(cfg.IDPEntityID, metadata.EntityID)
		if cfg.IDPSSOURL == "" && len(metadata.IDPSSODescriptors) > 0 {
			for _, endpoint := range metadata.IDPSSODescriptors[0].SingleSignOnServices {
				if endpoint.Binding == saml.HTTPRedirectBinding {
					cfg.IDPSSOURL = endpoint.Location
					break
				}
			}
			if cfg.IDPSSOURL == "" && len(metadata.IDPSSODescriptors[0].SingleSignOnServices) > 0 {
				cfg.IDPSSOURL = metadata.IDPSSODescriptors[0].SingleSignOnServices[0].Location
			}
		}
	}
	if cfg.IDPCertificate != "" {
		cert, err := normalizeSAMLX509Certificate(cfg.IDPCertificate)
		if err != nil {
			return cfg, err
		}
		cfg.IDPCertificate = cert
	}
	if cfg.IDPEntityID == "" || cfg.IDPSSOURL == "" || (cfg.IDPMetadataXML == "" && cfg.IDPCertificate == "") {
		return cfg, domain.ErrInvalidSSOConnection
	}

	if cfg.SPEntityID == "" {
		cfg.SPEntityID = strings.TrimRight(baseURL, "/") + "/api/auth/sso/metadata/" + connectionID
	}
	if cfg.SPMetadataURL == "" {
		cfg.SPMetadataURL = strings.TrimRight(baseURL, "/") + "/api/auth/sso/metadata/" + connectionID
	}
	if cfg.ACSURL == "" {
		cfg.ACSURL = callbackURL(baseURL, connectionID)
	}
	if cfg.SPPrivateKeyPEM == "" || cfg.SPCertificatePEM == "" {
		keyPEM, certPEM, err := generateSAMLSPCertificate(connectionID)
		if err != nil {
			return cfg, err
		}
		cfg.SPPrivateKeyPEM = keyPEM
		cfg.SPCertificatePEM = certPEM
	}
	return cfg, nil
}

func normalizeSSOAttributeMapping(mapping map[string]string) map[string]string {
	out := map[string]string{
		"email":       "email",
		"name":        "name",
		"external_id": "external_id",
	}
	for key, value := range mapping {
		k := strings.ToLower(strings.TrimSpace(key))
		v := strings.TrimSpace(value)
		if k != "" && v != "" {
			out[k] = v
		}
	}
	return out
}

func samlIDPMetadata(cfg domain.EnterpriseSSOSAMLConfig) (*saml.EntityDescriptor, error) {
	if cfg.IDPMetadataXML != "" {
		return samlsp.ParseMetadata([]byte(cfg.IDPMetadataXML))
	}
	return &saml.EntityDescriptor{
		EntityID: cfg.IDPEntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor: saml.RoleDescriptor{
					ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
				},
				NameIDFormats: []saml.NameIDFormat{saml.PersistentNameIDFormat, saml.EmailAddressNameIDFormat},
			},
			SingleSignOnServices: []saml.Endpoint{{
				Binding:  saml.HTTPRedirectBinding,
				Location: cfg.IDPSSOURL,
			}},
		}},
	}, nil
}

func normalizeSAMLX509Certificate(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "BEGIN CERTIFICATE") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return "", fmt.Errorf("invalid certificate")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(block.Bytes), nil
	}
	cleaned := strings.Join(strings.Fields(trimmed), "")
	raw, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return "", err
	}
	if _, err := x509.ParseCertificate(raw); err != nil {
		return "", err
	}
	return cleaned, nil
}

func parseCertificatePEM(value string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, fmt.Errorf("invalid certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func generateSAMLSPCertificate(connectionID string) (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	now := time.Now().UTC()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "authservice-saml-" + connectionID,
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return string(keyPEM), string(certPEM), nil
}

func callbackURL(baseURL, connectionID string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	return base + "/api/auth/sso/callback/" + connectionID
}

func normalizeSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash && b.Len() > 0 {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
