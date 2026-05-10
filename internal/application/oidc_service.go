package application

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

const (
	oidcCodeTTL             = 10 * time.Minute
	oidcDefaultIDTokenTTL   = 15 * time.Minute
	oidcDefaultACR          = "urn:authservice:acr:loa1"
	oidcCodeChallengeS256   = "S256"
	oidcCodeChallengePlain  = "plain"
	oidcPromptNone          = "none"
	oidcPromptLogin         = "login"
	oidcPromptConsent       = "consent"
	oidcConsentAccept       = "accept"
	oidcRefreshContextSlack = 5 * time.Minute
)

var defaultOIDCScopes = []string{"openid", "profile", "email", "offline_access"}

type OIDCService struct {
	clients  ClientRepository
	users    UserRepository
	sessions SessionRepository
	cache    CacheClient
	audit    AuditRepository
}

func NewOIDCService(clients ClientRepository, users UserRepository, sessions SessionRepository, cache CacheClient, audit AuditRepository) *OIDCService {
	return &OIDCService{clients: clients, users: users, sessions: sessions, cache: cache, audit: audit}
}

type OAuthError struct {
	Code        string
	Description string
	Status      int
	RedirectURI string
	State       string
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

type OIDCClientConfig struct {
	Enabled                bool
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	AllowedScopes          []string
	Audiences              []string
	Trusted                bool
	RequireConsent         bool
	RequirePKCE            bool
	PublicClient           bool
	ClientSecret           string
	LoginURL               string
	AllowedACRValues       []string
}

type OIDCAuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
	MaxAge              string
	ACRValues           string
	Audience            string
	Resources           []string
	Consent             string
}

type OIDCAuthorizeResult struct {
	Client        *domain.Client
	User          *domain.User
	RedirectURL   string
	NeedsLogin    bool
	NeedsConsent  bool
	Scopes        []string
	Audiences     []string
	AuthTime      time.Time
	ACR           string
	AMR           []string
	LoginURL      string
	ConsentClient string
}

type oidcCodePayload struct {
	ClientID            string   `json:"client_id"`
	UserID              string   `json:"user_id"`
	RedirectURI         string   `json:"redirect_uri"`
	Scopes              []string `json:"scopes"`
	Audiences           []string `json:"audiences"`
	Nonce               string   `json:"nonce,omitempty"`
	CodeChallenge       string   `json:"code_challenge,omitempty"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty"`
	AuthTime            int64    `json:"auth_time"`
	ACR                 string   `json:"acr"`
	AMR                 []string `json:"amr"`
	CreatedAt           int64    `json:"created_at"`
}

type oidcRefreshContext struct {
	ClientID  string   `json:"client_id"`
	UserID    string   `json:"user_id"`
	Scopes    []string `json:"scopes"`
	Audiences []string `json:"audiences"`
	AuthTime  int64    `json:"auth_time"`
	ACR       string   `json:"acr"`
	AMR       []string `json:"amr"`
}

type OIDCTokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	RefreshToken string
	Scope        string
}

type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

type IDTokenClaims struct {
	jwt.RegisteredClaims
	AuthorizedParty   string   `json:"azp,omitempty"`
	Nonce             string   `json:"nonce,omitempty"`
	AuthTime          int64    `json:"auth_time,omitempty"`
	ACR               string   `json:"acr,omitempty"`
	AMR               []string `json:"amr,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     bool     `json:"email_verified,omitempty"`
	Name              string   `json:"name,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Locale            string   `json:"locale,omitempty"`
	ZoneInfo          string   `json:"zoneinfo,omitempty"`
	Picture           string   `json:"picture,omitempty"`
}

type IDTokenOptions struct {
	Nonce    string
	AuthTime int64
	ACR      string
	AMR      []string
}

type OIDCUserInfoResponse struct {
	Subject           string `json:"sub"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Picture           string `json:"picture,omitempty"`
	Locale            string `json:"locale,omitempty"`
	ZoneInfo          string `json:"zoneinfo,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
}

type OIDCIntrospectionResponse struct {
	Active          bool     `json:"active"`
	Scope           string   `json:"scope,omitempty"`
	ClientID        string   `json:"client_id,omitempty"`
	Subject         string   `json:"sub,omitempty"`
	TokenType       string   `json:"token_type,omitempty"`
	TokenUse        string   `json:"token_use,omitempty"`
	Audience        []string `json:"aud,omitempty"`
	Issuer          string   `json:"iss,omitempty"`
	ExpiresAt       int64    `json:"exp,omitempty"`
	IssuedAt        int64    `json:"iat,omitempty"`
	NotBefore       int64    `json:"nbf,omitempty"`
	JWTID           string   `json:"jti,omitempty"`
	Username        string   `json:"username,omitempty"`
	Error           string   `json:"error,omitempty"`
	ServiceClientID string   `json:"service_client_id,omitempty"`
}

type OIDCRevocationRequest struct {
	Token         string
	TokenTypeHint string
	ClientID      string
	ClientSecret  string
}

type OIDCLogoutRequest struct {
	IDTokenHint           string
	ClientID              string
	PostLogoutRedirectURI string
	State                 string
}

type OIDCLogoutResponse struct {
	RedirectURL string
}

func OIDCDiscovery(issuer string) map[string]interface{} {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	return map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"revocation_endpoint":                   issuer + "/revoke",
		"introspection_endpoint":                issuer + "/introspect",
		"end_session_endpoint":                  issuer + "/logout",
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic", "client_secret_post"},
		"scopes_supported":                      defaultOIDCScopes,
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "jti", "azp", "nonce", "auth_time", "acr", "amr",
			"email", "email_verified", "name", "preferred_username", "picture", "locale", "zoneinfo", "updated_at",
		},
		"code_challenge_methods_supported": []string{oidcCodeChallengeS256, oidcCodeChallengePlain},
		"acr_values_supported":             []string{oidcDefaultACR},
	}
}

func (s *OIDCService) Authorize(ctx context.Context, req OIDCAuthorizeRequest, sessionToken, bearerToken, issuer, ip, ua string) (*OIDCAuthorizeResult, error) {
	if s == nil {
		return nil, oauthErr("server_error", "OIDC provider is not configured", 503)
	}
	client, cfg, err := s.loadOIDCClient(ctx, req.ClientID)
	if err != nil {
		return nil, err
	}
	redirectURI, err := validateRedirectURI(req.RedirectURI, cfg.RedirectURIs)
	if err != nil {
		return nil, err
	}
	if req.ResponseType != "code" {
		return nil, redirectOAuthErr("unsupported_response_type", "only response_type=code is supported", redirectURI, req.State)
	}
	scopes, err := normalizeOIDCScopes(req.Scope, cfg.AllowedScopes)
	if err != nil {
		return nil, redirectOAuthErr("invalid_scope", err.Error(), redirectURI, req.State)
	}
	audiences, err := normalizeOIDCAudiences(client.ID, req.Audience, req.Resources, cfg.Audiences)
	if err != nil {
		return nil, redirectOAuthErr("invalid_target", err.Error(), redirectURI, req.State)
	}
	method := strings.TrimSpace(req.CodeChallengeMethod)
	if method == "" && strings.TrimSpace(req.CodeChallenge) != "" {
		method = oidcCodeChallengePlain
	}
	if cfg.RequirePKCE && strings.TrimSpace(req.CodeChallenge) == "" {
		return nil, redirectOAuthErr("invalid_request", "code_challenge is required", redirectURI, req.State)
	}
	if strings.TrimSpace(req.CodeChallenge) != "" {
		if method != oidcCodeChallengeS256 && method != oidcCodeChallengePlain {
			return nil, redirectOAuthErr("invalid_request", "unsupported code_challenge_method", redirectURI, req.State)
		}
	}

	prompts := promptSet(req.Prompt)
	if prompts[oidcPromptNone] && len(prompts) > 1 {
		return nil, redirectOAuthErr("invalid_request", "prompt=none cannot be combined with other prompt values", redirectURI, req.State)
	}

	user, authTime, sessionID, err := s.authorizedUser(ctx, client, sessionToken, bearerToken)
	if err != nil {
		return nil, redirectOAuthErr("access_denied", err.Error(), redirectURI, req.State)
	}
	if user == nil || prompts[oidcPromptLogin] {
		if prompts[oidcPromptNone] {
			return nil, redirectOAuthErr("login_required", "the user is not authenticated", redirectURI, req.State)
		}
		return &OIDCAuthorizeResult{
			Client:        client,
			NeedsLogin:    true,
			Scopes:        scopes,
			Audiences:     audiences,
			LoginURL:      cfg.LoginURL,
			ConsentClient: client.Name,
		}, nil
	}
	if maxAgeExceeded(req.MaxAge, authTime) {
		if prompts[oidcPromptNone] {
			return nil, redirectOAuthErr("login_required", "max_age requires re-authentication", redirectURI, req.State)
		}
		return &OIDCAuthorizeResult{Client: client, NeedsLogin: true, Scopes: scopes, Audiences: audiences, LoginURL: cfg.LoginURL, ConsentClient: client.Name}, nil
	}

	needsConsent := (cfg.RequireConsent || prompts[oidcPromptConsent]) && !cfg.Trusted
	if needsConsent && req.Consent != oidcConsentAccept {
		if prompts[oidcPromptNone] {
			return nil, redirectOAuthErr("consent_required", "user consent is required", redirectURI, req.State)
		}
		return &OIDCAuthorizeResult{
			Client:        client,
			User:          user,
			NeedsConsent:  true,
			Scopes:        scopes,
			Audiences:     audiences,
			AuthTime:      authTime,
			ACR:           resolveACR(req.ACRValues, cfg.AllowedACRValues),
			AMR:           []string{"pwd"},
			ConsentClient: client.Name,
		}, nil
	}

	code, err := GenerateToken(32)
	if err != nil {
		return nil, redirectOAuthErr("server_error", "could not generate authorization code", redirectURI, req.State)
	}
	acr := resolveACR(req.ACRValues, cfg.AllowedACRValues)
	payload := oidcCodePayload{
		ClientID:            client.ID,
		UserID:              user.ID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		Audiences:           audiences,
		Nonce:               strings.TrimSpace(req.Nonce),
		CodeChallenge:       strings.TrimSpace(req.CodeChallenge),
		CodeChallengeMethod: method,
		AuthTime:            authTime.Unix(),
		ACR:                 acr,
		AMR:                 []string{"pwd"},
		CreatedAt:           time.Now().UTC().Unix(),
	}
	if err := s.storeCode(ctx, code, payload); err != nil {
		return nil, redirectOAuthErr("server_error", err.Error(), redirectURI, req.State)
	}
	if s.audit != nil {
		uid := user.ID
		s.audit.Log(ctx, client.ID, &uid, "oidc_authorize", ip, ua, map[string]interface{}{
			"scopes":     scopes,
			"audiences":  audiences,
			"session_id": sessionID,
		})
	}

	callback, _ := url.Parse(redirectURI)
	q := callback.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	callback.RawQuery = q.Encode()
	return &OIDCAuthorizeResult{
		Client:      client,
		User:        user,
		RedirectURL: callback.String(),
		Scopes:      scopes,
		Audiences:   audiences,
		AuthTime:    authTime,
		ACR:         acr,
		AMR:         []string{"pwd"},
	}, nil
}

func (s *OIDCService) ExchangeAuthorizationCode(ctx context.Context, req OIDCTokenRequest, issuer, ip, ua string, accessTTL, refreshTTL time.Duration) (*OIDCTokenResponse, error) {
	payload, err := s.consumeCode(ctx, req.Code)
	if err != nil {
		return nil, oauthErr("invalid_grant", err.Error(), 400)
	}
	clientID := firstNonEmptyOIDC(req.ClientID, payload.ClientID)
	client, _, err := s.authenticateOIDCClient(ctx, clientID, req.ClientSecret, true)
	if err != nil {
		return nil, err
	}
	if client.ID != payload.ClientID {
		return nil, oauthErr("invalid_grant", "authorization code was not issued to this client", 400)
	}
	if strings.TrimSpace(req.RedirectURI) != payload.RedirectURI {
		return nil, oauthErr("invalid_grant", "redirect_uri does not match authorization request", 400)
	}
	if err := verifyPKCE(payload.CodeChallenge, payload.CodeChallengeMethod, req.CodeVerifier); err != nil {
		return nil, oauthErr("invalid_grant", err.Error(), 400)
	}
	user, err := s.users.GetByID(ctx, payload.UserID)
	if err != nil || user == nil || user.ClientID != client.ID {
		return nil, oauthErr("invalid_grant", "authorization code subject is invalid", 400)
	}
	return s.issueUserTokens(ctx, client, user, issuer, payload.Scopes, payload.Audiences, payload.Nonce, payload.AuthTime, payload.ACR, payload.AMR, accessTTL, refreshTTL, ip, ua)
}

func (s *OIDCService) RefreshToken(ctx context.Context, req OIDCTokenRequest, issuer, ip, ua string, accessTTL, refreshTTL time.Duration) (*OIDCTokenResponse, error) {
	client, _, err := s.authenticateOIDCClient(ctx, req.ClientID, req.ClientSecret, true)
	if err != nil {
		return nil, err
	}
	userID, sessionID, err := s.sessions.Validate(ctx, client.ID, req.RefreshToken)
	if err != nil {
		return nil, oauthErr("invalid_grant", "invalid or expired refresh_token", 400)
	}
	refreshCtx, _ := s.getRefreshContext(ctx, req.RefreshToken)
	if refreshCtx == nil {
		refreshCtx = &oidcRefreshContext{
			ClientID:  client.ID,
			UserID:    userID,
			Scopes:    []string{"openid", "profile", "email", "offline_access"},
			Audiences: []string{client.ID},
			AuthTime:  time.Now().UTC().Unix(),
			ACR:       oidcDefaultACR,
			AMR:       []string{"pwd"},
		}
	}
	if refreshCtx.ClientID != client.ID || refreshCtx.UserID != userID {
		return nil, oauthErr("invalid_grant", "refresh_token context does not match client", 400)
	}
	_ = s.sessions.Revoke(ctx, sessionID)
	_ = s.deleteRefreshContext(ctx, req.RefreshToken)
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil || user.ClientID != client.ID {
		return nil, oauthErr("invalid_grant", "refresh_token subject is invalid", 400)
	}
	return s.issueUserTokens(ctx, client, user, issuer, refreshCtx.Scopes, refreshCtx.Audiences, "", refreshCtx.AuthTime, refreshCtx.ACR, refreshCtx.AMR, accessTTL, refreshTTL, ip, ua)
}

func (s *OIDCService) UserInfo(ctx context.Context, token string) (*OIDCUserInfoResponse, error) {
	claims, client, err := s.validateBearerAccessToken(ctx, token)
	if err != nil {
		return nil, err
	}
	if claims.TokenUse == domain.TokenUseClientCredentials {
		return nil, oauthErr("invalid_token", "client credentials tokens cannot call userinfo", 401)
	}
	user, err := s.users.GetByID(ctx, claims.Subject)
	if err != nil || user == nil || user.ClientID != client.ID {
		return nil, oauthErr("invalid_token", "subject is not active", 401)
	}
	return userInfoFromUser(user, claims.Scopes), nil
}

func (s *OIDCService) IntrospectToken(ctx context.Context, token, clientID, clientSecret string) (*OIDCIntrospectionResponse, error) {
	client, _, err := s.authenticateOIDCClient(ctx, clientID, clientSecret, false)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) == "" {
		return &OIDCIntrospectionResponse{Active: false, Error: "token is required"}, nil
	}
	if claims, tokenClient, err := s.validateAccessTokenByUnverifiedClient(ctx, token); err == nil {
		if tokenClient.ID != client.ID {
			return &OIDCIntrospectionResponse{Active: false, Error: "token was not issued to this client"}, nil
		}
		if s.isJWTRevoked(ctx, claims.ID) {
			return &OIDCIntrospectionResponse{Active: false, Error: "token was revoked"}, nil
		}
		resp := &OIDCIntrospectionResponse{
			Active:    true,
			Scope:     claims.Scope,
			ClientID:  claims.ClientID,
			Subject:   claims.Subject,
			TokenType: "Bearer",
			TokenUse:  claims.TokenUse,
			Audience:  []string(claims.Audience),
			Issuer:    claims.Issuer,
			JWTID:     claims.ID,
		}
		if claims.ExpiresAt != nil {
			resp.ExpiresAt = claims.ExpiresAt.Unix()
		}
		if claims.IssuedAt != nil {
			resp.IssuedAt = claims.IssuedAt.Unix()
		}
		if claims.NotBefore != nil {
			resp.NotBefore = claims.NotBefore.Unix()
		}
		if user, err := s.users.GetByID(ctx, claims.Subject); err == nil && user != nil {
			resp.Username = user.Email
		}
		return resp, nil
	}
	if userID, _, err := s.sessions.Validate(ctx, client.ID, token); err == nil && userID != "" {
		return &OIDCIntrospectionResponse{
			Active:    true,
			ClientID:  client.ID,
			Subject:   userID,
			TokenType: "refresh_token",
		}, nil
	}
	return &OIDCIntrospectionResponse{Active: false}, nil
}

func (s *OIDCService) RevokeToken(ctx context.Context, req OIDCRevocationRequest, ip, ua string) error {
	client, _, err := s.authenticateOIDCClient(ctx, req.ClientID, req.ClientSecret, true)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		return nil
	}
	if claims, tokenClient, err := s.validateAccessTokenByUnverifiedClient(ctx, token); err == nil && tokenClient.ID == client.ID {
		_ = s.revokeJWT(ctx, claims)
		if s.audit != nil {
			s.audit.Log(ctx, client.ID, nil, "oidc_token_revoked", ip, ua, map[string]interface{}{"token_type": "access_token", "jti": claims.ID})
		}
		return nil
	}
	_ = s.sessions.RevokeByToken(ctx, client.ID, token)
	_ = s.deleteRefreshContext(ctx, token)
	if s.audit != nil {
		s.audit.Log(ctx, client.ID, nil, "oidc_token_revoked", ip, ua, map[string]interface{}{"token_type": "refresh_token"})
	}
	return nil
}

func (s *OIDCService) Logout(ctx context.Context, req OIDCLogoutRequest, refreshToken string) (*OIDCLogoutResponse, error) {
	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" && strings.TrimSpace(req.IDTokenHint) != "" {
		clientID = clientIDFromIDTokenHint(req.IDTokenHint)
	}
	var client *domain.Client
	var cfg OIDCClientConfig
	if clientID != "" {
		var err error
		client, cfg, err = s.loadOIDCClient(ctx, clientID)
		if err != nil {
			return nil, err
		}
	}
	if refreshToken != "" && client != nil {
		_ = s.sessions.RevokeByToken(ctx, client.ID, refreshToken)
		_ = s.deleteRefreshContext(ctx, refreshToken)
	}
	redirectURI := strings.TrimSpace(req.PostLogoutRedirectURI)
	if redirectURI == "" {
		return &OIDCLogoutResponse{}, nil
	}
	if client == nil {
		return nil, oauthErr("invalid_request", "client_id or id_token_hint is required with post_logout_redirect_uri", 400)
	}
	validRedirect, err := validateRedirectURI(redirectURI, cfg.PostLogoutRedirectURIs)
	if err != nil {
		return nil, oauthErr("invalid_request", "post_logout_redirect_uri is not registered", 400)
	}
	logoutURL, _ := url.Parse(validRedirect)
	if req.State != "" {
		q := logoutURL.Query()
		q.Set("state", req.State)
		logoutURL.RawQuery = q.Encode()
	}
	return &OIDCLogoutResponse{RedirectURL: logoutURL.String()}, nil
}

func (s *OIDCService) LoginClient(ctx context.Context, clientID string) (*domain.Client, error) {
	client, _, err := s.loadOIDCClient(ctx, clientID)
	return client, err
}

func (s *OIDCService) issueUserTokens(ctx context.Context, client *domain.Client, user *domain.User, issuer string, scopes, audiences []string, nonce string, authTime int64, acr string, amr []string, accessTTL, refreshTTL time.Duration, ip, ua string) (*OIDCTokenResponse, error) {
	if len(audiences) == 0 {
		audiences = []string{client.ID}
	}
	scopeString := domain.ScopeString(scopes)
	accessToken, err := CreateAccessToken(ctx, client, accessTTL, user, WithOIDCAccessTokenClaims(issuer, client.ID, audiences, scopes))
	if err != nil {
		return nil, oauthErr("server_error", "could not issue access token", 500)
	}
	idToken := ""
	if stringSet(scopes)["openid"] {
		idToken, err = CreateIDToken(ctx, issuer, client, user, oidcDefaultIDTokenTTL, IDTokenOptions{
			Nonce:    nonce,
			AuthTime: authTime,
			ACR:      firstNonEmptyOIDC(acr, oidcDefaultACR),
			AMR:      amr,
		})
		if err != nil {
			return nil, oauthErr("server_error", "could not issue id token", 500)
		}
	}
	refreshToken := ""
	if stringSet(scopes)["offline_access"] {
		refreshToken, err = s.sessions.Create(ctx, user.ID, client.ID, ip, ua, refreshTTL)
		if err != nil {
			return nil, oauthErr("server_error", "could not issue refresh token", 500)
		}
		_ = s.storeRefreshContext(ctx, refreshToken, refreshTTL, oidcRefreshContext{
			ClientID:  client.ID,
			UserID:    user.ID,
			Scopes:    scopes,
			Audiences: audiences,
			AuthTime:  authTime,
			ACR:       firstNonEmptyOIDC(acr, oidcDefaultACR),
			AMR:       amr,
		})
	}
	if s.audit != nil {
		uid := user.ID
		s.audit.Log(ctx, client.ID, &uid, "oidc_token_issued", ip, ua, map[string]interface{}{"scopes": scopes, "audiences": audiences})
	}
	return &OIDCTokenResponse{
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(accessTTL.Seconds()),
		Scope:        scopeString,
	}, nil
}

func CreateIDToken(ctx context.Context, issuer string, client *domain.Client, user *domain.User, ttl time.Duration, opts IDTokenOptions) (string, error) {
	key, err := ensureActiveSigningKey(ctx, client.ID)
	if err != nil {
		return "", err
	}
	privateKey, err := parseRSAPrivateKey(key.PrivateKeyPEM)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if ttl <= 0 {
		ttl = oidcDefaultIDTokenTTL
	}
	if opts.AuthTime <= 0 {
		opts.AuthTime = now.Unix()
	}
	if opts.ACR == "" {
		opts.ACR = oidcDefaultACR
	}
	if len(opts.AMR) == 0 {
		opts.AMR = []string{"pwd"}
	}
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    strings.TrimRight(strings.TrimSpace(issuer), "/"),
			Subject:   user.ID,
			Audience:  jwt.ClaimStrings{client.ID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuidString(),
		},
		AuthorizedParty:   client.ID,
		Nonce:             opts.Nonce,
		AuthTime:          opts.AuthTime,
		ACR:               opts.ACR,
		AMR:               append([]string(nil), opts.AMR...),
		Email:             user.Email,
		EmailVerified:     user.EmailVerified,
		Name:              user.DisplayName,
		PreferredUsername: preferredUsername(user),
		Locale:            user.Locale,
		ZoneInfo:          user.Timezone,
		Picture:           user.AvatarURL,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.KID
	return token.SignedString(privateKey)
}

func (s *OIDCService) loadOIDCClient(ctx context.Context, clientID string) (*domain.Client, OIDCClientConfig, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, OIDCClientConfig{}, oauthErr("invalid_request", "client_id is required", 400)
	}
	client, err := s.clients.GetByID(ctx, clientID)
	if err != nil || client == nil || client.Status != "active" {
		return nil, OIDCClientConfig{}, oauthErr("invalid_client", "client is not active", 401)
	}
	cfg := oidcClientConfig(client)
	if !cfg.Enabled {
		return nil, OIDCClientConfig{}, oauthErr("unauthorized_client", "OIDC is disabled for this client", 400)
	}
	return client, cfg, nil
}

func (s *OIDCService) authenticateOIDCClient(ctx context.Context, clientID, clientSecret string, allowPublic bool) (*domain.Client, bool, error) {
	client, cfg, err := s.loadOIDCClient(ctx, clientID)
	if err != nil {
		return nil, false, err
	}
	clientSecret = strings.TrimSpace(clientSecret)
	if clientSecret == "" {
		if allowPublic && cfg.PublicClient {
			return client, false, nil
		}
		return nil, false, oauthErr("invalid_client", "client authentication is required", 401)
	}
	if constantStringEqual(clientSecret, client.JWTSecret) || (cfg.ClientSecret != "" && constantStringEqual(clientSecret, cfg.ClientSecret)) {
		return client, true, nil
	}
	if hashedClient, err := s.clients.GetByAPIKeyHash(ctx, hashKey(clientSecret)); err == nil && hashedClient != nil && hashedClient.ID == client.ID {
		return client, true, nil
	}
	return nil, false, oauthErr("invalid_client", "invalid client credentials", 401)
}

func oidcClientConfig(client *domain.Client) OIDCClientConfig {
	settings := client.Settings
	cfg := OIDCClientConfig{
		Enabled:                settingBool(settings, true, "oidc_enabled"),
		RedirectURIs:           settingStringSlice(settings, "oidc_redirect_uris", "redirect_uris"),
		PostLogoutRedirectURIs: settingStringSlice(settings, "oidc_post_logout_redirect_uris", "post_logout_redirect_uris"),
		AllowedScopes:          settingStringSlice(settings, "oidc_allowed_scopes", "oidc_scopes"),
		Audiences:              settingStringSlice(settings, "oidc_audiences", "audiences", "resource_servers"),
		Trusted:                settingBool(settings, false, "oidc_trusted", "oidc_trusted_first_party", "trusted_first_party"),
		RequirePKCE:            settingBool(settings, true, "oidc_require_pkce", "require_pkce"),
		PublicClient:           settingBool(settings, true, "oidc_public_client", "public_client"),
		ClientSecret:           settingString(settings, "oidc_client_secret", "client_secret"),
		LoginURL:               settingString(settings, "oidc_login_url", "login_url"),
		AllowedACRValues:       settingStringSlice(settings, "oidc_acr_values", "acr_values"),
	}
	cfg.RequireConsent = settingBool(settings, !cfg.Trusted, "oidc_require_consent", "require_consent")
	if len(cfg.AllowedScopes) == 0 {
		cfg.AllowedScopes = append([]string(nil), defaultOIDCScopes...)
	}
	if len(cfg.AllowedACRValues) == 0 {
		cfg.AllowedACRValues = []string{oidcDefaultACR}
	}
	return cfg
}

func normalizeOIDCScopes(raw string, allowed []string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		raw = "openid profile email"
	}
	scopes, err := domain.NormalizeScopes(strings.Fields(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid scope")
	}
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	if !domain.ScopesContainAll(allowed, scopes) {
		return nil, fmt.Errorf("requested scope is not allowed")
	}
	return scopes, nil
}

func normalizeOIDCAudiences(clientID, rawAudience string, resources, allowed []string) ([]string, error) {
	values := []string{}
	values = append(values, strings.Fields(rawAudience)...)
	values = append(values, resources...)
	if len(values) == 0 {
		return []string{clientID}, nil
	}
	allowedSet := stringSet(append(append([]string{clientID}, allowed...), ""))
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := allowedSet[value]; !ok {
			return nil, fmt.Errorf("audience %q is not allowed", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		out = []string{clientID}
	}
	sort.Strings(out)
	return out, nil
}

func validateRedirectURI(raw string, allowed []string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if len(allowed) == 1 {
			return allowed[0], nil
		}
		return "", fmt.Errorf("redirect_uri is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("redirect_uri must be an absolute URL")
	}
	for _, allowedURI := range allowed {
		if raw == strings.TrimSpace(allowedURI) {
			return raw, nil
		}
	}
	return "", fmt.Errorf("redirect_uri is not registered")
}

func (s *OIDCService) authorizedUser(ctx context.Context, client *domain.Client, sessionToken, bearerToken string) (*domain.User, time.Time, string, error) {
	if strings.TrimSpace(bearerToken) != "" {
		claims, err := ValidateAccessToken(ctx, client, bearerToken)
		if err != nil {
			return nil, time.Time{}, "", nil
		}
		user, err := s.users.GetByID(ctx, claims.Subject)
		if err != nil || user == nil || user.ClientID != client.ID || user.Status != "active" {
			return nil, time.Time{}, "", nil
		}
		authTime := time.Now().UTC()
		if claims.IssuedAt != nil {
			authTime = claims.IssuedAt.Time
		}
		return user, authTime, "", nil
	}
	if strings.TrimSpace(sessionToken) == "" {
		return nil, time.Time{}, "", nil
	}
	userID, sessionID, err := s.sessions.Validate(ctx, client.ID, sessionToken)
	if err != nil || userID == "" {
		return nil, time.Time{}, "", nil
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil || user.ClientID != client.ID || user.Status != "active" {
		return nil, time.Time{}, "", nil
	}
	authTime := time.Now().UTC()
	if sessions, err := s.sessions.ListForUser(ctx, client.ID, user.ID); err == nil {
		for _, session := range sessions {
			if session != nil && session.ID == sessionID {
				authTime = session.CreatedAt
				break
			}
		}
	}
	return user, authTime, sessionID, nil
}

func (s *OIDCService) storeCode(ctx context.Context, code string, payload oidcCodePayload) error {
	if s.cache == nil {
		return domain.ErrRedisRequired
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.cache.Set(ctx, oidcCodeKey(code), string(raw), oidcCodeTTL)
}

func (s *OIDCService) consumeCode(ctx context.Context, code string) (*oidcCodePayload, error) {
	if s.cache == nil {
		return nil, domain.ErrRedisRequired
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, fmt.Errorf("code is required")
	}
	raw, err := s.cache.Get(ctx, oidcCodeKey(code))
	if err != nil {
		return nil, fmt.Errorf("invalid or expired authorization code")
	}
	_ = s.cache.Del(ctx, oidcCodeKey(code))
	var payload oidcCodePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, fmt.Errorf("invalid authorization code")
	}
	return &payload, nil
}

func (s *OIDCService) storeRefreshContext(ctx context.Context, refreshToken string, ttl time.Duration, payload oidcRefreshContext) error {
	if s.cache == nil {
		return nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.cache.Set(ctx, oidcRefreshKey(refreshToken), string(raw), ttl+oidcRefreshContextSlack)
}

func (s *OIDCService) getRefreshContext(ctx context.Context, refreshToken string) (*oidcRefreshContext, error) {
	if s.cache == nil {
		return nil, domain.ErrRedisRequired
	}
	raw, err := s.cache.Get(ctx, oidcRefreshKey(refreshToken))
	if err != nil {
		return nil, err
	}
	var payload oidcRefreshContext
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func (s *OIDCService) deleteRefreshContext(ctx context.Context, refreshToken string) error {
	if s.cache == nil {
		return nil
	}
	return s.cache.Del(ctx, oidcRefreshKey(refreshToken))
}

func (s *OIDCService) validateBearerAccessToken(ctx context.Context, token string) (*AccessClaims, *domain.Client, error) {
	claims, client, err := s.validateAccessTokenByUnverifiedClient(ctx, token)
	if err != nil {
		return nil, nil, oauthErr("invalid_token", err.Error(), 401)
	}
	if s.isJWTRevoked(ctx, claims.ID) {
		return nil, nil, oauthErr("invalid_token", "token was revoked", 401)
	}
	return claims, client, nil
}

func (s *OIDCService) validateAccessTokenByUnverifiedClient(ctx context.Context, token string) (*AccessClaims, *domain.Client, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil, fmt.Errorf("token is required")
	}
	var unverified AccessClaims
	_, _, err := jwt.NewParser().ParseUnverified(token, &unverified)
	if err != nil {
		return nil, nil, fmt.Errorf("token is not a JWT")
	}
	clientID := strings.TrimSpace(unverified.ClientID)
	if clientID == "" && len(unverified.Audience) > 0 {
		clientID = unverified.Audience[0]
	}
	if clientID == "" {
		return nil, nil, fmt.Errorf("token does not include a client_id")
	}
	client, err := s.clients.GetByID(ctx, clientID)
	if err != nil || client == nil {
		return nil, nil, fmt.Errorf("token client is not active")
	}
	claims, err := ValidateAccessToken(ctx, client, token)
	if err != nil {
		return nil, nil, err
	}
	return claims, client, nil
}

func (s *OIDCService) revokeJWT(ctx context.Context, claims *AccessClaims) error {
	if s.cache == nil || claims == nil || claims.ID == "" {
		return nil
	}
	ttl := time.Minute
	if claims.ExpiresAt != nil {
		ttl = time.Until(claims.ExpiresAt.Time)
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	return s.cache.Set(ctx, oidcRevokedJTIKey(claims.ID), "true", ttl)
}

func (s *OIDCService) isJWTRevoked(ctx context.Context, jti string) bool {
	if s.cache == nil || strings.TrimSpace(jti) == "" {
		return false
	}
	ok, err := s.cache.Exists(ctx, oidcRevokedJTIKey(jti))
	return err == nil && ok
}

func verifyPKCE(challenge, method, verifier string) error {
	challenge = strings.TrimSpace(challenge)
	if challenge == "" {
		return nil
	}
	verifier = strings.TrimSpace(verifier)
	if !validCodeVerifier(verifier) {
		return fmt.Errorf("invalid code_verifier")
	}
	switch method {
	case "", oidcCodeChallengePlain:
		if subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) != 1 {
			return fmt.Errorf("code_verifier does not match code_challenge")
		}
	case oidcCodeChallengeS256:
		sum := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) != 1 {
			return fmt.Errorf("code_verifier does not match code_challenge")
		}
	default:
		return fmt.Errorf("unsupported code_challenge_method")
	}
	return nil
}

func validCodeVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, r := range verifier {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '-', '.', '_', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func userInfoFromUser(user *domain.User, scopes []string) *OIDCUserInfoResponse {
	scopeSet := stringSet(scopes)
	resp := &OIDCUserInfoResponse{Subject: user.ID}
	if scopeSet["email"] {
		resp.Email = user.Email
		resp.EmailVerified = user.EmailVerified
	}
	if scopeSet["profile"] {
		resp.Name = user.DisplayName
		resp.PreferredUsername = preferredUsername(user)
		resp.Picture = user.AvatarURL
		resp.Locale = user.Locale
		resp.ZoneInfo = user.Timezone
		resp.UpdatedAt = user.UpdatedAt.Unix()
	}
	return resp
}

func preferredUsername(user *domain.User) string {
	if user == nil {
		return ""
	}
	if idx := strings.Index(user.Email, "@"); idx > 0 {
		return user.Email[:idx]
	}
	return user.Email
}

func resolveACR(raw string, allowed []string) string {
	for _, requested := range strings.Fields(raw) {
		for _, value := range allowed {
			if requested == value {
				return requested
			}
		}
	}
	if len(allowed) > 0 {
		return allowed[0]
	}
	return oidcDefaultACR
}

func maxAgeExceeded(raw string, authTime time.Time) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || authTime.IsZero() {
		return false
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds < 0 {
		return false
	}
	return time.Since(authTime) > time.Duration(seconds)*time.Second
}

func promptSet(raw string) map[string]bool {
	out := map[string]bool{}
	for _, value := range strings.Fields(raw) {
		out[value] = true
	}
	return out
}

func redirectOAuthErr(code, description, redirectURI, state string) *OAuthError {
	return &OAuthError{Code: code, Description: description, Status: 302, RedirectURI: redirectURI, State: state}
}

func oauthErr(code, description string, status int) *OAuthError {
	if status == 0 {
		status = 400
	}
	return &OAuthError{Code: code, Description: description, Status: status}
}

func oidcCodeKey(code string) string {
	return "oidc:code:" + HashToken(code)
}

func oidcRefreshKey(token string) string {
	return "oidc:refresh:" + HashToken(token)
}

func oidcRevokedJTIKey(jti string) string {
	return "oidc:revoked:jti:" + HashToken(jti)
}

func stringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out[value] = true
		}
	}
	return out
}

func settingBool(settings map[string]interface{}, fallback bool, keys ...string) bool {
	for _, key := range keys {
		value, ok := settings[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case bool:
			return typed
		case string:
			switch strings.ToLower(strings.TrimSpace(typed)) {
			case "true", "1", "yes", "on":
				return true
			case "false", "0", "no", "off":
				return false
			}
		}
	}
	return fallback
}

func settingString(settings map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := settings[key]
		if !ok {
			continue
		}
		if s, ok := value.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func settingStringSlice(settings map[string]interface{}, keys ...string) []string {
	for _, key := range keys {
		value, ok := settings[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case []string:
			return cleanStrings(typed)
		case []interface{}:
			out := make([]string, 0, len(typed))
			for _, item := range typed {
				out = append(out, fmt.Sprint(item))
			}
			return cleanStrings(out)
		case string:
			if strings.Contains(typed, ",") {
				return cleanStrings(strings.Split(typed, ","))
			}
			return cleanStrings(strings.Fields(typed))
		}
	}
	return nil
}

func cleanStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func constantStringEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func firstNonEmptyOIDC(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func clientIDFromIDTokenHint(token string) string {
	var claims IDTokenClaims
	_, _, err := jwt.NewParser().ParseUnverified(token, &claims)
	if err != nil {
		return ""
	}
	if claims.AuthorizedParty != "" {
		return claims.AuthorizedParty
	}
	if len(claims.Audience) > 0 {
		return claims.Audience[0]
	}
	return ""
}

func uuidString() string {
	token, err := GenerateToken(16)
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return token
}
