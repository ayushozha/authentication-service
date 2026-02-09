package application

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type OAuthService struct {
	users    UserRepository
	clients  ClientRepository
	oauth    OAuthRepository
	sessions SessionRepository
	cache    CacheClient
	audit    AuditRepository
}

func NewOAuthService(users UserRepository, clients ClientRepository, oauth OAuthRepository, sessions SessionRepository, cache CacheClient, audit AuditRepository) *OAuthService {
	return &OAuthService{users: users, clients: clients, oauth: oauth, sessions: sessions, cache: cache, audit: audit}
}

type OAuthProviderConfig struct {
	OAuth2Config *oauth2.Config
	UserInfoURL  string
	ParseUser    func(data []byte) (providerUserID, email, name, avatar string, err error)
}

type oauthStatePayload struct {
	ClientID     string `json:"client_id"`
	Provider     string `json:"provider"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	CreatedAt    int64  `json:"created_at"`
}

func (s *OAuthService) BeginOAuth(ctx context.Context, client *domain.Client, providerCfg *OAuthProviderConfig, providerName string) (redirectURL string, err error) {
	if s.cache == nil {
		return "", domain.ErrRedisRequired
	}
	nonce, err := GenerateToken(16)
	if err != nil {
		return "", err
	}
	codeVerifier, err := GenerateToken(32)
	if err != nil {
		return "", err
	}
	statePayload := oauthStatePayload{
		ClientID:     client.ID,
		Provider:     providerName,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		CreatedAt:    time.Now().UTC().Unix(),
	}
	state, err := encodeOAuthState(statePayload)
	if err != nil {
		return "", err
	}
	serializedState, _ := json.Marshal(statePayload)
	if err := s.cache.Set(ctx, "oauth_state:"+HashToken(state), string(serializedState), 10*time.Minute); err != nil {
		return "", err
	}

	return providerCfg.OAuth2Config.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(codeVerifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

func (s *OAuthService) HandleCallback(ctx context.Context, providerCfg *OAuthProviderConfig, providerName, code, state, ip, ua string, accessTTL, refreshTTL time.Duration) (client *domain.Client, accessToken, refreshToken string, err error) {
	if s.cache == nil {
		return nil, "", "", domain.ErrRedisRequired
	}
	statePayload, err := decodeOAuthState(state)
	if err != nil {
		return nil, "", "", fmt.Errorf("invalid_state")
	}
	if statePayload.Provider != providerName || statePayload.ClientID == "" || statePayload.CodeVerifier == "" || statePayload.Nonce == "" {
		return nil, "", "", fmt.Errorf("invalid_state")
	}
	cacheKey := "oauth_state:" + HashToken(state)
	cachedStateJSON, err := s.cache.Get(ctx, cacheKey)
	if err != nil || cachedStateJSON == "" {
		return nil, "", "", fmt.Errorf("invalid_state")
	}
	_ = s.cache.Del(ctx, cacheKey)
	if cachedStateJSON != mustStateJSON(statePayload) {
		return nil, "", "", fmt.Errorf("invalid_state")
	}

	client, err = s.clients.GetByID(ctx, statePayload.ClientID)
	if err != nil || client == nil {
		return nil, "", "", fmt.Errorf("invalid_client")
	}

	token, err := providerCfg.OAuth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", statePayload.CodeVerifier))
	if err != nil {
		return nil, "", "", fmt.Errorf("exchange_failed")
	}

	var (
		providerUserID string
		email          string
		displayName    string
		avatar         string
		rawProfile     []byte
	)
	oauthClient := providerCfg.OAuth2Config.Client(ctx, token)
	if providerName == "apple" {
		providerUserID, email, err = parseAppleIDToken(ctx, token.Extra("id_token"), providerCfg.OAuth2Config.ClientID)
		if err != nil {
			return nil, "", "", fmt.Errorf("parse_failed")
		}
		rawProfile = []byte("{}")
	} else {
		resp, err := oauthClient.Get(providerCfg.UserInfoURL)
		if err != nil {
			return nil, "", "", fmt.Errorf("userinfo_failed")
		}
		defer resp.Body.Close()

		rawProfile, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, "", "", fmt.Errorf("read_failed")
		}

		providerUserID, email, displayName, avatar, err = providerCfg.ParseUser(rawProfile)
		if err != nil {
			return nil, "", "", fmt.Errorf("parse_failed")
		}
		if providerName == "github" && email == "" {
			email, _ = fetchGithubPrimaryEmail(ctx, oauthClient)
		}
	}

	oauthAcc, err := s.oauth.FindByProvider(ctx, client.ID, providerName, providerUserID)
	if err != nil && err != domain.ErrNotFound {
		return nil, "", "", fmt.Errorf("internal")
	}
	if err == domain.ErrNotFound {
		oauthAcc = nil
	}

	var user *domain.User
	if oauthAcc != nil {
		user, err = s.users.GetByID(ctx, oauthAcc.UserID)
		if err != nil || user == nil {
			return nil, "", "", fmt.Errorf("user_not_found")
		}
	} else {
		if email != "" {
			user, _ = s.users.GetByEmail(ctx, client.ID, email)
		}
		if user == nil {
			if displayName == "" && email != "" {
				displayName = strings.Split(email, "@")[0]
			}
			user, err = s.users.CreateOAuth(ctx, client.ID, email, displayName, avatar)
			if err != nil {
				return nil, "", "", fmt.Errorf("create_failed")
			}
			uid := user.ID
			s.audit.Log(ctx, client.ID, &uid, "signup", ip, ua, map[string]interface{}{"method": "oauth_" + providerName})
		}
		_ = s.oauth.Link(ctx, user.ID, client.ID, providerName, providerUserID, email, token.AccessToken, token.RefreshToken, rawProfile)
	}

	if user.Status != "active" {
		return nil, "", "", fmt.Errorf("account_suspended")
	}

	if !user.EmailVerified && email != "" {
		_ = s.users.VerifyEmail(ctx, user.ID)
	}

	_ = s.users.UpdateLastLogin(ctx, user.ID)
	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "login_success", ip, ua, map[string]interface{}{"method": "oauth_" + providerName})

	at, err := CreateAccessToken(ctx, client, accessTTL, user)
	if err != nil {
		return nil, "", "", err
	}

	rt, err := s.sessions.Create(ctx, user.ID, client.ID, ip, ua, refreshTTL)
	if err != nil {
		return nil, "", "", err
	}

	return client, at, rt, nil
}

func BuildOAuthProviders(cfg OAuthConfig) map[string]*OAuthProviderConfig {
	providers := make(map[string]*OAuthProviderConfig)

	if cfg.GoogleClientID != "" {
		providers["google"] = &OAuthProviderConfig{
			OAuth2Config: &oauth2.Config{
				ClientID:     cfg.GoogleClientID,
				ClientSecret: cfg.GoogleClientSecret,
				RedirectURL:  cfg.GoogleRedirectURL,
				Scopes:       []string{"openid", "email", "profile"},
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
					TokenURL: "https://oauth2.googleapis.com/token",
				},
			},
			UserInfoURL: "https://www.googleapis.com/oauth2/v2/userinfo",
			ParseUser: func(data []byte) (string, string, string, string, error) {
				var u struct {
					ID      string `json:"id"`
					Email   string `json:"email"`
					Name    string `json:"name"`
					Picture string `json:"picture"`
				}
				if err := json.Unmarshal(data, &u); err != nil {
					return "", "", "", "", err
				}
				return u.ID, u.Email, u.Name, u.Picture, nil
			},
		}
	}

	if cfg.GithubClientID != "" {
		providers["github"] = &OAuthProviderConfig{
			OAuth2Config: &oauth2.Config{
				ClientID:     cfg.GithubClientID,
				ClientSecret: cfg.GithubClientSecret,
				RedirectURL:  cfg.GithubRedirectURL,
				Scopes:       []string{"user:email", "read:user"},
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://github.com/login/oauth/authorize",
					TokenURL: "https://github.com/login/oauth/access_token",
				},
			},
			UserInfoURL: "https://api.github.com/user",
			ParseUser: func(data []byte) (string, string, string, string, error) {
				var u struct {
					ID        int    `json:"id"`
					Email     string `json:"email"`
					Name      string `json:"name"`
					Login     string `json:"login"`
					AvatarURL string `json:"avatar_url"`
				}
				if err := json.Unmarshal(data, &u); err != nil {
					return "", "", "", "", err
				}
				name := u.Name
				if name == "" {
					name = u.Login
				}
				return fmt.Sprintf("%d", u.ID), u.Email, name, u.AvatarURL, nil
			},
		}
	}

	if cfg.MicrosoftClientID != "" {
		providers["microsoft"] = &OAuthProviderConfig{
			OAuth2Config: &oauth2.Config{
				ClientID:     cfg.MicrosoftClientID,
				ClientSecret: cfg.MicrosoftClientSecret,
				RedirectURL:  cfg.MicrosoftRedirectURL,
				Scopes:       []string{"openid", "email", "profile", "User.Read"},
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://login.microsoftonline.com/" + cfg.MicrosoftTenantID + "/oauth2/v2.0/authorize",
					TokenURL: "https://login.microsoftonline.com/" + cfg.MicrosoftTenantID + "/oauth2/v2.0/token",
				},
			},
			UserInfoURL: "https://graph.microsoft.com/v1.0/me",
			ParseUser: func(data []byte) (string, string, string, string, error) {
				var u struct {
					ID          string `json:"id"`
					Mail        string `json:"mail"`
					DisplayName string `json:"displayName"`
					UPN         string `json:"userPrincipalName"`
				}
				if err := json.Unmarshal(data, &u); err != nil {
					return "", "", "", "", err
				}
				e := u.Mail
				if e == "" {
					e = u.UPN
				}
				return u.ID, e, u.DisplayName, "", nil
			},
		}
	}

	if cfg.AppleClientID != "" {
		providers["apple"] = &OAuthProviderConfig{
			OAuth2Config: &oauth2.Config{
				ClientID:    cfg.AppleClientID,
				RedirectURL: cfg.AppleRedirectURL,
				Scopes:      []string{"name", "email"},
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://appleid.apple.com/auth/authorize",
					TokenURL: "https://appleid.apple.com/auth/token",
				},
			},
			UserInfoURL: "",
			ParseUser: func(data []byte) (string, string, string, string, error) {
				var u struct {
					Sub   string `json:"sub"`
					Email string `json:"email"`
				}
				if err := json.Unmarshal(data, &u); err != nil {
					return "", "", "", "", err
				}
				return u.Sub, u.Email, "", "", nil
			},
		}
	}

	return providers
}

func encodeOAuthState(payload oauthStatePayload) (string, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeOAuthState(state string) (oauthStatePayload, error) {
	var payload oauthStatePayload
	raw, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return payload, err
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, err
	}
	return payload, nil
}

func mustStateJSON(payload oauthStatePayload) string {
	b, _ := json.Marshal(payload)
	return string(b)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func fetchGithubPrimaryEmail(ctx context.Context, oauthClient *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := oauthClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("github email request failed")
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&emails); err != nil {
		return "", err
	}
	for _, e := range emails {
		if e.Primary && e.Verified && e.Email != "" {
			return e.Email, nil
		}
	}
	for _, e := range emails {
		if e.Verified && e.Email != "" {
			return e.Email, nil
		}
	}
	return "", nil
}

func parseAppleIDToken(ctx context.Context, idTokenValue interface{}, expectedAudience string) (string, string, error) {
	idToken, ok := idTokenValue.(string)
	if !ok || strings.TrimSpace(idToken) == "" {
		return "", "", fmt.Errorf("missing id_token")
	}

	keys, err := fetchApplePublicKeys(ctx)
	if err != nil {
		return "", "", err
	}

	token, err := jwt.Parse(idToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		kid, _ := t.Header["kid"].(string)
		key, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown key id")
		}
		return key, nil
	}, jwt.WithAudience(expectedAudience), jwt.WithIssuer("https://appleid.apple.com"))
	if err != nil {
		return "", "", err
	}
	if !token.Valid {
		return "", "", fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", fmt.Errorf("invalid claims")
	}
	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	if strings.TrimSpace(sub) == "" {
		return "", "", fmt.Errorf("missing subject")
	}
	return sub, email, nil
}

func fetchApplePublicKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://appleid.apple.com/auth/keys", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("apple jwks request failed")
	}

	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, err
	}

	result := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		if e == 0 {
			return nil, fmt.Errorf("invalid exponent")
		}
		result[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: e,
		}
	}
	return result, nil
}

type OAuthConfig struct {
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	GithubClientID     string
	GithubClientSecret string
	GithubRedirectURL  string

	MicrosoftClientID     string
	MicrosoftClientSecret string
	MicrosoftTenantID     string
	MicrosoftRedirectURL  string

	AppleClientID    string
	AppleRedirectURL string
}
