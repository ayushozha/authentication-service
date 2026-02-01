package application

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"golang.org/x/oauth2"
)

type OAuthService struct {
	users    UserRepository
	oauth    OAuthRepository
	sessions SessionRepository
	cache    CacheClient
	audit    AuditRepository
}

func NewOAuthService(users UserRepository, oauth OAuthRepository, sessions SessionRepository, cache CacheClient, audit AuditRepository) *OAuthService {
	return &OAuthService{users: users, oauth: oauth, sessions: sessions, cache: cache, audit: audit}
}

type OAuthProviderConfig struct {
	OAuth2Config *oauth2.Config
	UserInfoURL  string
	ParseUser    func(data []byte) (providerUserID, email, name, avatar string, err error)
}

func (s *OAuthService) BeginOAuth(ctx context.Context, providerCfg *OAuthProviderConfig) (redirectURL string, err error) {
	state, err := GenerateToken(16)
	if err != nil {
		return "", err
	}
	if s.cache != nil {
		_ = s.cache.Set(ctx, "oauth_state:"+state, "1", 10*time.Minute)
	}
	return providerCfg.OAuth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

func (s *OAuthService) HandleCallback(ctx context.Context, client *domain.Client, providerCfg *OAuthProviderConfig, providerName, code, state, ip, ua string, accessTTL, refreshTTL time.Duration) (accessToken, refreshToken string, err error) {
	if s.cache != nil {
		exists, _ := s.cache.Exists(ctx, "oauth_state:"+state)
		if !exists {
			return "", "", fmt.Errorf("invalid_state")
		}
		_ = s.cache.Del(ctx, "oauth_state:"+state)
	}

	token, err := providerCfg.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		return "", "", fmt.Errorf("exchange_failed")
	}

	oauthClient := providerCfg.OAuth2Config.Client(ctx, token)
	resp, err := oauthClient.Get(providerCfg.UserInfoURL)
	if err != nil {
		return "", "", fmt.Errorf("userinfo_failed")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", fmt.Errorf("read_failed")
	}

	providerUserID, email, displayName, avatar, err := providerCfg.ParseUser(body)
	if err != nil {
		return "", "", fmt.Errorf("parse_failed")
	}

	oauthAcc, err := s.oauth.FindByProvider(ctx, client.ID, providerName, providerUserID)
	if err != nil {
		return "", "", fmt.Errorf("internal")
	}

	var user *domain.User
	if oauthAcc != nil {
		user, err = s.users.GetByID(ctx, oauthAcc.UserID)
		if err != nil || user == nil {
			return "", "", fmt.Errorf("user_not_found")
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
				return "", "", fmt.Errorf("create_failed")
			}
			uid := user.ID
			s.audit.Log(ctx, client.ID, &uid, "signup", ip, ua, map[string]interface{}{"method": "oauth_" + providerName})
		}
		_ = s.oauth.Link(ctx, user.ID, client.ID, providerName, providerUserID, email, token.AccessToken, token.RefreshToken, body)
	}

	if user.Status != "active" {
		return "", "", fmt.Errorf("account_suspended")
	}

	if !user.EmailVerified && email != "" {
		_ = s.users.VerifyEmail(ctx, user.ID)
	}

	_ = s.users.UpdateLastLogin(ctx, user.ID)
	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "login_success", ip, ua, map[string]interface{}{"method": "oauth_" + providerName})

	at, err := CreateAccessToken(client.JWTSecret, accessTTL, user)
	if err != nil {
		return "", "", err
	}

	rt, err := s.sessions.Create(ctx, user.ID, client.ID, ip, ua, refreshTTL)
	if err != nil {
		return "", "", err
	}

	return at, rt, nil
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
