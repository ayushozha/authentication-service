package application

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type MagicLinkService struct {
	clients  ClientRepository
	users    UserRepository
	sessions SessionRepository
	cache    CacheClient
	mailer   EmailSender
	audit    AuditRepository
	rl       RateLimiter
}

func NewMagicLinkService(clients ClientRepository, users UserRepository, sessions SessionRepository, cache CacheClient, mailer EmailSender, audit AuditRepository, rl RateLimiter) *MagicLinkService {
	return &MagicLinkService{clients: clients, users: users, sessions: sessions, cache: cache, mailer: mailer, audit: audit, rl: rl}
}

type magicLinkState struct {
	UserID   string `json:"user_id"`
	ClientID string `json:"client_id"`
}

func (s *MagicLinkService) SendMagicLink(ctx context.Context, client *domain.Client, email, baseURL, ip, ua string) error {
	if s.mailer == nil {
		return domain.ErrEmailNotConfigured
	}
	emailKey := strings.ToLower(strings.TrimSpace(email))

	if allowed, _, _ := s.rl.Allow(ctx, "rate:email:magic:"+emailKey, 3, 1*time.Hour); !allowed {
		return domain.ErrRateLimit
	}

	user, err := s.users.GetByEmail(ctx, client.ID, emailKey)
	if err != nil {
		log.Printf("magic link lookup error: %v", err)
	}

	if user != nil && s.cache != nil {
		token, err := GenerateToken(32)
		if err != nil {
			log.Printf("generate magic token error: %v", err)
			return nil
		}
		state, _ := json.Marshal(magicLinkState{UserID: user.ID, ClientID: client.ID})
		if err := s.cache.Set(ctx, "magic:"+HashToken(token), string(state), 15*time.Minute); err != nil {
			log.Printf("store magic token error: %v", err)
			return nil
		}
		magicURL := baseURL + "/api/auth/magic-link/verify?token=" + token
		go func() {
			if err := s.mailer.SendMagicLink(user.Email, magicURL); err != nil {
				log.Printf("send magic link email error: %v", err)
			}
		}()
		uid := user.ID
		s.audit.Log(ctx, client.ID, &uid, "magic_link_sent", ip, ua, nil)
	}

	return nil // Always return nil to prevent enumeration
}

func (s *MagicLinkService) VerifyMagicLink(ctx context.Context, client *domain.Client, rawToken, ip, ua string, accessTTL, refreshTTL time.Duration) (*AuthResponse, string, error) {
	return s.verifyMagicLink(ctx, rawToken, ip, ua, accessTTL, refreshTTL, client)
}

func (s *MagicLinkService) VerifyMagicLinkPublic(ctx context.Context, rawToken, ip, ua string, accessTTL, refreshTTL time.Duration) (*AuthResponse, string, error) {
	return s.verifyMagicLink(ctx, rawToken, ip, ua, accessTTL, refreshTTL, nil)
}

func (s *MagicLinkService) verifyMagicLink(ctx context.Context, rawToken, ip, ua string, accessTTL, refreshTTL time.Duration, expectedClient *domain.Client) (*AuthResponse, string, error) {
	if s.cache == nil {
		return nil, "", domain.ErrRedisRequired
	}

	tokenKey := "magic:" + HashToken(rawToken)
	stateRaw, err := s.cache.Get(ctx, tokenKey)
	if err != nil || stateRaw == "" {
		return nil, "", domain.ErrInvalidToken
	}
	_ = s.cache.Del(ctx, tokenKey)
	var state magicLinkState
	if err := json.Unmarshal([]byte(stateRaw), &state); err != nil {
		// backward compatibility with old token payloads that stored only user ID.
		state = magicLinkState{UserID: stateRaw}
	}
	if state.UserID == "" {
		return nil, "", domain.ErrInvalidToken
	}

	user, err := s.users.GetByID(ctx, state.UserID)
	if err != nil || user == nil {
		return nil, "", domain.ErrNotFound
	}
	if state.ClientID == "" {
		state.ClientID = user.ClientID
	}
	if user.ClientID != state.ClientID {
		return nil, "", domain.ErrInvalidToken
	}

	var client *domain.Client
	if expectedClient != nil {
		if expectedClient.ID != state.ClientID {
			return nil, "", domain.ErrInvalidToken
		}
		client = expectedClient
	} else {
		client, err = s.clients.GetByID(ctx, state.ClientID)
		if err != nil || client == nil {
			return nil, "", domain.ErrInvalidClient
		}
	}
	if user.Status != "active" {
		return nil, "", domain.ErrAccountSuspended
	}

	if !user.EmailVerified {
		_ = s.users.VerifyEmail(ctx, user.ID)
		user.EmailVerified = true
	}

	_ = s.users.UpdateLastLogin(ctx, user.ID)
	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "login_success", ip, ua, map[string]interface{}{"method": "magic_link"})

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
