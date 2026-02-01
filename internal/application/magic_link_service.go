package application

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type MagicLinkService struct {
	users    UserRepository
	sessions SessionRepository
	cache    CacheClient
	mailer   EmailSender
	audit    AuditRepository
	rl       RateLimiter
}

func NewMagicLinkService(users UserRepository, sessions SessionRepository, cache CacheClient, mailer EmailSender, audit AuditRepository, rl RateLimiter) *MagicLinkService {
	return &MagicLinkService{users: users, sessions: sessions, cache: cache, mailer: mailer, audit: audit, rl: rl}
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
		if err := s.cache.Set(ctx, "magic:"+HashToken(token), user.ID, 15*time.Minute); err != nil {
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
	if s.cache == nil {
		return nil, "", domain.ErrRedisRequired
	}

	tokenKey := "magic:" + HashToken(rawToken)
	userID, err := s.cache.Get(ctx, tokenKey)
	if err != nil || userID == "" {
		return nil, "", domain.ErrInvalidToken
	}
	_ = s.cache.Del(ctx, tokenKey)

	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, "", domain.ErrNotFound
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

	accessToken, err := CreateAccessToken(client.JWTSecret, accessTTL, user)
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
