package application

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type PasswordResetService struct {
	users    UserRepository
	tokens   TokenRepository
	sessions SessionRepository
	mailer   EmailSender
	rl       RateLimiter
	sso      EnterpriseSSORepository
}

func NewPasswordResetService(users UserRepository, tokens TokenRepository, sessions SessionRepository, mailer EmailSender, rateLimiters ...RateLimiter) *PasswordResetService {
	svc := &PasswordResetService{users: users, tokens: tokens, sessions: sessions, mailer: mailer}
	if len(rateLimiters) > 0 {
		svc.rl = rateLimiters[0]
	}
	return svc
}

func (s *PasswordResetService) SetEnterpriseSSORepository(repo EnterpriseSSORepository) {
	s.sso = repo
}

func (s *PasswordResetService) SetRateLimiter(rl RateLimiter) {
	s.rl = rl
}

func (s *PasswordResetService) ForgotPassword(ctx context.Context, clientID, email, baseURL string) error {
	emailKey, err := NormalizeEmailAddress(email)
	if err != nil {
		return err
	}
	if s.mailer == nil {
		return domain.ErrEmailNotConfigured
	}
	if s.rl != nil {
		allowed, _, err := s.rl.Allow(ctx, "rate:email:password_reset:"+emailKey, 3, time.Hour)
		if err != nil {
			log.Printf("password reset rate limit error: %v", err)
		} else if !allowed {
			return domain.ErrRateLimit
		}
	}
	user, err := s.users.GetByEmail(ctx, clientID, emailKey)
	if err != nil {
		log.Printf("forgot password lookup error: %v", err)
	}
	if user != nil {
		if _, enforced, enforceErr := enforcedSSOConnectionForEmail(ctx, s.sso, clientID, user.Email); enforceErr != nil {
			log.Printf("forgot password sso enforcement lookup error: %v", enforceErr)
			return nil
		} else if enforced {
			return nil
		}
		token, err := s.tokens.Create(ctx, user.ID, "password_reset", 1*time.Hour)
		if err != nil {
			log.Printf("create reset token error: %v", err)
		} else {
			resetURL := baseURL + "/reset-password.html?token=" + token
			go func() {
				if err := s.mailer.SendPasswordReset(user.Email, user.DisplayName, resetURL); err != nil {
					log.Printf("send password reset email error: %v", err)
				}
			}()
		}
	}
	// Always return nil to prevent email enumeration
	return nil
}

func (s *PasswordResetService) ResetPassword(ctx context.Context, rawToken, newPassword string, bcryptCost int) error {
	if msg := ValidatePasswordStrength(newPassword); msg != "" {
		return fmt.Errorf("%s", msg)
	}
	userID, err := s.tokens.Validate(ctx, rawToken, "password_reset")
	if err != nil {
		return err
	}
	if userID == "" {
		return domain.ErrInvalidToken
	}
	hash, err := HashPassword(newPassword, bcryptCost)
	if err != nil {
		return fmt.Errorf("internal error")
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrNotFound
	}
	if err := s.users.UpdatePassword(ctx, userID, hash); err != nil {
		return err
	}
	_ = s.sessions.RevokeAllForUser(ctx, user.ClientID, userID)
	return nil
}
