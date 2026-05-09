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
}

func NewPasswordResetService(users UserRepository, tokens TokenRepository, sessions SessionRepository, mailer EmailSender) *PasswordResetService {
	return &PasswordResetService{users: users, tokens: tokens, sessions: sessions, mailer: mailer}
}

func (s *PasswordResetService) ForgotPassword(ctx context.Context, clientID, email, baseURL string) error {
	user, err := s.users.GetByEmail(ctx, clientID, email)
	if err != nil {
		log.Printf("forgot password lookup error: %v", err)
	}
	if user != nil && s.mailer != nil {
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
