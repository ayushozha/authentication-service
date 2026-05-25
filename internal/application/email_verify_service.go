package application

import (
	"context"
	"log"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type EmailVerifyService struct {
	users  UserRepository
	tokens TokenRepository
	mailer EmailSender
	urls   *EmailURLBuilder
}

func NewEmailVerifyService(users UserRepository, tokens TokenRepository, mailer EmailSender, urls *EmailURLBuilder) *EmailVerifyService {
	return &EmailVerifyService{users: users, tokens: tokens, mailer: mailer, urls: urls}
}

func (s *EmailVerifyService) WireSignupHook() {
	if s.mailer == nil {
		return
	}
	OnSignup = func(clientID, userID, email, displayName string) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		token, err := s.tokens.Create(ctx, userID, "email_verify", 24*time.Hour)
		if err != nil {
			log.Printf("create verify token on signup error: %v", err)
			return
		}
		verifyURL := s.urls.VerifyEmailURL(ctx, clientID, token)
		go func() {
			if err := s.mailer.SendVerifyEmail(context.Background(), clientID, email, displayName, verifyURL); err != nil {
				log.Printf("send verify email error: %v", err)
			}
		}()
	}
}

func (s *EmailVerifyService) VerifyEmail(ctx context.Context, rawToken string) error {
	userID, err := s.tokens.Validate(ctx, rawToken, "email_verify")
	if err != nil {
		return err
	}
	if userID == "" {
		return domain.ErrInvalidToken
	}
	return s.users.VerifyEmail(ctx, userID)
}

func (s *EmailVerifyService) ResendVerification(ctx context.Context, userID, baseURL string) error {
	if s.mailer == nil {
		return domain.ErrEmailNotConfigured
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrNotFound
	}
	if user.EmailVerified {
		return domain.ErrEmailAlreadyVerified
	}
	token, err := s.tokens.Create(ctx, userID, "email_verify", 24*time.Hour)
	if err != nil {
		return err
	}
	verifyURL := s.urls.VerifyEmailURL(ctx, user.ClientID, token)
	go func() {
		if err := s.mailer.SendVerifyEmail(context.Background(), user.ClientID, user.Email, user.DisplayName, verifyURL); err != nil {
			log.Printf("send verify email error: %v", err)
		}
	}()
	return nil
}
