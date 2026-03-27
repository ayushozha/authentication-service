package application

import (
	"context"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/go-webauthn/webauthn/webauthn"
)

type ClientRepository interface {
	Create(ctx context.Context, client *domain.Client) error
	GetByID(ctx context.Context, id string) (*domain.Client, error)
	GetBySlug(ctx context.Context, slug string) (*domain.Client, error)
	GetByAPIKeyHash(ctx context.Context, hash string) (*domain.Client, error)
	List(ctx context.Context) ([]*domain.Client, error)
	Update(ctx context.Context, client *domain.Client) error
	UpdateJWTSecret(ctx context.Context, id, newSecret string) error
	UpdateAPIKeyHash(ctx context.Context, id, newHash string) error
}

type SigningKeyRepository interface {
	Create(ctx context.Context, key *domain.SigningKey) error
	GetActiveByClient(ctx context.Context, clientID string) (*domain.SigningKey, error)
	GetByClientAndKID(ctx context.Context, clientID, kid string) (*domain.SigningKey, error)
	ListActive(ctx context.Context) ([]*domain.SigningKey, error)
	ListActiveByClient(ctx context.Context, clientID string) ([]*domain.SigningKey, error)
}

type UserRepository interface {
	Create(ctx context.Context, clientID, email, passwordHash, displayName string) (*domain.User, error)
	CreateOAuth(ctx context.Context, clientID, email, displayName, avatarURL string) (*domain.User, error)
	GetByEmail(ctx context.Context, clientID, email string) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
	UpdateLastLogin(ctx context.Context, userID string) error
	VerifyEmail(ctx context.Context, userID string) error
	UpdatePassword(ctx context.Context, userID, passwordHash string) error
	UpdateProfile(ctx context.Context, userID, displayName, timezone string) error
	SetTOTPSecret(ctx context.Context, userID, secret string) error
	EnableTOTP(ctx context.Context, userID string) error
	DisableTOTP(ctx context.Context, userID string) error
}

type SessionRepository interface {
	Create(ctx context.Context, userID, clientID, ip, ua string, ttl time.Duration) (rawToken string, err error)
	Validate(ctx context.Context, clientID, rawToken string) (userID, sessionID string, err error)
	Revoke(ctx context.Context, sessionID string) error
	RevokeByToken(ctx context.Context, clientID, rawToken string) error
	RevokeAllForUser(ctx context.Context, clientID, userID string) error
}

type OAuthRepository interface {
	FindByProvider(ctx context.Context, clientID, provider, providerUserID string) (*domain.OAuthAccount, error)
	Link(ctx context.Context, userID, clientID, provider, providerUserID, email, accessToken, refreshToken string, rawProfile []byte) error
}

type WebAuthnRepository interface {
	Save(ctx context.Context, userID string, cred *webauthn.Credential, friendlyName string) error
	GetByUser(ctx context.Context, userID string) ([]webauthn.Credential, error)
	UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error
	ListByUser(ctx context.Context, userID string) ([]domain.WebAuthnCredential, error)
	GetUserIDByCredentialID(ctx context.Context, credentialID []byte) (string, error)
	DeleteByID(ctx context.Context, id, userID string) error
}

type TokenRepository interface {
	Create(ctx context.Context, userID, tokenType string, ttl time.Duration) (rawToken string, err error)
	Validate(ctx context.Context, rawToken, tokenType string) (userID string, err error)
}

type AuditRepository interface {
	Log(ctx context.Context, clientID string, userID *string, eventType, ip, ua string, metadata map[string]interface{})
}

type CacheClient interface {
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Del(ctx context.Context, key string) error
	Incr(ctx context.Context, key string) (int64, error)
	Expire(ctx context.Context, key string, ttl time.Duration) error
	Exists(ctx context.Context, key string) (bool, error)
	Ping(ctx context.Context) error
}

type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int64, window time.Duration) (allowed bool, remaining int64, err error)
	IsLocked(ctx context.Context, email string) bool
	RecordFailedLogin(ctx context.Context, email string)
	ClearFailedLogins(ctx context.Context, email string)
}

type EmailSender interface {
	Send(to, subject, htmlBody string) error
	SendVerifyEmail(to, displayName, verifyURL string) error
	SendPasswordReset(to, displayName, resetURL string) error
	SendMagicLink(to, magicURL string) error
}
