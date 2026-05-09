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
	UpdateStatus(ctx context.Context, userID, status string) error
	SetTOTPSecret(ctx context.Context, userID, secret string) error
	EnableTOTP(ctx context.Context, userID string) error
	DisableTOTP(ctx context.Context, userID string) error
}

type SessionRepository interface {
	Create(ctx context.Context, userID, clientID, ip, ua string, ttl time.Duration) (rawToken string, err error)
	Validate(ctx context.Context, clientID, rawToken string) (userID, sessionID string, err error)
	ListForUser(ctx context.Context, clientID, userID string) ([]*domain.Session, error)
	Revoke(ctx context.Context, sessionID string) error
	RevokeByToken(ctx context.Context, clientID, rawToken string) error
	RevokeForUser(ctx context.Context, clientID, userID, sessionID string) error
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

type RecoveryCodeRepository interface {
	ReplaceForUser(ctx context.Context, userID string, codeHashes []string) error
	CountUnused(ctx context.Context, userID string) (int, error)
	MarkUsedByHash(ctx context.Context, userID, codeHash string) (bool, error)
}

type AuditRepository interface {
	Log(ctx context.Context, clientID string, userID *string, eventType, ip, ua string, metadata map[string]interface{})
}

type OrganizationRepository interface {
	CreateOrganization(ctx context.Context, org *domain.Organization, owner *domain.OrganizationMembership) error
	UpdateOrganization(ctx context.Context, org *domain.Organization) error
	GetOrganization(ctx context.Context, clientID, organizationID string) (*domain.Organization, error)
	ListOrganizationsForUser(ctx context.Context, clientID, userID string) ([]domain.OrganizationMembershipDetails, error)
	GetMembership(ctx context.Context, clientID, organizationID, userID string) (*domain.OrganizationMembership, error)
	ListMemberships(ctx context.Context, clientID, organizationID string) ([]*domain.OrganizationMembership, error)
	UpsertMembership(ctx context.Context, membership *domain.OrganizationMembership) error
	UpdateMembership(ctx context.Context, membership *domain.OrganizationMembership) error
	DeleteMembership(ctx context.Context, clientID, organizationID, userID string) error
	CreateInvitation(ctx context.Context, invitation *domain.OrganizationInvitation) error
	ListInvitations(ctx context.Context, clientID, organizationID string) ([]*domain.OrganizationInvitation, error)
	GetInvitation(ctx context.Context, clientID, organizationID, invitationID string) (*domain.OrganizationInvitation, error)
	GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*domain.OrganizationInvitation, error)
	MarkInvitationAccepted(ctx context.Context, invitationID, userID string) error
	RevokeInvitation(ctx context.Context, clientID, organizationID, invitationID string) error
}

type ServiceAccountRepository interface {
	CreateServiceAccount(ctx context.Context, account *domain.ServiceAccount) error
	ListServiceAccounts(ctx context.Context, clientID string) ([]*domain.ServiceAccount, error)
	GetServiceAccount(ctx context.Context, clientID, serviceAccountID string) (*domain.ServiceAccount, error)
	UpdateServiceAccount(ctx context.Context, account *domain.ServiceAccount) error
	UpdateServiceAccountLastUsed(ctx context.Context, serviceAccountID string) error
	CreateServiceAccountKey(ctx context.Context, key *domain.ServiceAccountKey) error
	ListServiceAccountKeys(ctx context.Context, clientID, serviceAccountID string) ([]*domain.ServiceAccountKey, error)
	GetServiceAccountKey(ctx context.Context, clientID, serviceAccountID, keyID string) (*domain.ServiceAccountKey, error)
	GetServiceAccountKeyBySecretHash(ctx context.Context, serviceAccountID, secretHash string) (*domain.ServiceAccountKey, error)
	UpdateServiceAccountKeyLastUsed(ctx context.Context, keyID string) error
	RevokeServiceAccountKey(ctx context.Context, clientID, serviceAccountID, keyID string) error
}

type EnterpriseSSORepository interface {
	CreateConnection(ctx context.Context, connection *domain.EnterpriseSSOConnection) error
	ListConnections(ctx context.Context, clientID string) ([]*domain.EnterpriseSSOConnection, error)
	GetConnection(ctx context.Context, clientID, connectionID string) (*domain.EnterpriseSSOConnection, error)
	GetConnectionByID(ctx context.Context, connectionID string) (*domain.EnterpriseSSOConnection, error)
	GetConnectionBySlug(ctx context.Context, clientID, slug string) (*domain.EnterpriseSSOConnection, error)
	GetActiveConnectionByDomain(ctx context.Context, clientID, domain string) (*domain.EnterpriseSSOConnection, error)
	UpdateConnection(ctx context.Context, connection *domain.EnterpriseSSOConnection) error
	DeactivateConnection(ctx context.Context, clientID, connectionID string) error
	FindIdentity(ctx context.Context, clientID, connectionID, externalID string) (*domain.EnterpriseSSOIdentity, error)
	UpsertIdentity(ctx context.Context, identity *domain.EnterpriseSSOIdentity) error
}

type SCIMRepository interface {
	CreateDirectory(ctx context.Context, directory *domain.SCIMDirectory) error
	ListDirectories(ctx context.Context, clientID string) ([]*domain.SCIMDirectory, error)
	GetDirectory(ctx context.Context, clientID, directoryID string) (*domain.SCIMDirectory, error)
	GetDirectoryByID(ctx context.Context, directoryID string) (*domain.SCIMDirectory, error)
	GetDirectoryByTokenHash(ctx context.Context, tokenHash string) (*domain.SCIMDirectory, error)
	UpdateDirectory(ctx context.Context, directory *domain.SCIMDirectory) error
	UpsertUser(ctx context.Context, user *domain.SCIMUser) error
	ListUsers(ctx context.Context, clientID, directoryID string) ([]*domain.SCIMUser, error)
	GetUser(ctx context.Context, clientID, directoryID, scimUserID string) (*domain.SCIMUser, error)
	GetUserByExternalID(ctx context.Context, clientID, directoryID, externalID string) (*domain.SCIMUser, error)
	DeleteUser(ctx context.Context, clientID, directoryID, scimUserID string) error
	UpsertGroup(ctx context.Context, group *domain.SCIMGroup) error
	ListGroups(ctx context.Context, clientID, directoryID string) ([]*domain.SCIMGroup, error)
	GetGroup(ctx context.Context, clientID, directoryID, scimGroupID string) (*domain.SCIMGroup, error)
	GetGroupByExternalID(ctx context.Context, clientID, directoryID, externalID string) (*domain.SCIMGroup, error)
	DeleteGroup(ctx context.Context, clientID, directoryID, scimGroupID string) error
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
