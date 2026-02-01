package application

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/go-webauthn/webauthn/webauthn"
)

type PasskeyService struct {
	users    UserRepository
	webauthn WebAuthnRepository
	sessions SessionRepository
	cache    CacheClient
	audit    AuditRepository
	wa       *webauthn.WebAuthn
}

type webauthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webauthnUser) WebAuthnName() string                       { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func NewPasskeyService(users UserRepository, wa WebAuthnRepository, sessions SessionRepository, cache CacheClient, audit AuditRepository, rpDisplayName, rpID, rpOrigin string) (*PasskeyService, error) {
	waInstance, err := webauthn.New(&webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	})
	if err != nil {
		return nil, err
	}
	return &PasskeyService{
		users: users, webauthn: wa, sessions: sessions,
		cache: cache, audit: audit, wa: waInstance,
	}, nil
}

func (s *PasskeyService) BeginRegistration(ctx context.Context, userID string) (interface{}, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, domain.ErrNotFound
	}
	existingCreds, _ := s.webauthn.GetByUser(ctx, user.ID)
	waUser := &webauthnUser{
		id: []byte(user.ID), name: user.Email,
		displayName: user.DisplayName, credentials: existingCreds,
	}
	options, sessionData, err := s.wa.BeginRegistration(waUser)
	if err != nil {
		return nil, err
	}
	if s.cache != nil {
		sessionJSON, _ := json.Marshal(sessionData)
		_ = s.cache.Set(ctx, "webauthn:reg:"+user.ID, string(sessionJSON), 5*time.Minute)
	}
	return options, nil
}

func (s *PasskeyService) FinishRegistration(ctx context.Context, client *domain.Client, userID, friendlyName string, r interface{ FormValue(string) string }) error {
	if s.cache == nil {
		return domain.ErrRedisRequired
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrNotFound
	}
	sessionJSON, err := s.cache.Get(ctx, "webauthn:reg:"+user.ID)
	if err != nil || sessionJSON == "" {
		return domain.ErrInvalidToken
	}
	_ = s.cache.Del(ctx, "webauthn:reg:"+user.ID)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
		return err
	}
	existingCreds, _ := s.webauthn.GetByUser(ctx, user.ID)
	waUser := &webauthnUser{
		id: []byte(user.ID), name: user.Email,
		displayName: user.DisplayName, credentials: existingCreds,
	}

	// We need the http.Request for FinishRegistration - this is handled at the handler level
	// This method signature needs adjustment. See the handler layer for the actual call.
	_ = waUser
	_ = sessionData
	return nil
}

func (s *PasskeyService) BeginLogin(ctx context.Context) (interface{}, string, error) {
	if s.cache == nil {
		return nil, "", domain.ErrRedisRequired
	}
	options, sessionData, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", err
	}
	sessionID, _ := GenerateToken(16)
	sessionJSON, _ := json.Marshal(sessionData)
	_ = s.cache.Set(ctx, "webauthn:login:"+sessionID, string(sessionJSON), 5*time.Minute)
	return map[string]interface{}{
		"publicKey":  options.Response,
		"session_id": sessionID,
	}, sessionID, nil
}

func (s *PasskeyService) ListPasskeys(ctx context.Context, userID string) ([]domain.WebAuthnCredential, error) {
	creds, err := s.webauthn.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if creds == nil {
		creds = []domain.WebAuthnCredential{}
	}
	return creds, nil
}

func (s *PasskeyService) DeletePasskey(ctx context.Context, client *domain.Client, passkeyID, userID, ip, ua string) error {
	if err := s.webauthn.DeleteByID(ctx, passkeyID, userID); err != nil {
		return err
	}
	uid := userID
	s.audit.Log(ctx, client.ID, &uid, "passkey_deleted", ip, ua, nil)
	return nil
}

func (s *PasskeyService) GetWA() *webauthn.WebAuthn         { return s.wa }
func (s *PasskeyService) GetWebAuthnRepo() WebAuthnRepository { return s.webauthn }
func (s *PasskeyService) GetUserRepo() UserRepository         { return s.users }
func (s *PasskeyService) GetSessionRepo() SessionRepository   { return s.sessions }
func (s *PasskeyService) GetCache() CacheClient               { return s.cache }
func (s *PasskeyService) GetAudit() AuditRepository           { return s.audit }
