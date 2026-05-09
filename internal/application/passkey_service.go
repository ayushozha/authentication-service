package application

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type PasskeyService struct {
	users    UserRepository
	webauthn WebAuthnRepository
	sessions SessionRepository
	cache    CacheClient
	audit    AuditRepository

	defaultRPName   string
	defaultRPID     string
	defaultRPOrigin string

	waMu    sync.RWMutex
	waCache map[string]*webauthn.WebAuthn
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

type passkeyRegistrationState struct {
	ClientID    string               `json:"client_id"`
	UserID      string               `json:"user_id"`
	SessionData webauthn.SessionData `json:"session_data"`
}

type passkeyLoginState struct {
	ClientID    string               `json:"client_id"`
	SessionData webauthn.SessionData `json:"session_data"`
}

type PasskeyAttestationPolicy struct {
	Conveyance         protocol.ConveyancePreference `json:"conveyance"`
	RequireAttestation bool                          `json:"require_attestation"`
	AllowedFormats     []string                      `json:"allowed_formats,omitempty"`
}

func NewPasskeyService(users UserRepository, wa WebAuthnRepository, sessions SessionRepository, cache CacheClient, audit AuditRepository, rpDisplayName, rpID, rpOrigin string) (*PasskeyService, error) {
	svc := &PasskeyService{
		users:           users,
		webauthn:        wa,
		sessions:        sessions,
		cache:           cache,
		audit:           audit,
		defaultRPName:   rpDisplayName,
		defaultRPID:     rpID,
		defaultRPOrigin: rpOrigin,
		waCache:         make(map[string]*webauthn.WebAuthn),
	}
	_, err := svc.getWebAuthn(clientRPConfig{
		DisplayName: rpDisplayName,
		RPID:        rpID,
		RPOrigin:    rpOrigin,
	})
	if err != nil {
		return nil, err
	}
	return svc, nil
}

func (s *PasskeyService) BeginRegistration(ctx context.Context, client *domain.Client, userID string) (interface{}, error) {
	if s.cache == nil {
		return nil, domain.ErrRedisRequired
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, domain.ErrNotFound
	}
	if user.ClientID != client.ID {
		return nil, domain.ErrNotFound
	}

	existingCreds, _ := s.webauthn.GetByUser(ctx, user.ID)
	waUser := &webauthnUser{
		id: []byte(user.ID), name: user.Email,
		displayName: user.DisplayName, credentials: existingCreds,
	}

	waClient, err := s.getWebAuthn(s.configForClient(client))
	if err != nil {
		return nil, err
	}

	policy := passkeyAttestationPolicyForClient(client)
	registrationOptions := []webauthn.RegistrationOption{
		webauthn.WithConveyancePreference(policy.Conveyance),
	}
	if len(policy.AllowedFormats) > 0 {
		formats := make([]protocol.AttestationFormat, 0, len(policy.AllowedFormats))
		for _, format := range policy.AllowedFormats {
			formats = append(formats, protocol.AttestationFormat(format))
		}
		registrationOptions = append(registrationOptions, webauthn.WithAttestationFormats(formats))
	}
	options, sessionData, err := waClient.BeginRegistration(waUser, registrationOptions...)
	if err != nil {
		return nil, err
	}

	state := passkeyRegistrationState{
		ClientID:    client.ID,
		UserID:      user.ID,
		SessionData: *sessionData,
	}
	sessionJSON, _ := json.Marshal(state)
	if err := s.cache.Set(ctx, registrationKey(client.ID, user.ID), string(sessionJSON), 5*time.Minute); err != nil {
		return nil, domain.ErrRedisRequired
	}

	return options, nil
}

func (s *PasskeyService) FinishRegistration(ctx context.Context, client *domain.Client, userID, friendlyName string, r *http.Request, ip, ua string) error {
	if s.cache == nil {
		return domain.ErrRedisRequired
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrNotFound
	}
	if user.ClientID != client.ID {
		return domain.ErrInvalidToken
	}

	sessionJSON, err := s.cache.Get(ctx, registrationKey(client.ID, user.ID))
	if err != nil || sessionJSON == "" {
		return domain.ErrInvalidToken
	}
	_ = s.cache.Del(ctx, registrationKey(client.ID, user.ID))

	var state passkeyRegistrationState
	if err := json.Unmarshal([]byte(sessionJSON), &state); err != nil {
		return err
	}
	if state.ClientID != client.ID || state.UserID != user.ID {
		return domain.ErrInvalidToken
	}

	existingCreds, _ := s.webauthn.GetByUser(ctx, user.ID)
	waUser := &webauthnUser{
		id: []byte(user.ID), name: user.Email,
		displayName: user.DisplayName, credentials: existingCreds,
	}

	waClient, err := s.getWebAuthn(s.configForClient(client))
	if err != nil {
		return err
	}
	parsedResponse, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		return err
	}
	policy := passkeyAttestationPolicyForClient(client)
	attestationFormat := strings.TrimSpace(parsedResponse.Response.AttestationObject.Format)
	if err := validatePasskeyAttestationPolicy(policy, attestationFormat); err != nil {
		uid := user.ID
		s.audit.Log(ctx, client.ID, &uid, "passkey_attestation_rejected", ip, ua, map[string]interface{}{
			"attestation_format": attestationFormat,
			"attestation_policy": string(policy.Conveyance),
			"allowed_formats":    append([]string(nil), policy.AllowedFormats...),
		})
		return err
	}
	credential, err := waClient.CreateCredential(waUser, state.SessionData, parsedResponse)
	if err != nil {
		return err
	}

	name := strings.TrimSpace(friendlyName)
	if name == "" {
		name = "Passkey"
	}
	if err := s.webauthn.Save(ctx, user.ID, credential, name); err != nil {
		return err
	}

	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "passkey_registered", ip, ua, map[string]interface{}{
		"attestation_format": attestationFormat,
		"attestation_policy": string(policy.Conveyance),
	})
	return nil
}

func (s *PasskeyService) BeginLogin(ctx context.Context, client *domain.Client) (interface{}, string, error) {
	if s.cache == nil {
		return nil, "", domain.ErrRedisRequired
	}
	waClient, err := s.getWebAuthn(s.configForClient(client))
	if err != nil {
		return nil, "", err
	}

	options, sessionData, err := waClient.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", err
	}
	sessionID, _ := GenerateToken(16)
	state := passkeyLoginState{
		ClientID:    client.ID,
		SessionData: *sessionData,
	}
	sessionJSON, _ := json.Marshal(state)
	if err := s.cache.Set(ctx, loginKey(sessionID), string(sessionJSON), 5*time.Minute); err != nil {
		return nil, "", domain.ErrRedisRequired
	}

	return map[string]interface{}{
		"publicKey":  options.Response,
		"session_id": sessionID,
	}, sessionID, nil
}

func (s *PasskeyService) FinishLogin(ctx context.Context, client *domain.Client, sessionID string, r *http.Request, ip, ua string, accessTTL, refreshTTL time.Duration) (*AuthResponse, string, error) {
	if s.cache == nil {
		return nil, "", domain.ErrRedisRequired
	}

	sessionJSON, err := s.cache.Get(ctx, loginKey(sessionID))
	if err != nil || sessionJSON == "" {
		return nil, "", domain.ErrInvalidToken
	}
	_ = s.cache.Del(ctx, loginKey(sessionID))

	var state passkeyLoginState
	if err := json.Unmarshal([]byte(sessionJSON), &state); err != nil {
		return nil, "", err
	}
	if state.ClientID != client.ID {
		return nil, "", domain.ErrInvalidToken
	}

	waClient, err := s.getWebAuthn(s.configForClient(client))
	if err != nil {
		return nil, "", err
	}

	userHandler := func(rawID, userHandle []byte) (webauthn.User, error) {
		uid := string(userHandle)
		u, err := s.users.GetByID(ctx, uid)
		if err != nil || u == nil {
			return nil, err
		}
		if u.ClientID != client.ID {
			return nil, domain.ErrNotFound
		}
		creds, _ := s.webauthn.GetByUser(ctx, uid)
		return &webauthnUser{
			id: []byte(u.ID), name: u.Email,
			displayName: u.DisplayName, credentials: creds,
		}, nil
	}

	credential, err := waClient.FinishDiscoverableLogin(userHandler, state.SessionData, r)
	if err != nil {
		return nil, "", err
	}
	_ = s.webauthn.UpdateSignCount(ctx, credential.ID, credential.Authenticator.SignCount)

	userIDStr, err := s.webauthn.GetUserIDByCredentialID(ctx, credential.ID)
	if err != nil || userIDStr == "" {
		return nil, "", domain.ErrNotFound
	}

	user, err := s.users.GetByID(ctx, userIDStr)
	if err != nil || user == nil {
		return nil, "", domain.ErrNotFound
	}
	if user.ClientID != client.ID {
		return nil, "", domain.ErrInvalidToken
	}
	if user.Status != "active" {
		return nil, "", domain.ErrAccountSuspended
	}

	_ = s.users.UpdateLastLogin(ctx, user.ID)
	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "login_success", ip, ua, map[string]interface{}{"method": "passkey"})

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

type clientRPConfig struct {
	DisplayName string
	RPID        string
	RPOrigin    string
}

func (s *PasskeyService) configForClient(client *domain.Client) clientRPConfig {
	cfg := clientRPConfig{
		DisplayName: s.defaultRPName,
		RPID:        s.defaultRPID,
		RPOrigin:    s.defaultRPOrigin,
	}
	if client == nil || client.Settings == nil {
		return cfg
	}
	if v, ok := getStringSetting(client.Settings, "webauthn_display_name"); ok {
		cfg.DisplayName = v
	}
	if v, ok := getStringSetting(client.Settings, "webauthn_rp_id"); ok {
		cfg.RPID = v
	}
	if v, ok := getStringSetting(client.Settings, "webauthn_rp_origin"); ok {
		cfg.RPOrigin = v
	}
	return cfg
}

func passkeyAttestationPolicyForClient(client *domain.Client) PasskeyAttestationPolicy {
	policy := PasskeyAttestationPolicy{Conveyance: protocol.PreferNoAttestation}
	if client == nil || client.Settings == nil {
		return policy
	}
	if v, ok := getStringSetting(client.Settings, "webauthn_attestation"); ok {
		switch strings.ToLower(v) {
		case string(protocol.PreferIndirectAttestation):
			policy.Conveyance = protocol.PreferIndirectAttestation
		case string(protocol.PreferDirectAttestation):
			policy.Conveyance = protocol.PreferDirectAttestation
		case string(protocol.PreferEnterpriseAttestation):
			policy.Conveyance = protocol.PreferEnterpriseAttestation
		default:
			policy.Conveyance = protocol.PreferNoAttestation
		}
	}
	if v, ok := getBoolSetting(client.Settings, "webauthn_require_attestation"); ok {
		policy.RequireAttestation = v
	}
	if v, ok := getBoolSetting(client.Settings, "webauthn_block_none_attestation"); ok && v {
		policy.RequireAttestation = true
	}
	policy.AllowedFormats = getStringListSetting(client.Settings, "webauthn_allowed_attestation_formats")
	return policy
}

func validatePasskeyAttestationPolicy(policy PasskeyAttestationPolicy, format string) error {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = string(protocol.AttestationFormatNone)
	}
	if policy.RequireAttestation && format == string(protocol.AttestationFormatNone) {
		return domain.ErrPasskeyAttestation
	}
	if len(policy.AllowedFormats) == 0 {
		return nil
	}
	for _, allowed := range policy.AllowedFormats {
		if strings.EqualFold(strings.TrimSpace(allowed), format) {
			return nil
		}
	}
	return domain.ErrPasskeyAttestation
}

func getStringSetting(settings map[string]interface{}, key string) (string, bool) {
	val, ok := settings[key]
	if !ok {
		return "", false
	}
	s, ok := val.(string)
	if !ok {
		return "", false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	return s, true
}

func getBoolSetting(settings map[string]interface{}, key string) (bool, bool) {
	val, ok := settings[key]
	if !ok {
		return false, false
	}
	switch v := val.(type) {
	case bool:
		return v, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes", "on":
			return true, true
		case "false", "0", "no", "off":
			return false, true
		}
	}
	return false, false
}

func getStringListSetting(settings map[string]interface{}, key string) []string {
	val, ok := settings[key]
	if !ok {
		return nil
	}
	out := []string{}
	add := func(value string) {
		for _, part := range strings.Split(value, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part != "" {
				out = append(out, part)
			}
		}
	}
	switch v := val.(type) {
	case []string:
		for _, item := range v {
			add(item)
		}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				add(s)
			}
		}
	case string:
		add(v)
	}
	return out
}

func (s *PasskeyService) getWebAuthn(cfg clientRPConfig) (*webauthn.WebAuthn, error) {
	cacheKey := cfg.DisplayName + "|" + cfg.RPID + "|" + cfg.RPOrigin
	s.waMu.RLock()
	if waClient, ok := s.waCache[cacheKey]; ok {
		s.waMu.RUnlock()
		return waClient, nil
	}
	s.waMu.RUnlock()

	waClient, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.DisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     []string{cfg.RPOrigin},
	})
	if err != nil {
		return nil, err
	}

	s.waMu.Lock()
	s.waCache[cacheKey] = waClient
	s.waMu.Unlock()
	return waClient, nil
}

func registrationKey(clientID, userID string) string {
	return "webauthn:reg:" + clientID + ":" + userID
}

func loginKey(sessionID string) string {
	return "webauthn:login:" + sessionID
}
