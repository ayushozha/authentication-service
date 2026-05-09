package application

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
)

type TOTPService struct {
	users         UserRepository
	sessions      SessionRepository
	cache         CacheClient
	audit         AuditRepository
	recoveryCodes RecoveryCodeRepository
}

func NewTOTPService(users UserRepository, sessions SessionRepository, cache CacheClient, audit AuditRepository, recoveryCodes RecoveryCodeRepository) *TOTPService {
	return &TOTPService{users: users, sessions: sessions, cache: cache, audit: audit, recoveryCodes: recoveryCodes}
}

type TOTPSetupResponse struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
	QR     string `json:"qr"`
}

type RecoveryCodesResponse struct {
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
	UnusedCount   int      `json:"unused_count"`
}

func (s *TOTPService) Setup(ctx context.Context, client *domain.Client, userID, issuerName string) (*TOTPSetupResponse, error) {
	if s.cache == nil {
		return nil, domain.ErrRedisRequired
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, domain.ErrNotFound
	}
	if user.TOTPEnabled {
		return nil, domain.ErrTOTPAlreadyOn
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuerName,
		AccountName: user.Email,
	})
	if err != nil {
		return nil, err
	}

	png, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}

	if err := s.cache.Set(ctx, "totp_setup:"+user.ID, key.Secret(), 10*time.Minute); err != nil {
		return nil, domain.ErrRedisRequired
	}

	return &TOTPSetupResponse{
		Secret: key.Secret(),
		URI:    key.URL(),
		QR:     base64.StdEncoding.EncodeToString(png),
	}, nil
}

func (s *TOTPService) Enable(ctx context.Context, client *domain.Client, userID, code, ip, ua string) error {
	if s.cache == nil {
		return domain.ErrRedisRequired
	}
	var secret string
	secret, _ = s.cache.Get(ctx, "totp_setup:"+userID)
	if secret == "" {
		user, err := s.users.GetByID(ctx, userID)
		if err != nil || user == nil {
			return domain.ErrNotFound
		}
		if user.TOTPSecret != nil {
			secret = *user.TOTPSecret
		}
	}
	if secret == "" {
		return domain.ErrTOTPNoPending
	}

	if !totp.Validate(code, secret) {
		return domain.ErrTOTPInvalid
	}

	if err := s.users.SetTOTPSecret(ctx, userID, secret); err != nil {
		return err
	}
	if err := s.users.EnableTOTP(ctx, userID); err != nil {
		return err
	}

	if s.cache != nil {
		_ = s.cache.Del(ctx, "totp_setup:"+userID)
	}

	uid := userID
	s.audit.Log(ctx, client.ID, &uid, "totp_enabled", ip, ua, nil)
	return nil
}

func (s *TOTPService) Verify(ctx context.Context, client *domain.Client, twoFAToken, code, ip, ua string, accessTTL, refreshTTL time.Duration) (*AuthResponse, string, error) {
	if s.cache == nil {
		return nil, "", domain.ErrRedisRequired
	}

	challengeKey := "2fa:" + HashToken(twoFAToken)
	userID, err := s.cache.Get(ctx, challengeKey)
	if err != nil || userID == "" {
		return nil, "", domain.ErrInvalidToken
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, "", domain.ErrNotFound
	}
	if user.ClientID != client.ID {
		return nil, "", domain.ErrInvalidToken
	}

	if user.TOTPSecret == nil {
		return nil, "", domain.ErrTOTPNotEnabled
	}

	if !totp.Validate(code, *user.TOTPSecret) {
		return nil, "", domain.ErrTOTPInvalid
	}

	_ = s.cache.Del(ctx, challengeKey)
	_ = s.users.UpdateLastLogin(ctx, user.ID)
	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "login_success", ip, ua, map[string]interface{}{"method": "email+totp"})

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

func (s *TOTPService) GenerateRecoveryCodes(ctx context.Context, client *domain.Client, userID, ip, ua string) (*RecoveryCodesResponse, error) {
	if s.recoveryCodes == nil {
		return nil, domain.ErrNotFound
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, domain.ErrNotFound
	}
	if user.ClientID != client.ID {
		return nil, domain.ErrInvalidToken
	}
	if !user.TOTPEnabled {
		return nil, domain.ErrTOTPNotEnabled
	}

	const count = 10
	codes := make([]string, 0, count)
	hashes := make([]string, 0, count)
	for len(codes) < count {
		raw, err := GenerateToken(6)
		if err != nil {
			return nil, err
		}
		code := strings.ToUpper(raw[0:4] + "-" + raw[4:8] + "-" + raw[8:12])
		hash := HashToken(normalizeRecoveryCode(code))
		codes = append(codes, code)
		hashes = append(hashes, hash)
	}
	if err := s.recoveryCodes.ReplaceForUser(ctx, user.ID, hashes); err != nil {
		return nil, err
	}
	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "recovery_codes_rotated", ip, ua, map[string]interface{}{"count": len(codes)})
	return &RecoveryCodesResponse{RecoveryCodes: codes, UnusedCount: len(codes)}, nil
}

func (s *TOTPService) CountRecoveryCodes(ctx context.Context, client *domain.Client, userID string) (*RecoveryCodesResponse, error) {
	if s.recoveryCodes == nil {
		return nil, domain.ErrNotFound
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, domain.ErrNotFound
	}
	if user.ClientID != client.ID {
		return nil, domain.ErrInvalidToken
	}
	count, err := s.recoveryCodes.CountUnused(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return &RecoveryCodesResponse{UnusedCount: count}, nil
}

func (s *TOTPService) VerifyRecoveryCode(ctx context.Context, client *domain.Client, twoFAToken, code, ip, ua string, accessTTL, refreshTTL time.Duration) (*AuthResponse, string, error) {
	if s.cache == nil {
		return nil, "", domain.ErrRedisRequired
	}
	if s.recoveryCodes == nil {
		return nil, "", domain.ErrNotFound
	}

	challengeKey := "2fa:" + HashToken(twoFAToken)
	userID, err := s.cache.Get(ctx, challengeKey)
	if err != nil || userID == "" {
		return nil, "", domain.ErrInvalidToken
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, "", domain.ErrNotFound
	}
	if user.ClientID != client.ID {
		return nil, "", domain.ErrInvalidToken
	}
	if !user.TOTPEnabled {
		return nil, "", domain.ErrTOTPNotEnabled
	}

	used, err := s.recoveryCodes.MarkUsedByHash(ctx, user.ID, HashToken(normalizeRecoveryCode(code)))
	if err != nil {
		return nil, "", err
	}
	if !used {
		return nil, "", domain.ErrTOTPInvalid
	}

	_ = s.cache.Del(ctx, challengeKey)
	_ = s.users.UpdateLastLogin(ctx, user.ID)
	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "login_success", ip, ua, map[string]interface{}{"method": "email+recovery_code"})
	s.audit.Log(ctx, client.ID, &uid, "recovery_code_used", ip, ua, nil)

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

func (s *TOTPService) Disable(ctx context.Context, client *domain.Client, userID, code, ip, ua string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrNotFound
	}
	if !user.TOTPEnabled || user.TOTPSecret == nil {
		return domain.ErrTOTPNotEnabled
	}
	if !totp.Validate(code, *user.TOTPSecret) {
		return domain.ErrTOTPInvalid
	}
	if err := s.users.DisableTOTP(ctx, user.ID); err != nil {
		return err
	}
	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "totp_disabled", ip, ua, nil)
	return nil
}

func normalizeRecoveryCode(code string) string {
	return strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
}
