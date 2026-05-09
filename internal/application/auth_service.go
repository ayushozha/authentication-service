package application

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	users    UserRepository
	sessions SessionRepository
	cache    CacheClient
	audit    AuditRepository
	rl       RateLimiter
}

func NewAuthService(users UserRepository, sessions SessionRepository, cache CacheClient, audit AuditRepository, rl RateLimiter) *AuthService {
	return &AuthService{users: users, sessions: sessions, cache: cache, audit: audit, rl: rl}
}

type AccessClaims struct {
	jwt.RegisteredClaims
	Email                   string   `json:"email"`
	Role                    string   `json:"role"`
	EmailVerified           bool     `json:"email_verified"`
	ClientID                string   `json:"client_id"`
	TokenUse                string   `json:"token_use,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Scopes                  []string `json:"scopes,omitempty"`
	ServiceAccountID        string   `json:"service_account_id,omitempty"`
	ServiceAccountName      string   `json:"service_account_name,omitempty"`
	OrganizationID          string   `json:"org_id,omitempty"`
	OrganizationSlug        string   `json:"org_slug,omitempty"`
	OrganizationRole        string   `json:"org_role,omitempty"`
	OrganizationPermissions []string `json:"org_permissions,omitempty"`
}

type accessTokenOptions struct {
	organizationID          string
	organizationSlug        string
	organizationRole        string
	organizationPermissions []string
	tokenUse                string
	scope                   string
	scopes                  []string
	serviceAccountID        string
	serviceAccountName      string
}

type AccessTokenOption func(*accessTokenOptions)

func WithOrganizationScope(org *domain.Organization, membership *domain.OrganizationMembership) AccessTokenOption {
	return func(opts *accessTokenOptions) {
		if org == nil || membership == nil {
			return
		}
		opts.organizationID = org.ID
		opts.organizationSlug = org.Slug
		opts.organizationRole = membership.Role
		opts.organizationPermissions = domain.EffectiveOrganizationPermissions(membership.Role, membership.Permissions)
	}
}

func WithServiceAccountScope(account *domain.ServiceAccount, scopes []string) AccessTokenOption {
	return func(opts *accessTokenOptions) {
		if account == nil {
			return
		}
		opts.serviceAccountID = account.ID
		opts.serviceAccountName = account.Name
		opts.scopes = append([]string(nil), scopes...)
		opts.scope = domain.ScopeString(scopes)
		opts.tokenUse = domain.TokenUseClientCredentials
	}
}

type AuthResponse struct {
	AccessToken  string       `json:"access_token,omitempty"`
	RefreshToken string       `json:"refresh_token,omitempty"`
	TokenType    string       `json:"token_type,omitempty"`
	ExpiresIn    int          `json:"expires_in,omitempty"`
	User         *domain.User `json:"user,omitempty"`
	Risk         *LoginRisk   `json:"risk,omitempty"`
	Requires2FA  bool         `json:"requires_2fa,omitempty"`
	TwoFAToken   string       `json:"two_factor_token,omitempty"`
	TwoFAMethods []string     `json:"two_factor_methods,omitempty"`
}

type SignupRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	DisplayName  string `json:"display_name"`
	SessionMode  string `json:"session_mode,omitempty"`
	CaptchaToken string `json:"captcha_token,omitempty"`
}

type LoginRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	CaptchaToken string `json:"captcha_token,omitempty"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type UpdateProfileRequest struct {
	DisplayName string `json:"display_name"`
	Timezone    string `json:"timezone"`
}

type LoginRisk struct {
	Level     string   `json:"level"`
	Reasons   []string `json:"reasons,omitempty"`
	NewIP     bool     `json:"new_ip,omitempty"`
	NewDevice bool     `json:"new_device,omitempty"`
}

type PasswordPolicy struct {
	MinLength     int
	MaxLength     int
	MinUnique     int
	BlockCommon   bool
	BlockUserInfo bool
}

// OnSignup is called after successful signup to send verification email.
// Set this from outside (e.g., from the email verify service).
var OnSignup func(userID, email, displayName string)
var signingKeys SigningKeyRepository
var passwordPolicy = DefaultPasswordPolicy()
var blockedSignupEmailDomains = DefaultBlockedSignupEmailDomains()

func SetSigningKeyRepository(repo SigningKeyRepository) {
	signingKeys = repo
}

func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:     8,
		MaxLength:     72,
		MinUnique:     4,
		BlockCommon:   true,
		BlockUserInfo: true,
	}
}

func SetPasswordPolicy(policy PasswordPolicy) {
	defaults := DefaultPasswordPolicy()
	if policy.MinLength <= 0 {
		policy.MinLength = defaults.MinLength
	}
	if policy.MaxLength <= 0 || policy.MaxLength > 72 {
		policy.MaxLength = defaults.MaxLength
	}
	if policy.MinUnique <= 0 {
		policy.MinUnique = defaults.MinUnique
	}
	if policy.MinLength > policy.MaxLength {
		policy.MinLength = defaults.MinLength
		policy.MaxLength = defaults.MaxLength
	}
	passwordPolicy = policy
}

func DefaultBlockedSignupEmailDomains() map[string]bool {
	return map[string]bool{
		"10minutemail.com":  true,
		"dispostable.com":   true,
		"guerrillamail.com": true,
		"guerrillamail.net": true,
		"mailinator.com":    true,
		"maildrop.cc":       true,
		"sharklasers.com":   true,
		"tempmail.com":      true,
		"throwawaymail.com": true,
		"yopmail.com":       true,
	}
}

func SetBlockedSignupEmailDomains(domains []string) {
	next := map[string]bool{}
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain != "" {
			next[domain] = true
		}
	}
	blockedSignupEmailDomains = next
}

func (s *AuthService) assessLoginRisk(ctx context.Context, clientID, userID, ip, ua string) LoginRisk {
	risk := LoginRisk{Level: "low"}
	sessions, err := s.sessions.ListForUser(ctx, clientID, userID)
	if err != nil || len(sessions) == 0 {
		return risk
	}

	currentIP := normalizeRiskIP(ip)
	currentDevice := deviceFingerprint(ua)
	if currentIP != "" && !sessionsContainIP(sessions, currentIP) {
		risk.NewIP = true
		risk.Reasons = append(risk.Reasons, "new_ip")
	}
	if currentDevice != "" && !sessionsContainDevice(sessions, currentDevice) {
		risk.NewDevice = true
		risk.Reasons = append(risk.Reasons, "new_device")
	}
	if risk.NewIP && risk.NewDevice {
		risk.Level = "medium"
	}
	return risk
}

func sessionsContainIP(sessions []*domain.Session, currentIP string) bool {
	for _, session := range sessions {
		if session != nil && normalizeRiskIP(session.IPAddress) == currentIP {
			return true
		}
	}
	return false
}

func sessionsContainDevice(sessions []*domain.Session, currentDevice string) bool {
	for _, session := range sessions {
		if session != nil && deviceFingerprint(session.UserAgent) == currentDevice {
			return true
		}
	}
	return false
}

func normalizeRiskIP(ip string) string {
	return strings.ToLower(strings.TrimSpace(ip))
}

func deviceFingerprint(ua string) string {
	ua = strings.ToLower(strings.TrimSpace(ua))
	if ua == "" {
		return ""
	}
	osName := "other"
	switch {
	case strings.Contains(ua, "android"):
		osName = "android"
	case strings.Contains(ua, "iphone"), strings.Contains(ua, "ipad"), strings.Contains(ua, "ios"):
		osName = "ios"
	case strings.Contains(ua, "windows"):
		osName = "windows"
	case strings.Contains(ua, "mac os"), strings.Contains(ua, "macintosh"):
		osName = "macos"
	case strings.Contains(ua, "linux"):
		osName = "linux"
	}
	browser := "other"
	switch {
	case strings.Contains(ua, "edg/"):
		browser = "edge"
	case strings.Contains(ua, "chrome/"), strings.Contains(ua, "crios/"):
		browser = "chrome"
	case strings.Contains(ua, "firefox/"), strings.Contains(ua, "fxios/"):
		browser = "firefox"
	case strings.Contains(ua, "safari/"):
		browser = "safari"
	}
	return osName + "/" + browser
}

func (r LoginRisk) isSuspicious() bool {
	return r.Level == "medium"
}

func riskResponse(risk LoginRisk) *LoginRisk {
	if !risk.isSuspicious() {
		return nil
	}
	return &risk
}

func riskAuditMetadata(method string, risk LoginRisk, extra map[string]interface{}) map[string]interface{} {
	metadata := map[string]interface{}{
		"method":     method,
		"risk_level": risk.Level,
	}
	if len(risk.Reasons) > 0 {
		metadata["risk_reasons"] = append([]string(nil), risk.Reasons...)
	}
	if risk.NewIP {
		metadata["new_ip"] = true
	}
	if risk.NewDevice {
		metadata["new_device"] = true
	}
	for key, value := range extra {
		metadata[key] = value
	}
	return metadata
}

func (s *AuthService) Signup(ctx context.Context, client *domain.Client, req SignupRequest, ip, ua string, bcryptCost int, accessTTL, refreshTTL time.Duration) (*AuthResponse, string, error) {
	// Rate limit
	if allowed, _, _ := s.rl.Allow(ctx, "rate:signup:"+ip, 5, 1*time.Hour); !allowed {
		return nil, "", domain.ErrRateLimit
	}
	if err := verifyBotToken(ctx, botProtection.SignupRequired, req.CaptchaToken, ip); err != nil {
		s.audit.Log(ctx, client.ID, nil, "signup_blocked", ip, ua, map[string]interface{}{"reason": "bot_verification"})
		return nil, "", err
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return nil, "", fmt.Errorf("email is required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, "", fmt.Errorf("invalid email")
	}
	if isBlockedSignupEmailDomain(email) {
		s.audit.Log(ctx, client.ID, nil, "signup_blocked", ip, ua, map[string]interface{}{"reason": "blocked_email_domain", "email": email})
		return nil, "", fmt.Errorf("email domain is not allowed")
	}

	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = strings.Split(email, "@")[0]
	}
	if msg := ValidatePassword(req.Password, email, displayName); msg != "" {
		s.audit.Log(ctx, client.ID, nil, "signup_blocked", ip, ua, map[string]interface{}{"reason": "password_policy", "email": email})
		return nil, "", fmt.Errorf("%s", msg)
	}

	existing, err := s.users.GetByEmail(ctx, client.ID, email)
	if err != nil && err != domain.ErrNotFound {
		return nil, "", fmt.Errorf("internal error")
	}
	if existing != nil {
		return nil, "", domain.ErrDuplicateEmail
	}

	hash, err := HashPassword(req.Password, bcryptCost)
	if err != nil {
		return nil, "", fmt.Errorf("internal error")
	}

	user, err := s.users.Create(ctx, client.ID, email, hash, displayName)
	if err != nil {
		if strings.Contains(err.Error(), "idx_users_client_email") {
			return nil, "", domain.ErrDuplicateEmail
		}
		return nil, "", fmt.Errorf("could not create account")
	}

	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "signup", ip, ua, map[string]interface{}{"method": "email"})

	if OnSignup != nil {
		OnSignup(user.ID, user.Email, user.DisplayName)
	}

	accessToken, err := CreateAccessToken(ctx, client, accessTTL, user)
	if err != nil {
		return nil, "", fmt.Errorf("internal error")
	}

	refreshToken, err := s.sessions.Create(ctx, user.ID, client.ID, ip, ua, refreshTTL)
	if err != nil {
		return nil, "", fmt.Errorf("internal error")
	}

	return &AuthResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(accessTTL.Seconds()),
		User:        user,
	}, refreshToken, nil
}

func (s *AuthService) Login(ctx context.Context, client *domain.Client, req LoginRequest, ip, ua string, accessTTL, refreshTTL time.Duration) (*AuthResponse, string, error) {
	emailKey := strings.ToLower(strings.TrimSpace(req.Email))

	if s.rl.IsLocked(ctx, client.ID+":"+emailKey) {
		s.audit.Log(ctx, client.ID, nil, "login_locked", ip, ua, map[string]interface{}{"email": emailKey})
		return nil, "", domain.ErrAccountLocked
	}

	if allowed, _, _ := s.rl.Allow(ctx, "rate:login:"+ip, 10, 15*time.Minute); !allowed {
		return nil, "", domain.ErrRateLimit
	}
	if err := verifyBotToken(ctx, botProtection.LoginRequired, req.CaptchaToken, ip); err != nil {
		s.audit.Log(ctx, client.ID, nil, "login_blocked", ip, ua, map[string]interface{}{"reason": "bot_verification", "email": emailKey})
		return nil, "", err
	}

	user, err := s.users.GetByEmail(ctx, client.ID, req.Email)
	if err != nil && err != domain.ErrNotFound {
		return nil, "", fmt.Errorf("internal error")
	}
	if user == nil || user.PasswordHash == nil || !CheckPassword(*user.PasswordHash, req.Password) {
		s.rl.RecordFailedLogin(ctx, client.ID+":"+emailKey)
		var uid *string
		if user != nil {
			uid = &user.ID
		}
		s.audit.Log(ctx, client.ID, uid, "login_failed", ip, ua, map[string]interface{}{"email": emailKey})
		return nil, "", domain.ErrInvalidPassword
	}

	if user.Status != "active" {
		return nil, "", domain.ErrAccountSuspended
	}

	s.rl.ClearFailedLogins(ctx, client.ID+":"+emailKey)
	risk := s.assessLoginRisk(ctx, client.ID, user.ID, ip, ua)
	if risk.isSuspicious() {
		uid := user.ID
		s.audit.Log(ctx, client.ID, &uid, "suspicious_login", ip, ua, riskAuditMetadata("password", risk, map[string]interface{}{"email": emailKey}))
	}

	// Check 2FA
	if user.TOTPEnabled {
		if s.cache == nil {
			return nil, "", domain.ErrRedisRequired
		}
		twoFAToken, err := GenerateToken(32)
		if err != nil {
			return nil, "", fmt.Errorf("internal error")
		}
		if err := s.cache.Set(ctx, "2fa:"+HashToken(twoFAToken), user.ID, 5*time.Minute); err != nil {
			return nil, "", domain.ErrRedisRequired
		}
		if risk.isSuspicious() {
			uid := user.ID
			s.audit.Log(ctx, client.ID, &uid, "adaptive_mfa_challenge", ip, ua, riskAuditMetadata("totp", risk, nil))
		}
		return &AuthResponse{
			Requires2FA:  true,
			TwoFAToken:   twoFAToken,
			TwoFAMethods: []string{"totp", "recovery_code"},
			Risk:         riskResponse(risk),
		}, "", nil
	}

	_ = s.users.UpdateLastLogin(ctx, user.ID)
	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "login_success", ip, ua, riskAuditMetadata("email", risk, nil))

	accessToken, err := CreateAccessToken(ctx, client, accessTTL, user)
	if err != nil {
		return nil, "", fmt.Errorf("internal error")
	}

	refreshToken, err := s.sessions.Create(ctx, user.ID, client.ID, ip, ua, refreshTTL)
	if err != nil {
		return nil, "", fmt.Errorf("internal error")
	}

	return &AuthResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(accessTTL.Seconds()),
		User:        user,
		Risk:        riskResponse(risk),
	}, refreshToken, nil
}

func (s *AuthService) Refresh(ctx context.Context, client *domain.Client, rawRefreshToken, ip, ua string, accessTTL, refreshTTL time.Duration) (*AuthResponse, string, error) {
	userID, sessionID, err := s.sessions.Validate(ctx, client.ID, rawRefreshToken)
	if err != nil {
		if err == domain.ErrInvalidToken {
			return nil, "", domain.ErrInvalidToken
		}
		return nil, "", fmt.Errorf("internal error")
	}
	if userID == "" {
		return nil, "", domain.ErrInvalidToken
	}

	_ = s.sessions.Revoke(ctx, sessionID)

	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, "", domain.ErrNotFound
	}

	accessToken, err := CreateAccessToken(ctx, client, accessTTL, user)
	if err != nil {
		return nil, "", fmt.Errorf("internal error")
	}

	newRefreshToken, err := s.sessions.Create(ctx, user.ID, client.ID, ip, ua, refreshTTL)
	if err != nil {
		return nil, "", fmt.Errorf("internal error")
	}

	return &AuthResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(accessTTL.Seconds()),
		User:        user,
	}, newRefreshToken, nil
}

func (s *AuthService) Logout(ctx context.Context, clientID, rawRefreshToken string) error {
	return s.sessions.RevokeByToken(ctx, clientID, rawRefreshToken)
}

func (s *AuthService) ListSessions(ctx context.Context, client *domain.Client, userID string) ([]*domain.Session, error) {
	if client == nil {
		return nil, domain.ErrInvalidClient
	}
	return s.sessions.ListForUser(ctx, client.ID, userID)
}

func (s *AuthService) RevokeSession(ctx context.Context, client *domain.Client, userID, sessionID, ip, ua string) error {
	if client == nil {
		return domain.ErrInvalidClient
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return domain.ErrNotFound
	}
	if err := s.sessions.RevokeForUser(ctx, client.ID, userID, sessionID); err != nil {
		return err
	}
	s.audit.Log(ctx, client.ID, &userID, "session_revoked", ip, ua, map[string]interface{}{"session_id": sessionID})
	return nil
}

func (s *AuthService) RevokeAllSessions(ctx context.Context, client *domain.Client, userID, ip, ua string) error {
	if client == nil {
		return domain.ErrInvalidClient
	}
	if err := s.sessions.RevokeAllForUser(ctx, client.ID, userID); err != nil {
		return err
	}
	s.audit.Log(ctx, client.ID, &userID, "sessions_revoked", ip, ua, nil)
	return nil
}

func (s *AuthService) GetUser(ctx context.Context, userID string) (*domain.User, error) {
	return s.users.GetByID(ctx, userID)
}

func (s *AuthService) UpdateProfile(ctx context.Context, userID string, req UpdateProfileRequest) (*domain.User, error) {
	displayName := strings.TrimSpace(req.DisplayName)
	timezone := strings.TrimSpace(req.Timezone)
	if timezone == "" {
		timezone = "UTC"
	}
	if err := s.users.UpdateProfile(ctx, userID, displayName, timezone); err != nil {
		return nil, err
	}
	return s.users.GetByID(ctx, userID)
}

func (s *AuthService) ChangePassword(ctx context.Context, client *domain.Client, userID string, req ChangePasswordRequest, ip, ua string, bcryptCost int) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrNotFound
	}

	if msg := ValidatePassword(req.NewPassword, user.Email, user.DisplayName); msg != "" {
		uid := user.ID
		s.audit.Log(ctx, client.ID, &uid, "password_change_blocked", ip, ua, map[string]interface{}{"reason": "password_policy"})
		return fmt.Errorf("%s", msg)
	}

	if user.PasswordHash != nil && !CheckPassword(*user.PasswordHash, req.OldPassword) {
		return fmt.Errorf("incorrect current password")
	}

	hash, err := HashPassword(req.NewPassword, bcryptCost)
	if err != nil {
		return fmt.Errorf("internal error")
	}

	if err := s.users.UpdatePassword(ctx, user.ID, hash); err != nil {
		return err
	}
	_ = s.sessions.RevokeAllForUser(ctx, client.ID, user.ID)

	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "password_changed", ip, ua, nil)
	return nil
}

// --- Crypto helpers ---

func CreateAccessToken(ctx context.Context, client *domain.Client, ttl time.Duration, user *domain.User, opts ...AccessTokenOption) (string, error) {
	tokenOpts := buildAccessTokenOptions(opts...)
	if strings.EqualFold(client.TokenMode, "v2_jwks") {
		key, err := ensureActiveSigningKey(ctx, client.ID)
		if err != nil {
			return "", err
		}
		return createRS256Token(key, ttl, user, tokenOpts)
	}
	return createHS256Token(client.JWTSecret, ttl, user, tokenOpts)
}

func CreateMachineAccessToken(ctx context.Context, client *domain.Client, ttl time.Duration, account *domain.ServiceAccount, scopes []string) (string, error) {
	user := &domain.User{
		ID:            account.ID,
		ClientID:      account.ClientID,
		DisplayName:   account.Name,
		Role:          "service_account",
		Status:        account.Status,
		EmailVerified: true,
	}
	return CreateAccessToken(ctx, client, ttl, user, WithServiceAccountScope(account, scopes))
}

func buildAccessTokenOptions(opts ...AccessTokenOption) accessTokenOptions {
	var tokenOpts accessTokenOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&tokenOpts)
		}
	}
	return tokenOpts
}

func createHS256Token(secret string, ttl time.Duration, user *domain.User, opts accessTokenOptions) (string, error) {
	now := time.Now()
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.NewString(),
		},
		Email:                   user.Email,
		Role:                    user.Role,
		EmailVerified:           user.EmailVerified,
		ClientID:                user.ClientID,
		TokenUse:                opts.tokenUse,
		Scope:                   opts.scope,
		Scopes:                  opts.scopes,
		ServiceAccountID:        opts.serviceAccountID,
		ServiceAccountName:      opts.serviceAccountName,
		OrganizationID:          opts.organizationID,
		OrganizationSlug:        opts.organizationSlug,
		OrganizationRole:        opts.organizationRole,
		OrganizationPermissions: opts.organizationPermissions,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func createRS256Token(key *domain.SigningKey, ttl time.Duration, user *domain.User, opts accessTokenOptions) (string, error) {
	privateKey, err := parseRSAPrivateKey(key.PrivateKeyPEM)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.NewString(),
		},
		Email:                   user.Email,
		Role:                    user.Role,
		EmailVerified:           user.EmailVerified,
		ClientID:                user.ClientID,
		TokenUse:                opts.tokenUse,
		Scope:                   opts.scope,
		Scopes:                  opts.scopes,
		ServiceAccountID:        opts.serviceAccountID,
		ServiceAccountName:      opts.serviceAccountName,
		OrganizationID:          opts.organizationID,
		OrganizationSlug:        opts.organizationSlug,
		OrganizationRole:        opts.organizationRole,
		OrganizationPermissions: opts.organizationPermissions,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.KID
	return token.SignedString(privateKey)
}

func ValidateAccessToken(ctx context.Context, client *domain.Client, tokenStr string) (*AccessClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &AccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.Alg() {
		case jwt.SigningMethodHS256.Alg():
			return []byte(client.JWTSecret), nil
		case jwt.SigningMethodRS256.Alg():
			kid, _ := t.Header["kid"].(string)
			if kid == "" {
				return nil, fmt.Errorf("missing key id")
			}
			if signingKeys == nil {
				return nil, fmt.Errorf("signing key repository is not configured")
			}
			key, err := signingKeys.GetByClientAndKID(ctx, client.ID, kid)
			if err != nil || key == nil {
				return nil, fmt.Errorf("unknown signing key")
			}
			return parseRSAPublicKey(key.PublicKeyPEM)
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*AccessClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	if claims.ClientID != client.ID {
		return nil, fmt.Errorf("token does not belong to this client")
	}
	return claims, nil
}

func ensureActiveSigningKey(ctx context.Context, clientID string) (*domain.SigningKey, error) {
	if signingKeys == nil {
		return nil, fmt.Errorf("signing key repository is not configured")
	}
	key, err := signingKeys.GetActiveByClient(ctx, clientID)
	if err == nil && key != nil {
		return key, nil
	}
	if err != nil && err != domain.ErrNotFound {
		return nil, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	privateDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateDER})
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	newKey := &domain.SigningKey{
		ID:            uuid.NewString(),
		ClientID:      clientID,
		KID:           uuid.NewString(),
		Algorithm:     "RS256",
		PublicKeyPEM:  string(publicPEM),
		PrivateKeyPEM: string(privatePEM),
		Status:        "active",
		CreatedAt:     time.Now().UTC(),
	}
	if err := signingKeys.Create(ctx, newKey); err != nil {
		return nil, err
	}
	return newKey, nil
}

func parseRSAPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("invalid private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func parseRSAPublicKey(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported public key type")
	}
	return rsaPub, nil
}

func ClientJWKS(ctx context.Context, clientID string) (map[string]interface{}, error) {
	if signingKeys == nil {
		return nil, fmt.Errorf("signing key repository is not configured")
	}
	keys, err := signingKeys.ListActiveByClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	return buildJWKS(keys)
}

func JWKS(ctx context.Context) (map[string]interface{}, error) {
	if signingKeys == nil {
		return nil, fmt.Errorf("signing key repository is not configured")
	}
	keys, err := signingKeys.ListActive(ctx)
	if err != nil {
		return nil, err
	}
	return buildJWKS(keys)
}

func buildJWKS(keys []*domain.SigningKey) (map[string]interface{}, error) {
	jwkKeys := make([]map[string]interface{}, 0, len(keys))
	for _, key := range keys {
		pub, err := parseRSAPublicKey(key.PublicKeyPEM)
		if err != nil {
			return nil, err
		}
		eBytes := bigIntBytes(pub.E)
		jwkKeys = append(jwkKeys, map[string]interface{}{
			"kty": "RSA",
			"kid": key.KID,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(eBytes),
		})
	}
	return map[string]interface{}{"keys": jwkKeys}, nil
}

func bigIntBytes(v int) []byte {
	i := big.NewInt(int64(v))
	return i.Bytes()
}

func HashPassword(password string, cost int) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func ValidatePasswordStrength(password string) string {
	return ValidatePassword(password, "", "")
}

func ValidatePassword(password, email, displayName string) string {
	policy := passwordPolicy
	length := utf8.RuneCountInString(password)
	if length < policy.MinLength {
		return fmt.Sprintf("password must be at least %d characters", policy.MinLength)
	}
	if length > policy.MaxLength {
		return fmt.Sprintf("password must be at most %d characters", policy.MaxLength)
	}
	if uniqueNormalizedRunes(password) < policy.MinUnique {
		return fmt.Sprintf("password must contain at least %d unique characters", policy.MinUnique)
	}
	normalized := normalizePasswordSignal(password)
	if policy.BlockCommon && commonPasswordSignals[normalized] {
		return "password appears in a known compromised password list"
	}
	if policy.BlockUserInfo {
		if token := normalizePasswordSignal(strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")[0]); len(token) >= 4 && strings.Contains(normalized, token) {
			return "password must not contain your email name"
		}
		for _, token := range strings.Fields(strings.ToLower(displayName)) {
			token = normalizePasswordSignal(token)
			if len(token) >= 4 && strings.Contains(normalized, token) {
				return "password must not contain your name"
			}
		}
	}
	return ""
}

func isBlockedSignupEmailDomain(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	domain := strings.ToLower(strings.TrimSpace(parts[1]))
	return blockedSignupEmailDomains[domain]
}

func normalizePasswordSignal(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func uniqueNormalizedRunes(value string) int {
	seen := map[rune]struct{}{}
	for _, r := range strings.ToLower(value) {
		if unicode.IsSpace(r) {
			continue
		}
		seen[r] = struct{}{}
	}
	return len(seen)
}

var commonPasswordSignals = map[string]bool{
	"000000":                    true,
	"111111":                    true,
	"123123":                    true,
	"123456":                    true,
	"1234567":                   true,
	"12345678":                  true,
	"123456789":                 true,
	"1234567890":                true,
	"abc123":                    true,
	"admin":                     true,
	"admin123":                  true,
	"changeme":                  true,
	"default":                   true,
	"dragon":                    true,
	"iloveyou":                  true,
	"letmein":                   true,
	"monkey":                    true,
	"password":                  true,
	"password1":                 true,
	"password12":                true,
	"password123":               true,
	"password1234":              true,
	"qwerty":                    true,
	"qwerty123":                 true,
	"welcome":                   true,
	"welcome1":                  true,
	"welcome123":                true,
	"zaq12wsx":                  true,
	"trustno1":                  true,
	"correcthorsebatterystaple": true,
}

func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func GenerateToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
