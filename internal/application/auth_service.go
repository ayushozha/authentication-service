package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/mail"
	"strings"
	"time"
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
	Email         string `json:"email"`
	Role          string `json:"role"`
	EmailVerified bool   `json:"email_verified"`
	ClientID      string `json:"client_id"`
}

type AuthResponse struct {
	AccessToken  string       `json:"access_token,omitempty"`
	TokenType    string       `json:"token_type,omitempty"`
	ExpiresIn    int          `json:"expires_in,omitempty"`
	User         *domain.User `json:"user,omitempty"`
	Requires2FA  bool         `json:"requires_2fa,omitempty"`
	TwoFAToken   string       `json:"two_factor_token,omitempty"`
	TwoFAMethods []string     `json:"two_factor_methods,omitempty"`
}

type SignupRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type UpdateProfileRequest struct {
	DisplayName string `json:"display_name"`
	Timezone    string `json:"timezone"`
}

// OnSignup is called after successful signup to send verification email.
// Set this from outside (e.g., from the email verify service).
var OnSignup func(userID, email, displayName string)

func (s *AuthService) Signup(ctx context.Context, client *domain.Client, req SignupRequest, ip, ua string, bcryptCost int, accessTTL, refreshTTL time.Duration) (*AuthResponse, error) {
	// Rate limit
	if allowed, _, _ := s.rl.Allow(ctx, "rate:signup:"+ip, 5, 1*time.Hour); !allowed {
		return nil, domain.ErrRateLimit
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, fmt.Errorf("invalid email")
	}
	if msg := ValidatePasswordStrength(req.Password); msg != "" {
		return nil, fmt.Errorf("%s", msg)
	}

	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		displayName = strings.Split(email, "@")[0]
	}

	existing, err := s.users.GetByEmail(ctx, client.ID, email)
	if err != nil {
		return nil, fmt.Errorf("internal error")
	}
	if existing != nil {
		return nil, domain.ErrDuplicateEmail
	}

	hash, err := HashPassword(req.Password, bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("internal error")
	}

	user, err := s.users.Create(ctx, client.ID, email, hash, displayName)
	if err != nil {
		if strings.Contains(err.Error(), "idx_users_client_email") {
			return nil, domain.ErrDuplicateEmail
		}
		return nil, fmt.Errorf("could not create account")
	}

	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "signup", ip, ua, map[string]interface{}{"method": "email"})

	if OnSignup != nil {
		OnSignup(user.ID, user.Email, user.DisplayName)
	}

	accessToken, err := CreateAccessToken(client.JWTSecret, accessTTL, user)
	if err != nil {
		return nil, fmt.Errorf("internal error")
	}

	_, err = s.sessions.Create(ctx, user.ID, client.ID, ip, ua, refreshTTL)
	if err != nil {
		return nil, fmt.Errorf("internal error")
	}

	return &AuthResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(accessTTL.Seconds()),
		User:        user,
	}, nil
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

	user, err := s.users.GetByEmail(ctx, client.ID, req.Email)
	if err != nil {
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

	// Check 2FA
	if user.TOTPEnabled {
		twoFAToken, err := GenerateToken(32)
		if err != nil {
			return nil, "", fmt.Errorf("internal error")
		}
		if s.cache != nil {
			if err := s.cache.Set(ctx, "2fa:"+HashToken(twoFAToken), user.ID, 5*time.Minute); err != nil {
				return nil, "", fmt.Errorf("internal error")
			}
		}
		return &AuthResponse{
			Requires2FA:  true,
			TwoFAToken:   twoFAToken,
			TwoFAMethods: []string{"totp"},
		}, "", nil
	}

	_ = s.users.UpdateLastLogin(ctx, user.ID)
	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "login_success", ip, ua, map[string]interface{}{"method": "email"})

	accessToken, err := CreateAccessToken(client.JWTSecret, accessTTL, user)
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

func (s *AuthService) Refresh(ctx context.Context, client *domain.Client, rawRefreshToken, ip, ua string, accessTTL, refreshTTL time.Duration) (*AuthResponse, string, error) {
	userID, sessionID, err := s.sessions.Validate(ctx, rawRefreshToken)
	if err != nil {
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

	accessToken, err := CreateAccessToken(client.JWTSecret, accessTTL, user)
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

func (s *AuthService) Logout(ctx context.Context, rawRefreshToken string) error {
	return s.sessions.RevokeByToken(ctx, rawRefreshToken)
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
	if msg := ValidatePasswordStrength(req.NewPassword); msg != "" {
		return fmt.Errorf("%s", msg)
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrNotFound
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

	uid := user.ID
	s.audit.Log(ctx, client.ID, &uid, "password_changed", ip, ua, nil)
	return nil
}

// --- Crypto helpers ---

func CreateAccessToken(secret string, ttl time.Duration, user *domain.User) (string, error) {
	now := time.Now()
	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        uuid.NewString(),
		},
		Email:         user.Email,
		Role:          user.Role,
		EmailVerified: user.EmailVerified,
		ClientID:      user.ClientID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func ValidateAccessToken(secret, tokenStr string) (*AccessClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &AccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*AccessClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
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
	length := utf8.RuneCountInString(password)
	if length < 8 {
		return "password must be at least 8 characters"
	}
	if length > 72 {
		return "password must be at most 72 characters"
	}
	return ""
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
