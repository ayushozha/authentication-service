package grpc

import "github.com/Ayush10/authentication-service/internal/domain"

// --- Auth Service Messages ---

type SignupRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	APIKey      string `json:"api_key"`
	IP          string `json:"ip"`
	UserAgent   string `json:"user_agent"`
}

type LoginRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	APIKey    string `json:"api_key"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
	APIKey       string `json:"api_key"`
	IP           string `json:"ip"`
	UserAgent    string `json:"user_agent"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
	APIKey       string `json:"api_key"`
}

type GetUserRequest struct {
	UserID string `json:"user_id"`
}

type UpdateUserRequest struct {
	UserID      string `json:"user_id"`
	DisplayName string `json:"display_name"`
	Timezone    string `json:"timezone"`
}

type ChangePasswordRequest struct {
	UserID      string `json:"user_id"`
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
	APIKey      string `json:"api_key"`
	IP          string `json:"ip"`
	UserAgent   string `json:"user_agent"`
}

type VerifyEmailRequest struct {
	Token string `json:"token"`
}

type ResendVerificationRequest struct {
	UserID  string `json:"user_id"`
	BaseURL string `json:"base_url"`
}

type ForgotPasswordRequest struct {
	Email    string `json:"email"`
	ClientID string `json:"client_id"`
	BaseURL  string `json:"base_url"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type SendMagicLinkRequest struct {
	Email     string `json:"email"`
	APIKey    string `json:"api_key"`
	BaseURL   string `json:"base_url"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

type VerifyMagicLinkRequest struct {
	Token     string `json:"token"`
	APIKey    string `json:"api_key"`
	IP        string `json:"ip"`
	UserAgent string `json:"user_agent"`
}

type AuthResponse struct {
	AccessToken      string        `json:"access_token,omitempty"`
	RefreshToken     string        `json:"refresh_token,omitempty"`
	TokenType        string        `json:"token_type,omitempty"`
	ExpiresIn        int32         `json:"expires_in,omitempty"`
	User             *UserResponse `json:"user,omitempty"`
	Requires2FA      bool          `json:"requires_2fa,omitempty"`
	TwoFactorToken   string        `json:"two_factor_token,omitempty"`
	TwoFactorMethods []string      `json:"two_factor_methods,omitempty"`
}

type UserResponse struct {
	ID            string `json:"id"`
	ClientID      string `json:"client_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	DisplayName   string `json:"display_name"`
	AvatarURL     string `json:"avatar_url,omitempty"`
	Timezone      string `json:"timezone"`
	Locale        string `json:"locale"`
	Role          string `json:"role"`
	Status        string `json:"status"`
	TOTPEnabled   bool   `json:"totp_enabled"`
	LastLoginAt   string `json:"last_login_at,omitempty"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type Empty struct{}

// --- Token Service Messages ---

type ValidateTokenRequest struct {
	AccessToken string `json:"access_token"`
	APIKey      string `json:"api_key"`
}

type ValidateTokenResponse struct {
	Valid                   bool     `json:"valid"`
	UserID                  string   `json:"user_id,omitempty"`
	Email                   string   `json:"email,omitempty"`
	Role                    string   `json:"role,omitempty"`
	EmailVerified           bool     `json:"email_verified,omitempty"`
	ClientID                string   `json:"client_id,omitempty"`
	TokenUse                string   `json:"token_use,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Scopes                  []string `json:"scopes,omitempty"`
	ServiceAccountID        string   `json:"service_account_id,omitempty"`
	ServiceAccountName      string   `json:"service_account_name,omitempty"`
	OrganizationID          string   `json:"org_id,omitempty"`
	OrganizationSlug        string   `json:"org_slug,omitempty"`
	OrganizationRole        string   `json:"org_role,omitempty"`
	OrganizationPermissions []string `json:"org_permissions,omitempty"`
	Error                   string   `json:"error,omitempty"`
}

// --- Admin Service Messages ---

type CreateClientRequest struct {
	Name           string   `json:"name"`
	Slug           string   `json:"slug"`
	AllowedOrigins []string `json:"allowed_origins"`
	WebhookURL     string   `json:"webhook_url"`
}

type GetClientRequest struct {
	ClientID string `json:"client_id"`
}

type ListClientsRequest struct{}

type RotateJWTSecretRequest struct {
	ClientID string `json:"client_id"`
}

type RotateAPIKeyRequest struct {
	ClientID string `json:"client_id"`
}

type ClientResponse struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Slug           string   `json:"slug"`
	AllowedOrigins []string `json:"allowed_origins"`
	WebhookURL     string   `json:"webhook_url,omitempty"`
	Status         string   `json:"status"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}

type CreateClientResponse struct {
	Client *ClientResponse `json:"client"`
	APIKey string          `json:"api_key"`
}

type ListClientsResponse struct {
	Clients []*ClientResponse `json:"clients"`
}

type RotateAPIKeyResponse struct {
	Client *ClientResponse `json:"client"`
	APIKey string          `json:"api_key"`
}

// --- Conversion helpers ---

func userToResponse(u *domain.User) *UserResponse {
	if u == nil {
		return nil
	}
	r := &UserResponse{
		ID:            u.ID,
		ClientID:      u.ClientID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		DisplayName:   u.DisplayName,
		AvatarURL:     u.AvatarURL,
		Timezone:      u.Timezone,
		Locale:        u.Locale,
		Role:          u.Role,
		Status:        u.Status,
		TOTPEnabled:   u.TOTPEnabled,
		CreatedAt:     u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:     u.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if u.LastLoginAt != nil {
		r.LastLoginAt = u.LastLoginAt.Format("2006-01-02T15:04:05Z")
	}
	return r
}

func clientToResponse(c *domain.Client) *ClientResponse {
	if c == nil {
		return nil
	}
	return &ClientResponse{
		ID:             c.ID,
		Name:           c.Name,
		Slug:           c.Slug,
		AllowedOrigins: c.AllowedOrigins,
		WebhookURL:     c.WebhookURL,
		Status:         c.Status,
		CreatedAt:      c.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:      c.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}
