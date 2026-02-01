package domain

import "time"

type User struct {
	ID            string     `json:"id"`
	ClientID      string     `json:"client_id"`
	Email         string     `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	PasswordHash  *string    `json:"-"`
	DisplayName   string     `json:"display_name"`
	AvatarURL     string     `json:"avatar_url,omitempty"`
	Timezone      string     `json:"timezone"`
	Locale        string     `json:"locale"`
	Role          string     `json:"role"`
	Status        string     `json:"status"`
	TOTPEnabled   bool       `json:"totp_enabled"`
	TOTPSecret    *string    `json:"-"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}
