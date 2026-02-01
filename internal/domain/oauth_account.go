package domain

import "time"

type OAuthAccount struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	ClientID       string    `json:"client_id"`
	Provider       string    `json:"provider"`
	ProviderUserID string    `json:"provider_user_id"`
	Email          *string   `json:"email,omitempty"`
	AccessToken    string    `json:"-"`
	RefreshToken   string    `json:"-"`
	RawProfile     []byte    `json:"-"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
