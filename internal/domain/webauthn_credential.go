package domain

import "time"

type WebAuthnCredential struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	CredentialID    []byte    `json:"-"`
	PublicKey       []byte    `json:"-"`
	AttestationType string    `json:"attestation_type"`
	Transport       []string  `json:"transport"`
	AAGUID          []byte    `json:"-"`
	SignCount       uint32    `json:"sign_count"`
	FriendlyName    string    `json:"friendly_name"`
	BackedUp        bool      `json:"backed_up"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}
