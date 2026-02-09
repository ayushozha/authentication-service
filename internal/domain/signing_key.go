package domain

import "time"

type SigningKey struct {
	ID            string     `json:"id"`
	ClientID      string     `json:"client_id"`
	KID           string     `json:"kid"`
	Algorithm     string     `json:"alg"`
	PublicKeyPEM  string     `json:"-"`
	PrivateKeyPEM string     `json:"-"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	RotatedAt     *time.Time `json:"rotated_at,omitempty"`
}
