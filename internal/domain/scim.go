package domain

import "time"

const (
	SCIMDirectoryStatusActive   = "active"
	SCIMDirectoryStatusDisabled = "disabled"
)

type SCIMDirectory struct {
	ID          string    `json:"id"`
	ClientID    string    `json:"client_id"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	TokenHash   string    `json:"-"`
	TokenPrefix string    `json:"token_prefix"`
	Domains     []string  `json:"domains"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type SCIMDirectoryWithToken struct {
	Directory *SCIMDirectory `json:"directory"`
	Token     string         `json:"token"`
}

type SCIMUser struct {
	ID          string    `json:"id"`
	ClientID    string    `json:"client_id"`
	DirectoryID string    `json:"directory_id"`
	UserID      string    `json:"user_id"`
	ExternalID  string    `json:"external_id"`
	UserName    string    `json:"user_name"`
	Active      bool      `json:"active"`
	RawResource []byte    `json:"-"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type SCIMGroup struct {
	ID          string    `json:"id"`
	ClientID    string    `json:"client_id"`
	DirectoryID string    `json:"directory_id"`
	ExternalID  string    `json:"external_id"`
	DisplayName string    `json:"display_name"`
	Members     []string  `json:"members"`
	RawResource []byte    `json:"-"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
