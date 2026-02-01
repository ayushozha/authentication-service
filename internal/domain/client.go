package domain

import "time"

type Client struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Slug           string            `json:"slug"`
	JWTSecret      string            `json:"-"`
	AllowedOrigins []string          `json:"allowed_origins"`
	WebhookURL     string            `json:"webhook_url,omitempty"`
	Settings       map[string]interface{} `json:"settings"`
	Status         string            `json:"status"`
	APIKeyHash     string            `json:"-"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}
