package jwtvalidator

import "github.com/golang-jwt/jwt/v5"

// Claims represents the JWT claims issued by the authentication service.
type Claims struct {
	jwt.RegisteredClaims
	Email         string `json:"email"`
	Role          string `json:"role"`
	EmailVerified bool   `json:"email_verified"`
	ClientID      string `json:"client_id"`
}

// UserID returns the user's ID from the Subject claim.
func (c *Claims) UserID() string {
	return c.Subject
}
