package jwtvalidator

import "github.com/golang-jwt/jwt/v5"

// Claims represents the JWT claims issued by the authentication service.
type Claims struct {
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

// UserID returns the user's ID from the Subject claim.
func (c *Claims) UserID() string {
	return c.Subject
}
