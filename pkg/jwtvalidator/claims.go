package jwtvalidator

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

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

func PermissionFor(resource, action string) string {
	resource = strings.ToLower(strings.TrimSpace(resource))
	action = strings.ToLower(strings.TrimSpace(action))
	if resource == "" || action == "" {
		return ""
	}
	return resource + ":" + action
}

func (c *Claims) IsAuthorized(resource, action string) bool {
	return c.HasOrganizationPermission(PermissionFor(resource, action))
}

// ScopeList returns scopes from both the OAuth scope string and structured scopes claim.
func (c *Claims) ScopeList() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(c.Scopes)+1)
	for _, scope := range c.Scopes {
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	for _, scope := range splitScopeString(c.Scope) {
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return out
}

// HasScope reports whether the token grants the requested scope.
func (c *Claims) HasScope(required string) bool {
	for _, granted := range c.ScopeList() {
		if scopeMatches(granted, required) {
			return true
		}
	}
	return false
}

// HasOrganizationPermission reports whether the organization claims grant a permission.
func (c *Claims) HasOrganizationPermission(required string) bool {
	if c == nil {
		return false
	}
	if c.OrganizationRole == "owner" {
		return true
	}
	required = strings.ToLower(strings.TrimSpace(required))
	for _, permission := range c.OrganizationPermissions {
		if strings.ToLower(strings.TrimSpace(permission)) == required {
			return true
		}
	}
	return false
}
