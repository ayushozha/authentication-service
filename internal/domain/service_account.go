package domain

import (
	"sort"
	"strings"
	"time"
)

const TokenUseClientCredentials = "client_credentials"

type ServiceAccount struct {
	ID          string     `json:"id"`
	ClientID    string     `json:"client_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Scopes      []string   `json:"scopes"`
	Status      string     `json:"status"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type ServiceAccountKey struct {
	ID               string     `json:"id"`
	ClientID         string     `json:"client_id"`
	ServiceAccountID string     `json:"service_account_id"`
	Name             string     `json:"name"`
	KeyPrefix        string     `json:"key_prefix"`
	SecretHash       string     `json:"-"`
	Scopes           []string   `json:"scopes"`
	Status           string     `json:"status"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type ServiceAccountKeyWithSecret struct {
	ServiceAccount *ServiceAccount    `json:"service_account,omitempty"`
	Key            *ServiceAccountKey `json:"key"`
	ClientID       string             `json:"client_id"`
	ClientSecret   string             `json:"client_secret"`
}

func NormalizeScopes(scopes []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope == "" {
			continue
		}
		if !validScope(scope) {
			return nil, ErrInvalidScope
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	sort.Strings(out)
	return out, nil
}

func ScopesContainAll(allowed, requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	allowedSet := map[string]struct{}{}
	for _, scope := range allowed {
		allowedSet[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := allowedSet[scope]; !ok {
			return false
		}
	}
	return true
}

func IntersectScopes(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, scope := range a {
		set[scope] = struct{}{}
	}
	out := make([]string, 0, len(b))
	for _, scope := range b {
		if _, ok := set[scope]; ok {
			out = append(out, scope)
		}
	}
	sort.Strings(out)
	return out
}

func ScopeString(scopes []string) string {
	return strings.Join(scopes, " ")
}

func validScope(scope string) bool {
	if len(scope) > 128 {
		return false
	}
	for _, r := range scope {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case ':', '.', '-', '_', '*':
			continue
		default:
			return false
		}
	}
	return true
}
