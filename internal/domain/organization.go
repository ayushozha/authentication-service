package domain

import (
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	OrganizationRoleOwner  = "owner"
	OrganizationRoleAdmin  = "admin"
	OrganizationRoleMember = "member"
	OrganizationRoleViewer = "viewer"
)

const (
	PermissionOrganizationRead    = "org:read"
	PermissionOrganizationWrite   = "org:write"
	PermissionMembersRead         = "members:read"
	PermissionMembersWrite        = "members:write"
	PermissionMembersInvite       = "members:invite"
	PermissionInvitationsRead     = "invitations:read"
	PermissionInvitationsWrite    = "invitations:write"
	PermissionAuthorizationRead   = "authorization:read"
	PermissionAuthorizationManage = "authorization:manage"
	PermissionEnterpriseRead      = "enterprise:read"
	PermissionEnterpriseWrite     = "enterprise:write"
	PermissionEnterpriseAudit     = "enterprise:audit:read"
)

type Organization struct {
	ID              string                 `json:"id"`
	ClientID        string                 `json:"client_id"`
	Name            string                 `json:"name"`
	Slug            string                 `json:"slug"`
	Metadata        map[string]interface{} `json:"metadata"`
	CreatedByUserID *string                `json:"created_by_user_id,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

type OrganizationMembership struct {
	ID             string    `json:"id"`
	ClientID       string    `json:"client_id"`
	OrganizationID string    `json:"organization_id"`
	UserID         string    `json:"user_id"`
	Role           string    `json:"role"`
	Permissions    []string  `json:"permissions"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type OrganizationMembershipDetails struct {
	Organization *Organization           `json:"organization"`
	Membership   *OrganizationMembership `json:"membership"`
}

type OrganizationInvitation struct {
	ID              string     `json:"id"`
	ClientID        string     `json:"client_id"`
	OrganizationID  string     `json:"organization_id"`
	Email           string     `json:"email"`
	Role            string     `json:"role"`
	Permissions     []string   `json:"permissions"`
	Status          string     `json:"status"`
	InvitedByUserID *string    `json:"invited_by_user_id,omitempty"`
	ExpiresAt       time.Time  `json:"expires_at"`
	AcceptedAt      *time.Time `json:"accepted_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	TokenHash       string     `json:"-"`
}

type OrganizationInvitationWithToken struct {
	Invitation *OrganizationInvitation `json:"invitation"`
	Token      string                  `json:"token"`
}

func NormalizeOrganizationRole(role string) (string, error) {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		role = OrganizationRoleMember
	}
	switch role {
	case OrganizationRoleOwner, OrganizationRoleAdmin, OrganizationRoleMember, OrganizationRoleViewer:
		return role, nil
	default:
		if isValidOrganizationKey(role, false) {
			return role, nil
		}
		return "", ErrInvalidRole
	}
}

func OrganizationRolePermissions(role string) []string {
	switch role {
	case OrganizationRoleOwner:
		return []string{
			PermissionOrganizationRead,
			PermissionOrganizationWrite,
			PermissionMembersRead,
			PermissionMembersWrite,
			PermissionMembersInvite,
			PermissionInvitationsRead,
			PermissionInvitationsWrite,
			PermissionAuthorizationRead,
			PermissionAuthorizationManage,
			PermissionEnterpriseRead,
			PermissionEnterpriseWrite,
			PermissionEnterpriseAudit,
		}
	case OrganizationRoleAdmin:
		return []string{
			PermissionOrganizationRead,
			PermissionOrganizationWrite,
			PermissionMembersRead,
			PermissionMembersWrite,
			PermissionMembersInvite,
			PermissionInvitationsRead,
			PermissionInvitationsWrite,
			PermissionAuthorizationRead,
			PermissionAuthorizationManage,
			PermissionEnterpriseRead,
			PermissionEnterpriseWrite,
			PermissionEnterpriseAudit,
		}
	case OrganizationRoleMember:
		return []string{
			PermissionOrganizationRead,
			PermissionMembersRead,
			PermissionAuthorizationRead,
		}
	case OrganizationRoleViewer:
		return []string{
			PermissionOrganizationRead,
		}
	default:
		return nil
	}
}

func NormalizeOrganizationPermissions(permissions []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		permission = strings.ToLower(strings.TrimSpace(permission))
		if permission == "" {
			continue
		}
		if !IsBuiltInOrganizationPermission(permission) && !isValidOrganizationKey(permission, true) {
			return nil, ErrInvalidPermission
		}
		if _, ok := seen[permission]; ok {
			continue
		}
		seen[permission] = struct{}{}
		out = append(out, permission)
	}
	sort.Strings(out)
	return out, nil
}

func EffectiveOrganizationPermissions(role string, permissions []string) []string {
	rolePermissions := OrganizationRolePermissions(role)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(rolePermissions)+len(permissions))
	for _, permission := range rolePermissions {
		if permission == "" {
			continue
		}
		seen[permission] = struct{}{}
		out = append(out, permission)
	}
	for _, permission := range permissions {
		if permission == "" {
			continue
		}
		if _, ok := seen[permission]; ok {
			continue
		}
		seen[permission] = struct{}{}
		out = append(out, permission)
	}
	sort.Strings(out)
	return out
}

func IsBuiltInOrganizationPermission(permission string) bool {
	switch strings.ToLower(strings.TrimSpace(permission)) {
	case PermissionOrganizationRead,
		PermissionOrganizationWrite,
		PermissionMembersRead,
		PermissionMembersWrite,
		PermissionMembersInvite,
		PermissionInvitationsRead,
		PermissionInvitationsWrite,
		PermissionAuthorizationRead,
		PermissionAuthorizationManage,
		PermissionEnterpriseRead,
		PermissionEnterpriseWrite,
		PermissionEnterpriseAudit:
		return true
	default:
		return false
	}
}

func HasOrganizationPermission(membership *OrganizationMembership, permission string) bool {
	if membership == nil || membership.Status != "active" {
		return false
	}
	if membership.Role == OrganizationRoleOwner {
		return true
	}
	permission = strings.ToLower(strings.TrimSpace(permission))
	for _, candidate := range EffectiveOrganizationPermissions(membership.Role, membership.Permissions) {
		if candidate == permission {
			return true
		}
	}
	return false
}

func isValidOrganizationKey(value string, requireNamespace bool) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	if requireNamespace && !strings.Contains(value, ":") {
		return false
	}
	if value[0] == ':' || value[len(value)-1] == ':' {
		return false
	}
	lastSeparator := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			lastSeparator = false
		case r >= '0' && r <= '9':
			lastSeparator = false
		case r == ':' || r == '_' || r == '-' || r == '.':
			if lastSeparator {
				return false
			}
			lastSeparator = true
		default:
			if unicode.IsSpace(r) {
				return false
			}
			return false
		}
	}
	return !lastSeparator
}
