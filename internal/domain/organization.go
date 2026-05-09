package domain

import (
	"sort"
	"strings"
	"time"
)

const (
	OrganizationRoleOwner  = "owner"
	OrganizationRoleAdmin  = "admin"
	OrganizationRoleMember = "member"
	OrganizationRoleViewer = "viewer"
)

const (
	PermissionOrganizationRead  = "org:read"
	PermissionOrganizationWrite = "org:write"
	PermissionMembersRead       = "members:read"
	PermissionMembersWrite      = "members:write"
	PermissionInvitationsRead   = "invitations:read"
	PermissionInvitationsWrite  = "invitations:write"
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
			PermissionInvitationsRead,
			PermissionInvitationsWrite,
		}
	case OrganizationRoleAdmin:
		return []string{
			PermissionOrganizationRead,
			PermissionOrganizationWrite,
			PermissionMembersRead,
			PermissionMembersWrite,
			PermissionInvitationsRead,
			PermissionInvitationsWrite,
		}
	case OrganizationRoleMember:
		return []string{
			PermissionOrganizationRead,
			PermissionMembersRead,
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
	allowed := map[string]struct{}{
		PermissionOrganizationRead:  {},
		PermissionOrganizationWrite: {},
		PermissionMembersRead:       {},
		PermissionMembersWrite:      {},
		PermissionInvitationsRead:   {},
		PermissionInvitationsWrite:  {},
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		permission = strings.ToLower(strings.TrimSpace(permission))
		if permission == "" {
			continue
		}
		if _, ok := allowed[permission]; !ok {
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
