package domain

import "time"

const (
	AdminActorTypeUser       = "admin_user"
	AdminActorTypeBreakGlass = "break_glass"

	AdminRoleOwner           = "owner"
	AdminRoleSecurityAdmin   = "security_admin"
	AdminRoleSupportAdmin    = "support_admin"
	AdminRoleBillingAdmin    = "billing_admin"
	AdminRoleReadOnlyAuditor = "read_only_auditor"

	AdminScopeAll          = "all"
	AdminScopeClient       = "client"
	AdminScopeOrganization = "organization"
)

type AdminUser struct {
	ID                  string     `json:"id"`
	Email               string     `json:"email"`
	DisplayName         string     `json:"display_name"`
	PasswordHash        string     `json:"-"`
	Roles               []string   `json:"roles"`
	ScopeType           string     `json:"scope_type"`
	ScopeClientID       string     `json:"scope_client_id,omitempty"`
	ScopeOrganizationID string     `json:"scope_organization_id,omitempty"`
	MFARequired         bool       `json:"mfa_required"`
	TOTPSecret          string     `json:"-"`
	TOTPEnabled         bool       `json:"totp_enabled"`
	SSOProvider         string     `json:"sso_provider,omitempty"`
	SSOSubject          string     `json:"sso_subject,omitempty"`
	Status              string     `json:"status"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type AdminActor struct {
	Type                string   `json:"type"`
	ID                  string   `json:"id,omitempty"`
	Email               string   `json:"email,omitempty"`
	Roles               []string `json:"roles"`
	ScopeType           string   `json:"scope_type"`
	ScopeClientID       string   `json:"scope_client_id,omitempty"`
	ScopeOrganizationID string   `json:"scope_organization_id,omitempty"`
}

func (a AdminActor) IsBreakGlass() bool {
	return a.Type == AdminActorTypeBreakGlass
}

func (a AdminActor) IsAllScoped() bool {
	return a.ScopeType == "" || a.ScopeType == AdminScopeAll
}

func (a AdminActor) MatchesClient(clientID string) bool {
	if clientID == "" || a.IsAllScoped() {
		return true
	}
	return a.ScopeType == AdminScopeClient && a.ScopeClientID == clientID
}
