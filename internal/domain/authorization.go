package domain

import (
	"sort"
	"strings"
	"time"
)

const (
	GroupMappingSourceSSO  = "sso"
	GroupMappingSourceSCIM = "scim"
)

type AuthorizationAction struct {
	Key         string `json:"key"`
	Description string `json:"description,omitempty"`
	Default     bool   `json:"default"`
}

type AuthorizationResource struct {
	Key         string                `json:"key"`
	Description string                `json:"description,omitempty"`
	Actions     []AuthorizationAction `json:"actions"`
}

type AuthorizationPermission struct {
	Key         string `json:"key"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
	Default     bool   `json:"default"`
}

type AuthorizationRoleTemplate struct {
	Key         string   `json:"key"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
	Default     bool     `json:"default"`
}

type OrganizationAuthorizationPolicy struct {
	ClientID       string                      `json:"client_id,omitempty"`
	OrganizationID string                      `json:"organization_id,omitempty"`
	Version        int                         `json:"version"`
	Description    string                      `json:"description,omitempty"`
	Resources      []AuthorizationResource     `json:"resources"`
	Permissions    []AuthorizationPermission   `json:"permissions"`
	Roles          []AuthorizationRoleTemplate `json:"roles"`
	CreatedAt      time.Time                   `json:"created_at,omitempty"`
	UpdatedAt      time.Time                   `json:"updated_at,omitempty"`
}

type OrganizationGroupMapping struct {
	ID             string    `json:"id"`
	ClientID       string    `json:"client_id"`
	OrganizationID string    `json:"organization_id"`
	Source         string    `json:"source"`
	SourceID       string    `json:"source_id,omitempty"`
	Group          string    `json:"group"`
	Role           string    `json:"role"`
	Permissions    []string  `json:"permissions"`
	Description    string    `json:"description,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type AuthorizationDecision struct {
	Allowed        bool     `json:"allowed"`
	ClientID       string   `json:"client_id,omitempty"`
	OrganizationID string   `json:"organization_id,omitempty"`
	UserID         string   `json:"user_id,omitempty"`
	Resource       string   `json:"resource"`
	Action         string   `json:"action"`
	Permission     string   `json:"permission"`
	Role           string   `json:"role,omitempty"`
	PolicyVersion  int      `json:"policy_version,omitempty"`
	Reasons        []string `json:"reasons"`
	Missing        []string `json:"missing,omitempty"`
}

func PermissionKey(resource, action string) string {
	resource = strings.ToLower(strings.TrimSpace(resource))
	action = strings.ToLower(strings.TrimSpace(action))
	if resource == "" || action == "" {
		return ""
	}
	return resource + ":" + action
}

func DefaultAuthorizationPolicy(clientID, organizationID string, now time.Time) *OrganizationAuthorizationPolicy {
	policy := &OrganizationAuthorizationPolicy{
		ClientID:       clientID,
		OrganizationID: organizationID,
		Version:        1,
		Description:    "Default organization authorization policy",
		Resources: []AuthorizationResource{
			{
				Key:         "org",
				Description: "Organization profile and settings",
				Actions: []AuthorizationAction{
					{Key: "read", Description: "Read organization settings", Default: true},
					{Key: "write", Description: "Update organization settings", Default: true},
				},
			},
			{
				Key:         "members",
				Description: "Organization members",
				Actions: []AuthorizationAction{
					{Key: "read", Description: "List organization members", Default: true},
					{Key: "write", Description: "Update or remove organization members", Default: true},
					{Key: "invite", Description: "Invite organization members", Default: true},
				},
			},
			{
				Key:         "invitations",
				Description: "Organization invitations",
				Actions: []AuthorizationAction{
					{Key: "read", Description: "List organization invitations", Default: true},
					{Key: "write", Description: "Create or revoke organization invitations", Default: true},
				},
			},
			{
				Key:         "authorization",
				Description: "Organization authorization policy",
				Actions: []AuthorizationAction{
					{Key: "read", Description: "Read authorization policy", Default: true},
					{Key: "manage", Description: "Manage authorization policy and mappings", Default: true},
				},
			},
		},
		Roles: []AuthorizationRoleTemplate{
			{
				Key:         OrganizationRoleOwner,
				Name:        "Owner",
				Description: "Full organization access",
				Permissions: []string{
					PermissionOrganizationRead,
					PermissionOrganizationWrite,
					PermissionMembersRead,
					PermissionMembersWrite,
					PermissionMembersInvite,
					PermissionInvitationsRead,
					PermissionInvitationsWrite,
					PermissionAuthorizationRead,
					PermissionAuthorizationManage,
				},
				Default: true,
			},
			{
				Key:         OrganizationRoleAdmin,
				Name:        "Admin",
				Description: "Manage organization settings and members",
				Permissions: []string{
					PermissionOrganizationRead,
					PermissionOrganizationWrite,
					PermissionMembersRead,
					PermissionMembersWrite,
					PermissionMembersInvite,
					PermissionInvitationsRead,
					PermissionInvitationsWrite,
					PermissionAuthorizationRead,
					PermissionAuthorizationManage,
				},
				Default: true,
			},
			{
				Key:         OrganizationRoleMember,
				Name:        "Member",
				Description: "Read organization and member information",
				Permissions: []string{
					PermissionOrganizationRead,
					PermissionMembersRead,
					PermissionAuthorizationRead,
				},
				Default: true,
			},
			{
				Key:         OrganizationRoleViewer,
				Name:        "Viewer",
				Description: "Read organization profile",
				Permissions: []string{
					PermissionOrganizationRead,
				},
				Default: true,
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	normalized, err := NormalizeAuthorizationPolicy(policy)
	if err != nil {
		return policy
	}
	return normalized
}

func NormalizeAuthorizationPolicy(policy *OrganizationAuthorizationPolicy) (*OrganizationAuthorizationPolicy, error) {
	if policy == nil {
		return nil, ErrInvalidAuthorizationPolicy
	}
	cp := *policy
	if cp.Version <= 0 {
		cp.Version = 1
	}
	cp.Description = strings.TrimSpace(cp.Description)

	resources := make([]AuthorizationResource, 0, len(cp.Resources))
	permissionsByKey := map[string]AuthorizationPermission{}
	for _, resource := range cp.Resources {
		resource.Key = normalizeAuthorizationKey(resource.Key)
		resource.Description = strings.TrimSpace(resource.Description)
		if !IsValidOrganizationKey(resource.Key, false) {
			return nil, ErrInvalidAuthorizationPolicy
		}
		actions := make([]AuthorizationAction, 0, len(resource.Actions))
		seenActions := map[string]struct{}{}
		for _, action := range resource.Actions {
			action.Key = normalizeAuthorizationKey(action.Key)
			action.Description = strings.TrimSpace(action.Description)
			if !IsValidOrganizationKey(action.Key, false) {
				return nil, ErrInvalidAuthorizationPolicy
			}
			if _, ok := seenActions[action.Key]; ok {
				continue
			}
			seenActions[action.Key] = struct{}{}
			actions = append(actions, action)
			key := PermissionKey(resource.Key, action.Key)
			permissionsByKey[key] = AuthorizationPermission{
				Key:         key,
				Resource:    resource.Key,
				Action:      action.Key,
				Description: strings.TrimSpace(firstAuthorizationText(action.Description, resource.Description)),
				Default:     action.Default,
			}
		}
		sort.Slice(actions, func(i, j int) bool { return actions[i].Key < actions[j].Key })
		resource.Actions = actions
		resources = append(resources, resource)
	}
	for _, permission := range cp.Permissions {
		permission.Resource = normalizeAuthorizationKey(permission.Resource)
		permission.Action = normalizeAuthorizationKey(permission.Action)
		if permission.Key != "" {
			permission.Key = strings.ToLower(strings.TrimSpace(permission.Key))
			parts := strings.Split(permission.Key, ":")
			if len(parts) == 2 && permission.Resource == "" && permission.Action == "" {
				permission.Resource = parts[0]
				permission.Action = parts[1]
			}
		}
		permission.Key = PermissionKey(permission.Resource, permission.Action)
		permission.Description = strings.TrimSpace(permission.Description)
		if !IsValidOrganizationKey(permission.Key, true) {
			return nil, ErrInvalidAuthorizationPolicy
		}
		if existing, ok := permissionsByKey[permission.Key]; ok {
			if permission.Description == "" {
				permission.Description = existing.Description
			}
			permission.Default = permission.Default || existing.Default
		}
		permissionsByKey[permission.Key] = permission
	}

	permissions := make([]AuthorizationPermission, 0, len(permissionsByKey))
	for _, permission := range permissionsByKey {
		permissions = append(permissions, permission)
	}
	sort.Slice(permissions, func(i, j int) bool { return permissions[i].Key < permissions[j].Key })
	sort.Slice(resources, func(i, j int) bool { return resources[i].Key < resources[j].Key })

	knownPermissions := map[string]struct{}{}
	for _, permission := range permissions {
		knownPermissions[permission.Key] = struct{}{}
	}
	roles := make([]AuthorizationRoleTemplate, 0, len(cp.Roles))
	seenRoles := map[string]struct{}{}
	for _, role := range cp.Roles {
		key, err := NormalizeOrganizationRole(role.Key)
		if err != nil {
			return nil, err
		}
		if _, ok := seenRoles[key]; ok {
			continue
		}
		seenRoles[key] = struct{}{}
		role.Key = key
		role.Name = strings.TrimSpace(role.Name)
		role.Description = strings.TrimSpace(role.Description)
		perms, err := NormalizeOrganizationPermissions(role.Permissions)
		if err != nil {
			return nil, err
		}
		for _, permission := range perms {
			if _, ok := knownPermissions[permission]; !ok && !IsBuiltInOrganizationPermission(permission) {
				return nil, ErrInvalidAuthorizationPolicy
			}
		}
		role.Permissions = perms
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Key < roles[j].Key })

	cp.Resources = resources
	cp.Permissions = permissions
	cp.Roles = roles
	return &cp, nil
}

func ResolveOrganizationPermissions(membership *OrganizationMembership, policy *OrganizationAuthorizationPolicy) []string {
	if membership == nil || membership.Status != "active" {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0)
	add := func(permissions []string) {
		for _, permission := range permissions {
			permission = strings.ToLower(strings.TrimSpace(permission))
			if permission == "" {
				continue
			}
			if _, ok := seen[permission]; ok {
				continue
			}
			seen[permission] = struct{}{}
			out = append(out, permission)
		}
	}
	add(OrganizationRolePermissions(membership.Role))
	add(membership.Permissions)
	if policy != nil {
		if membership.Role == OrganizationRoleOwner {
			for _, permission := range policy.Permissions {
				add([]string{permission.Key})
			}
		}
		for _, role := range policy.Roles {
			if role.Key == membership.Role {
				add(role.Permissions)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func OrganizationPermissionAllowed(membership *OrganizationMembership, policy *OrganizationAuthorizationPolicy, permission string) bool {
	if membership == nil || membership.Status != "active" {
		return false
	}
	if membership.Role == OrganizationRoleOwner {
		return true
	}
	permission = strings.ToLower(strings.TrimSpace(permission))
	for _, candidate := range ResolveOrganizationPermissions(membership, policy) {
		if candidate == permission {
			return true
		}
	}
	return false
}

func AuthorizationRolePermissions(policy *OrganizationAuthorizationPolicy, role string) []string {
	role, err := NormalizeOrganizationRole(role)
	if err != nil || policy == nil {
		return nil
	}
	for _, template := range policy.Roles {
		if template.Key == role {
			return append([]string(nil), template.Permissions...)
		}
	}
	return nil
}

func ExplainAuthorizationDecision(clientID, organizationID, userID string, membership *OrganizationMembership, policy *OrganizationAuthorizationPolicy, resource, action string) AuthorizationDecision {
	resource = normalizeAuthorizationKey(resource)
	action = normalizeAuthorizationKey(action)
	permission := PermissionKey(resource, action)
	decision := AuthorizationDecision{
		ClientID:       clientID,
		OrganizationID: organizationID,
		UserID:         userID,
		Resource:       resource,
		Action:         action,
		Permission:     permission,
		Reasons:        []string{},
	}
	if policy != nil {
		decision.PolicyVersion = policy.Version
	}
	if membership == nil || membership.Status != "active" {
		decision.Reasons = append(decision.Reasons, "no active organization membership")
		decision.Missing = []string{permission}
		return decision
	}
	decision.Role = membership.Role
	if permission == "" || !IsValidOrganizationKey(permission, true) {
		decision.Reasons = append(decision.Reasons, "resource and action must form a valid permission")
		decision.Missing = []string{permission}
		return decision
	}
	if membership.Role == OrganizationRoleOwner {
		decision.Allowed = true
		decision.Reasons = append(decision.Reasons, "owner role grants all organization permissions")
		return decision
	}
	if containsPermission(OrganizationRolePermissions(membership.Role), permission) {
		decision.Allowed = true
		decision.Reasons = append(decision.Reasons, "built-in role grants "+permission)
		return decision
	}
	if containsPermission(membership.Permissions, permission) {
		decision.Allowed = true
		decision.Reasons = append(decision.Reasons, "membership grants "+permission)
		return decision
	}
	if policy != nil {
		for _, role := range policy.Roles {
			if role.Key == membership.Role && containsPermission(role.Permissions, permission) {
				decision.Allowed = true
				decision.Reasons = append(decision.Reasons, "role template "+role.Key+" grants "+permission)
				return decision
			}
		}
	}
	decision.Reasons = append(decision.Reasons, "permission "+permission+" is not granted by membership, role, or policy")
	decision.Missing = []string{permission}
	return decision
}

func NormalizeGroupMappingSource(source string) (string, error) {
	source = strings.ToLower(strings.TrimSpace(source))
	switch source {
	case GroupMappingSourceSSO, GroupMappingSourceSCIM:
		return source, nil
	default:
		return "", ErrInvalidGroupMapping
	}
}

func NormalizeGroupName(group string) string {
	return strings.ToLower(strings.TrimSpace(group))
}

func IsValidOrganizationKey(value string, requireNamespace bool) bool {
	return isValidOrganizationKey(value, requireNamespace)
}

func normalizeAuthorizationKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func containsPermission(values []string, permission string) bool {
	permission = strings.ToLower(strings.TrimSpace(permission))
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == permission {
			return true
		}
	}
	return false
}

func firstAuthorizationText(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
