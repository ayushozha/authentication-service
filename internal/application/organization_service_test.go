package application

import (
	"testing"

	"github.com/Ayush10/authentication-service/internal/domain"
)

func TestCanAssignOrganizationPermissionsUsesEffectiveRoleDefaults(t *testing.T) {
	limitedManager := &domain.OrganizationMembership{
		Role:        "member-manager",
		Permissions: []string{domain.PermissionMembersWrite},
		Status:      "active",
	}

	if !canAssignOrganizationRole(limitedManager, domain.OrganizationRoleAdmin) {
		t.Fatalf("limited member manager should pass role hierarchy checks before permission checks")
	}
	if canAssignOrganizationPermissions(limitedManager, domain.EffectiveOrganizationPermissions(domain.OrganizationRoleAdmin, nil)) {
		t.Fatalf("limited member manager must not be able to grant admin role defaults")
	}

	owner := &domain.OrganizationMembership{Role: domain.OrganizationRoleOwner, Status: "active"}
	if !canAssignOrganizationPermissions(owner, domain.EffectiveOrganizationPermissions(domain.OrganizationRoleAdmin, nil)) {
		t.Fatalf("owner should be able to grant built-in admin permissions")
	}
}

func TestAuthorizationPolicyCustomRoleTemplateExplainsDecision(t *testing.T) {
	policy, err := domain.NormalizeAuthorizationPolicy(&domain.OrganizationAuthorizationPolicy{
		ClientID:       "client-a",
		OrganizationID: "org-a",
		Version:        3,
		Resources: []domain.AuthorizationResource{
			{
				Key: "billing",
				Actions: []domain.AuthorizationAction{
					{Key: "manage", Description: "Manage billing"},
				},
			},
			{
				Key: "documents",
				Actions: []domain.AuthorizationAction{
					{Key: "read", Description: "Read documents"},
				},
			},
		},
		Roles: []domain.AuthorizationRoleTemplate{
			{
				Key:         "billing-admin",
				Permissions: []string{"billing:manage", "documents:read", domain.PermissionMembersInvite},
			},
		},
	})
	if err != nil {
		t.Fatalf("normalize policy: %v", err)
	}

	membership := &domain.OrganizationMembership{
		ClientID:       "client-a",
		OrganizationID: "org-a",
		UserID:         "user-a",
		Role:           "billing-admin",
		Status:         "active",
	}
	allowed := domain.ExplainAuthorizationDecision("client-a", "org-a", "user-a", membership, policy, "billing", "manage")
	if !allowed.Allowed || allowed.PolicyVersion != 3 {
		t.Fatalf("expected billing-admin role template to allow billing:manage: %+v", allowed)
	}
	if !domain.OrganizationPermissionAllowed(membership, policy, "documents:read") {
		t.Fatalf("expected role template to grant documents:read")
	}

	denied := domain.ExplainAuthorizationDecision("client-a", "org-a", "user-a", membership, policy, "billing", "delete")
	if denied.Allowed || len(denied.Missing) != 1 || denied.Missing[0] != "billing:delete" {
		t.Fatalf("expected billing:delete denial explanation: %+v", denied)
	}
}
