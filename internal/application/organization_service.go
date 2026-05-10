package application

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
)

const (
	defaultInvitationTTL = 7 * 24 * time.Hour
	maxInvitationTTL     = 30 * 24 * time.Hour
)

type OrganizationService struct {
	orgs  OrganizationRepository
	users UserRepository
	audit AuditRepository
}

func NewOrganizationService(orgs OrganizationRepository, users UserRepository, audit AuditRepository) *OrganizationService {
	return &OrganizationService{orgs: orgs, users: users, audit: audit}
}

type CreateOrganizationRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type UpdateOrganizationRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type InviteOrganizationMemberRequest struct {
	Email          string   `json:"email"`
	Role           string   `json:"role"`
	Permissions    []string `json:"permissions"`
	ExpiresInHours int      `json:"expires_in_hours"`
}

type UpdateOrganizationMemberRequest struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

type UpdateAuthorizationPolicyRequest struct {
	ExpectedVersion int                                `json:"expected_version"`
	Description     string                             `json:"description"`
	Resources       []domain.AuthorizationResource     `json:"resources"`
	Permissions     []domain.AuthorizationPermission   `json:"permissions"`
	Roles           []domain.AuthorizationRoleTemplate `json:"roles"`
}

type UpsertGroupMappingRequest struct {
	Source      string   `json:"source"`
	SourceID    string   `json:"source_id"`
	Group       string   `json:"group"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	Description string   `json:"description"`
}

type AuthorizationSimulationRequest struct {
	UserID   string `json:"user_id"`
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

func (s *OrganizationService) CreateOrganization(ctx context.Context, clientID, actorUserID string, req CreateOrganizationRequest, ip, ua string) (*domain.OrganizationMembershipDetails, error) {
	name, slug, err := normalizeOrganizationNameAndSlug(req.Name, req.Slug)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	createdBy := actorUserID
	org := &domain.Organization{
		ID:              uuid.NewString(),
		ClientID:        clientID,
		Name:            name,
		Slug:            slug,
		Metadata:        map[string]interface{}{},
		CreatedByUserID: &createdBy,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	membership := &domain.OrganizationMembership{
		ID:             uuid.NewString(),
		ClientID:       clientID,
		OrganizationID: org.ID,
		UserID:         actorUserID,
		Role:           domain.OrganizationRoleOwner,
		Permissions:    domain.OrganizationRolePermissions(domain.OrganizationRoleOwner),
		Status:         "active",
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.orgs.CreateOrganization(ctx, org, membership); err != nil {
		if isDuplicateError(err) {
			return nil, domain.ErrDuplicateOrganization
		}
		return nil, err
	}
	if _, err := s.ensureAuthorizationPolicy(ctx, clientID, org.ID); err != nil {
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "organization_created", ip, ua, map[string]interface{}{
		"organization_id":   org.ID,
		"organization_slug": org.Slug,
	})
	return &domain.OrganizationMembershipDetails{Organization: org, Membership: membership}, nil
}

func (s *OrganizationService) ListOrganizations(ctx context.Context, clientID, userID string) ([]domain.OrganizationMembershipDetails, error) {
	return s.orgs.ListOrganizationsForUser(ctx, clientID, userID)
}

func (s *OrganizationService) GetOrganization(ctx context.Context, clientID, organizationID, userID string) (*domain.OrganizationMembershipDetails, error) {
	membership, err := s.requirePermission(ctx, clientID, organizationID, userID, domain.PermissionOrganizationRead)
	if err != nil {
		return nil, err
	}
	org, err := s.orgs.GetOrganization(ctx, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	return &domain.OrganizationMembershipDetails{Organization: org, Membership: membership}, nil
}

func (s *OrganizationService) UpdateOrganization(ctx context.Context, clientID, organizationID, actorUserID string, req UpdateOrganizationRequest, ip, ua string) (*domain.Organization, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionOrganizationWrite); err != nil {
		return nil, err
	}
	org, err := s.orgs.GetOrganization(ctx, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Name) != "" || strings.TrimSpace(req.Slug) != "" {
		name := org.Name
		if strings.TrimSpace(req.Name) != "" {
			name = strings.TrimSpace(req.Name)
		}
		slug := org.Slug
		if strings.TrimSpace(req.Slug) != "" {
			slug = strings.TrimSpace(req.Slug)
		}
		normalizedName, normalizedSlug, err := normalizeOrganizationNameAndSlug(name, slug)
		if err != nil {
			return nil, err
		}
		org.Name = normalizedName
		org.Slug = normalizedSlug
	}
	org.UpdatedAt = time.Now().UTC()
	if err := s.orgs.UpdateOrganization(ctx, org); err != nil {
		if isDuplicateError(err) {
			return nil, domain.ErrDuplicateOrganization
		}
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "organization_updated", ip, ua, map[string]interface{}{"organization_id": organizationID})
	return org, nil
}

func (s *OrganizationService) UpdateSecurityPolicy(ctx context.Context, clientID, organizationID, actorUserID string, policy domain.AdaptiveSecurityPolicy, ip, ua string) (domain.AdaptiveSecurityPolicy, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionOrganizationWrite); err != nil {
		return domain.AdaptiveSecurityPolicy{}, err
	}
	org, err := s.orgs.GetOrganization(ctx, clientID, organizationID)
	if err != nil {
		return domain.AdaptiveSecurityPolicy{}, err
	}
	if org.Metadata == nil {
		org.Metadata = map[string]interface{}{}
	}
	normalized := NormalizeAdaptiveSecurityPolicy(policy)
	org.Metadata[adaptiveSecurityPolicyKey] = normalized
	org.UpdatedAt = time.Now().UTC()
	if err := s.orgs.UpdateOrganization(ctx, org); err != nil {
		return domain.AdaptiveSecurityPolicy{}, err
	}
	s.log(ctx, clientID, &actorUserID, "organization_security_policy_updated", ip, ua, map[string]interface{}{"organization_id": organizationID})
	return normalized, nil
}

func (s *OrganizationService) ListMembers(ctx context.Context, clientID, organizationID, actorUserID string) ([]*domain.OrganizationMembership, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionMembersRead); err != nil {
		return nil, err
	}
	return s.orgs.ListMemberships(ctx, clientID, organizationID)
}

func (s *OrganizationService) InviteMember(ctx context.Context, clientID, organizationID, actorUserID string, req InviteOrganizationMemberRequest, ip, ua string) (*domain.OrganizationInvitationWithToken, error) {
	actorMembership, err := s.requireAnyPermission(ctx, clientID, organizationID, actorUserID, domain.PermissionInvitationsWrite, domain.PermissionMembersInvite)
	if err != nil {
		return nil, err
	}
	email, err := normalizeEmail(req.Email)
	if err != nil {
		return nil, err
	}
	role, err := domain.NormalizeOrganizationRole(req.Role)
	if err != nil {
		return nil, err
	}
	if !canAssignOrganizationRole(actorMembership, role) {
		return nil, domain.ErrForbidden
	}
	permissions, err := normalizeRequestedPermissions(role, req.Permissions)
	if err != nil {
		return nil, err
	}
	policy, _ := s.ensureAuthorizationPolicy(ctx, clientID, organizationID)
	assignedPermissions := domain.ResolveOrganizationPermissions(&domain.OrganizationMembership{Role: role, Permissions: permissions, Status: "active"}, policy)
	if !canAssignOrganizationPermissions(actorMembership, assignedPermissions) {
		return nil, domain.ErrForbidden
	}
	rawToken, err := GenerateToken(32)
	if err != nil {
		return nil, err
	}
	ttl := invitationTTL(req.ExpiresInHours)
	now := time.Now().UTC()
	inviter := actorUserID
	invitation := &domain.OrganizationInvitation{
		ID:              uuid.NewString(),
		ClientID:        clientID,
		OrganizationID:  organizationID,
		Email:           email,
		Role:            role,
		Permissions:     permissions,
		Status:          "pending",
		InvitedByUserID: &inviter,
		TokenHash:       HashToken(rawToken),
		ExpiresAt:       now.Add(ttl),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := s.orgs.CreateInvitation(ctx, invitation); err != nil {
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "organization_invitation_created", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"email":           email,
		"role":            role,
	})
	return &domain.OrganizationInvitationWithToken{Invitation: invitation, Token: rawToken}, nil
}

func (s *OrganizationService) ListInvitations(ctx context.Context, clientID, organizationID, actorUserID string) ([]*domain.OrganizationInvitation, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionInvitationsRead); err != nil {
		return nil, err
	}
	return s.orgs.ListInvitations(ctx, clientID, organizationID)
}

func (s *OrganizationService) RevokeInvitation(ctx context.Context, clientID, organizationID, invitationID, actorUserID, ip, ua string) error {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionInvitationsWrite); err != nil {
		return err
	}
	if err := s.orgs.RevokeInvitation(ctx, clientID, organizationID, invitationID); err != nil {
		return err
	}
	s.log(ctx, clientID, &actorUserID, "organization_invitation_revoked", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"invitation_id":   invitationID,
	})
	return nil
}

func (s *OrganizationService) AcceptInvitation(ctx context.Context, clientID, actorUserID, token, ip, ua string) (*domain.OrganizationMembershipDetails, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, domain.ErrInvalidInvitation
	}
	user, err := s.users.GetByID(ctx, actorUserID)
	if err != nil {
		return nil, err
	}
	invitation, err := s.orgs.GetInvitationByTokenHash(ctx, HashToken(token))
	if err != nil {
		return nil, domain.ErrInvalidInvitation
	}
	if invitation.ClientID != clientID || invitation.Status != "pending" {
		return nil, domain.ErrInvalidInvitation
	}
	if time.Now().UTC().After(invitation.ExpiresAt) {
		return nil, domain.ErrInvitationExpired
	}
	if !strings.EqualFold(strings.TrimSpace(user.Email), invitation.Email) {
		return nil, domain.ErrForbidden
	}
	org, err := s.orgs.GetOrganization(ctx, clientID, invitation.OrganizationID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	membership := &domain.OrganizationMembership{
		ID:             uuid.NewString(),
		ClientID:       clientID,
		OrganizationID: invitation.OrganizationID,
		UserID:         actorUserID,
		Role:           invitation.Role,
		Permissions:    invitation.Permissions,
		Status:         "active",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.orgs.UpsertMembership(ctx, membership); err != nil {
		return nil, err
	}
	if err := s.orgs.MarkInvitationAccepted(ctx, invitation.ID, actorUserID); err != nil {
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "organization_invitation_accepted", ip, ua, map[string]interface{}{
		"organization_id": invitation.OrganizationID,
		"invitation_id":   invitation.ID,
	})
	return &domain.OrganizationMembershipDetails{Organization: org, Membership: membership}, nil
}

func (s *OrganizationService) UpdateMember(ctx context.Context, clientID, organizationID, targetUserID, actorUserID string, req UpdateOrganizationMemberRequest, ip, ua string) (*domain.OrganizationMembership, error) {
	actorMembership, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionMembersWrite)
	if err != nil {
		return nil, err
	}
	targetMembership, err := s.orgs.GetMembership(ctx, clientID, organizationID, targetUserID)
	if err != nil {
		return nil, err
	}
	role, err := domain.NormalizeOrganizationRole(req.Role)
	if err != nil {
		return nil, err
	}
	if !canAssignOrganizationRole(actorMembership, role) {
		return nil, domain.ErrForbidden
	}
	if targetMembership.Role == domain.OrganizationRoleOwner && role != domain.OrganizationRoleOwner {
		if err := s.ensureNotLastOwner(ctx, clientID, organizationID); err != nil {
			return nil, err
		}
	}
	permissions, err := normalizeRequestedPermissions(role, req.Permissions)
	if err != nil {
		return nil, err
	}
	policy, _ := s.ensureAuthorizationPolicy(ctx, clientID, organizationID)
	assignedPermissions := domain.ResolveOrganizationPermissions(&domain.OrganizationMembership{Role: role, Permissions: permissions, Status: "active"}, policy)
	if !canAssignOrganizationPermissions(actorMembership, assignedPermissions) {
		return nil, domain.ErrForbidden
	}
	targetMembership.Role = role
	targetMembership.Permissions = permissions
	targetMembership.UpdatedAt = time.Now().UTC()
	if err := s.orgs.UpdateMembership(ctx, targetMembership); err != nil {
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "organization_member_updated", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"target_user_id":  targetUserID,
		"role":            role,
	})
	return targetMembership, nil
}

func (s *OrganizationService) RemoveMember(ctx context.Context, clientID, organizationID, targetUserID, actorUserID, ip, ua string) error {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionMembersWrite); err != nil {
		return err
	}
	targetMembership, err := s.orgs.GetMembership(ctx, clientID, organizationID, targetUserID)
	if err != nil {
		return err
	}
	if targetMembership.Role == domain.OrganizationRoleOwner {
		if err := s.ensureNotLastOwner(ctx, clientID, organizationID); err != nil {
			return err
		}
	}
	if err := s.orgs.DeleteMembership(ctx, clientID, organizationID, targetUserID); err != nil {
		return err
	}
	s.log(ctx, clientID, &actorUserID, "organization_member_removed", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"target_user_id":  targetUserID,
	})
	return nil
}

func (s *OrganizationService) IssueOrganizationAccessToken(ctx context.Context, client *domain.Client, organizationID, userID string, ttl time.Duration) (string, error) {
	membership, err := s.requirePermission(ctx, client.ID, organizationID, userID, domain.PermissionOrganizationRead)
	if err != nil {
		return "", err
	}
	org, err := s.orgs.GetOrganization(ctx, client.ID, organizationID)
	if err != nil {
		return "", err
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return "", err
	}
	policy, _ := s.ensureAuthorizationPolicy(ctx, client.ID, organizationID)
	membership = cloneMembershipForAuthz(membership, policy)
	return CreateAccessToken(ctx, client, ttl, user, WithOrganizationScope(org, membership))
}

func (s *OrganizationService) GetAuthorizationPolicy(ctx context.Context, clientID, organizationID, actorUserID string) (*domain.OrganizationAuthorizationPolicy, error) {
	if _, err := s.requireAnyPermission(ctx, clientID, organizationID, actorUserID, domain.PermissionAuthorizationRead, domain.PermissionAuthorizationManage); err != nil {
		return nil, err
	}
	return s.ensureAuthorizationPolicy(ctx, clientID, organizationID)
}

func (s *OrganizationService) UpdateAuthorizationPolicy(ctx context.Context, clientID, organizationID, actorUserID string, req UpdateAuthorizationPolicyRequest, ip, ua string) (*domain.OrganizationAuthorizationPolicy, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionAuthorizationManage); err != nil {
		return nil, err
	}
	current, err := s.ensureAuthorizationPolicy(ctx, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	if req.ExpectedVersion > 0 && req.ExpectedVersion != current.Version {
		return nil, domain.ErrAuthorizationPolicyConflict
	}
	now := time.Now().UTC()
	next := &domain.OrganizationAuthorizationPolicy{
		ClientID:       clientID,
		OrganizationID: organizationID,
		Version:        current.Version + 1,
		Description:    req.Description,
		Resources:      req.Resources,
		Permissions:    req.Permissions,
		Roles:          req.Roles,
		CreatedAt:      current.CreatedAt,
		UpdatedAt:      now,
	}
	policy, err := domain.NormalizeAuthorizationPolicy(next)
	if err != nil {
		return nil, err
	}
	if err := s.orgs.UpsertAuthorizationPolicy(ctx, policy); err != nil {
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "authorization_policy_updated", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"version":         policy.Version,
	})
	return policy, nil
}

func (s *OrganizationService) ListGroupMappings(ctx context.Context, clientID, organizationID, actorUserID string) ([]*domain.OrganizationGroupMapping, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionAuthorizationRead); err != nil {
		return nil, err
	}
	return s.orgs.ListGroupMappings(ctx, clientID, organizationID)
}

func (s *OrganizationService) UpsertGroupMapping(ctx context.Context, clientID, organizationID, actorUserID, mappingID string, req UpsertGroupMappingRequest, ip, ua string) (*domain.OrganizationGroupMapping, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionAuthorizationManage); err != nil {
		return nil, err
	}
	source, err := domain.NormalizeGroupMappingSource(req.Source)
	if err != nil {
		return nil, err
	}
	group := domain.NormalizeGroupName(req.Group)
	if group == "" {
		return nil, domain.ErrInvalidGroupMapping
	}
	role, err := domain.NormalizeOrganizationRole(req.Role)
	if err != nil {
		return nil, err
	}
	permissions, err := domain.NormalizeOrganizationPermissions(req.Permissions)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	mapping := &domain.OrganizationGroupMapping{
		ID:             mappingID,
		ClientID:       clientID,
		OrganizationID: organizationID,
		Source:         source,
		SourceID:       strings.TrimSpace(req.SourceID),
		Group:          group,
		Role:           role,
		Permissions:    permissions,
		Description:    strings.TrimSpace(req.Description),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if mapping.ID == "" {
		mapping.ID = uuid.NewString()
	}
	if err := s.orgs.UpsertGroupMapping(ctx, mapping); err != nil {
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "authorization_group_mapping_upserted", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"mapping_id":      mapping.ID,
		"source":          mapping.Source,
		"group":           mapping.Group,
	})
	return mapping, nil
}

func (s *OrganizationService) DeleteGroupMapping(ctx context.Context, clientID, organizationID, actorUserID, mappingID, ip, ua string) error {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionAuthorizationManage); err != nil {
		return err
	}
	if err := s.orgs.DeleteGroupMapping(ctx, clientID, organizationID, mappingID); err != nil {
		return err
	}
	s.log(ctx, clientID, &actorUserID, "authorization_group_mapping_deleted", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"mapping_id":      mappingID,
	})
	return nil
}

func (s *OrganizationService) SimulateAuthorization(ctx context.Context, clientID, organizationID, actorUserID string, req AuthorizationSimulationRequest) (*domain.AuthorizationDecision, error) {
	if _, err := s.requireAnyPermission(ctx, clientID, organizationID, actorUserID, domain.PermissionAuthorizationRead, domain.PermissionAuthorizationManage); err != nil {
		return nil, err
	}
	userID := strings.TrimSpace(req.UserID)
	if userID == "" {
		userID = actorUserID
	}
	membership, err := s.orgs.GetMembership(ctx, clientID, organizationID, userID)
	if err != nil && err != domain.ErrNotFound {
		return nil, err
	}
	policy, _ := s.ensureAuthorizationPolicy(ctx, clientID, organizationID)
	decision := domain.ExplainAuthorizationDecision(clientID, organizationID, userID, membership, policy, req.Resource, req.Action)
	return &decision, nil
}

func (s *OrganizationService) IsAuthorized(ctx context.Context, clientID, organizationID, userID, resource, action string) (*domain.AuthorizationDecision, error) {
	membership, err := s.orgs.GetMembership(ctx, clientID, organizationID, userID)
	if err != nil {
		if err == domain.ErrNotFound {
			decision := domain.ExplainAuthorizationDecision(clientID, organizationID, userID, nil, nil, resource, action)
			return &decision, nil
		}
		return nil, err
	}
	policy, _ := s.ensureAuthorizationPolicy(ctx, clientID, organizationID)
	decision := domain.ExplainAuthorizationDecision(clientID, organizationID, userID, membership, policy, resource, action)
	return &decision, nil
}

func (s *OrganizationService) requirePermission(ctx context.Context, clientID, organizationID, userID, permission string) (*domain.OrganizationMembership, error) {
	return s.requireAnyPermission(ctx, clientID, organizationID, userID, permission)
}

func (s *OrganizationService) requireAnyPermission(ctx context.Context, clientID, organizationID, userID string, permissions ...string) (*domain.OrganizationMembership, error) {
	membership, err := s.orgs.GetMembership(ctx, clientID, organizationID, userID)
	if err != nil {
		return nil, err
	}
	policy, _ := s.ensureAuthorizationPolicy(ctx, clientID, organizationID)
	effectiveMembership := cloneMembershipForAuthz(membership, policy)
	for _, permission := range permissions {
		if domain.OrganizationPermissionAllowed(effectiveMembership, policy, permission) {
			return effectiveMembership, nil
		}
	}
	return nil, domain.ErrForbidden
}

func (s *OrganizationService) ensureAuthorizationPolicy(ctx context.Context, clientID, organizationID string) (*domain.OrganizationAuthorizationPolicy, error) {
	policy, err := s.orgs.GetAuthorizationPolicy(ctx, clientID, organizationID)
	if err == nil {
		normalized, normalizeErr := domain.NormalizeAuthorizationPolicy(policy)
		if normalizeErr != nil {
			return nil, normalizeErr
		}
		return normalized, nil
	}
	if err != domain.ErrNotFound {
		return nil, err
	}
	now := time.Now().UTC()
	policy = domain.DefaultAuthorizationPolicy(clientID, organizationID, now)
	if err := s.orgs.UpsertAuthorizationPolicy(ctx, policy); err != nil {
		return nil, err
	}
	return policy, nil
}

func (s *OrganizationService) ensureNotLastOwner(ctx context.Context, clientID, organizationID string) error {
	members, err := s.orgs.ListMemberships(ctx, clientID, organizationID)
	if err != nil {
		return err
	}
	ownerCount := 0
	for _, member := range members {
		if member.Status == "active" && member.Role == domain.OrganizationRoleOwner {
			ownerCount++
		}
	}
	if ownerCount <= 1 {
		return domain.ErrForbidden
	}
	return nil
}

func cloneMembershipForAuthz(membership *domain.OrganizationMembership, policy *domain.OrganizationAuthorizationPolicy) *domain.OrganizationMembership {
	if membership == nil {
		return nil
	}
	cp := *membership
	cp.Permissions = domain.ResolveOrganizationPermissions(membership, policy)
	return &cp
}

func ApplyOrganizationGroupMappings(ctx context.Context, orgs OrganizationRepository, clientID, source, sourceID, userID string, groups []string) error {
	if orgs == nil || strings.TrimSpace(userID) == "" {
		return nil
	}
	normalizedSource, err := domain.NormalizeGroupMappingSource(source)
	if err != nil {
		return err
	}
	normalizedGroups := normalizeGroupNames(groups)
	if len(normalizedGroups) == 0 {
		return nil
	}
	mappings, err := orgs.ListGroupMappingsForSource(ctx, clientID, normalizedSource, strings.TrimSpace(sourceID), normalizedGroups)
	if err != nil {
		return err
	}
	if len(mappings) == 0 {
		return nil
	}

	now := time.Now().UTC()
	planned := map[string]*domain.OrganizationMembership{}
	for _, mapping := range mappings {
		role, err := domain.NormalizeOrganizationRole(mapping.Role)
		if err != nil {
			return err
		}
		permissions, err := domain.NormalizeOrganizationPermissions(mapping.Permissions)
		if err != nil {
			return err
		}
		membership := planned[mapping.OrganizationID]
		if membership == nil {
			existing, err := orgs.GetMembership(ctx, clientID, mapping.OrganizationID, userID)
			if err == nil {
				membership = existing
			} else if err == domain.ErrNotFound {
				membership = &domain.OrganizationMembership{
					ID:             uuid.NewString(),
					ClientID:       clientID,
					OrganizationID: mapping.OrganizationID,
					UserID:         userID,
					Role:           role,
					Status:         "active",
					CreatedAt:      now,
					UpdatedAt:      now,
				}
			} else {
				return err
			}
			planned[mapping.OrganizationID] = membership
		}
		if membership.Role != domain.OrganizationRoleOwner {
			membership.Role = strongerOrganizationRole(membership.Role, role)
		}
		membership.Permissions = mergeOrganizationPermissions(membership.Permissions, permissions)
		membership.Status = "active"
		membership.UpdatedAt = now
	}
	for _, membership := range planned {
		if err := orgs.UpsertMembership(ctx, membership); err != nil {
			return err
		}
	}
	return nil
}

func (s *OrganizationService) log(ctx context.Context, clientID string, userID *string, eventType, ip, ua string, metadata map[string]interface{}) {
	if s.audit != nil {
		s.audit.Log(ctx, clientID, userID, eventType, ip, ua, metadata)
	}
}

func normalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", fmt.Errorf("email is required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return "", fmt.Errorf("invalid email")
	}
	return email, nil
}

func normalizeOrganizationNameAndSlug(name, slug string) (string, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", fmt.Errorf("organization name is required")
	}
	if len(name) > 128 {
		return "", "", fmt.Errorf("organization name must be 128 characters or fewer")
	}
	slug = normalizeOrganizationSlug(slug, name)
	if slug == "" {
		return "", "", fmt.Errorf("organization slug is required")
	}
	if len(slug) > 80 {
		return "", "", fmt.Errorf("organization slug must be 80 characters or fewer")
	}
	return name, slug, nil
}

func normalizeOrganizationSlug(raw, fallback string) string {
	source := strings.ToLower(strings.TrimSpace(raw))
	if source == "" {
		source = strings.ToLower(strings.TrimSpace(fallback))
	}
	var b strings.Builder
	lastDash := false
	for _, r := range source {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if r == '_' {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if r == '-' || unicode.IsSpace(r) {
			if b.Len() > 0 && !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func normalizeRequestedPermissions(role string, requested []string) ([]string, error) {
	if requested == nil {
		return domain.OrganizationRolePermissions(role), nil
	}
	return domain.NormalizeOrganizationPermissions(requested)
}

func normalizeGroupNames(groups []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		group = domain.NormalizeGroupName(group)
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		out = append(out, group)
	}
	return out
}

func mergeGroupNames(existing, added []string) []string {
	merged := append([]string(nil), existing...)
	merged = append(merged, added...)
	return normalizeGroupNames(merged)
}

func mergeOrganizationPermissions(existing, added []string) []string {
	merged := append([]string(nil), existing...)
	merged = append(merged, added...)
	permissions, err := domain.NormalizeOrganizationPermissions(merged)
	if err != nil {
		return existing
	}
	return permissions
}

func strongerOrganizationRole(current, candidate string) string {
	currentRank := organizationRoleRank(current)
	candidateRank := organizationRoleRank(candidate)
	if candidateRank > currentRank {
		return candidate
	}
	if current == "" {
		return candidate
	}
	if currentRank == candidateRank && isBuiltInRole(current) && !isBuiltInRole(candidate) {
		return candidate
	}
	return current
}

func organizationRoleRank(role string) int {
	switch role {
	case domain.OrganizationRoleOwner:
		return 4
	case domain.OrganizationRoleAdmin:
		return 3
	case domain.OrganizationRoleMember:
		return 2
	case domain.OrganizationRoleViewer:
		return 1
	case "":
		return 0
	default:
		return 2
	}
}

func isBuiltInRole(role string) bool {
	switch role {
	case domain.OrganizationRoleOwner, domain.OrganizationRoleAdmin, domain.OrganizationRoleMember, domain.OrganizationRoleViewer:
		return true
	default:
		return false
	}
}

func invitationTTL(hours int) time.Duration {
	if hours <= 0 {
		return defaultInvitationTTL
	}
	ttl := time.Duration(hours) * time.Hour
	if ttl > maxInvitationTTL {
		return maxInvitationTTL
	}
	return ttl
}

func canAssignOrganizationRole(actor *domain.OrganizationMembership, role string) bool {
	if actor == nil || actor.Status != "active" {
		return false
	}
	if actor.Role == domain.OrganizationRoleOwner {
		return true
	}
	if role == domain.OrganizationRoleOwner {
		return false
	}
	return domain.HasOrganizationPermission(actor, domain.PermissionMembersWrite) ||
		domain.HasOrganizationPermission(actor, domain.PermissionMembersInvite) ||
		domain.HasOrganizationPermission(actor, domain.PermissionInvitationsWrite)
}

func canAssignOrganizationPermissions(actor *domain.OrganizationMembership, permissions []string) bool {
	if actor == nil || actor.Status != "active" {
		return false
	}
	if actor.Role == domain.OrganizationRoleOwner {
		return true
	}
	for _, permission := range permissions {
		if !domain.HasOrganizationPermission(actor, permission) {
			return false
		}
	}
	return true
}

func isDuplicateError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique constraint") || strings.Contains(msg, "unique_violation")
}
