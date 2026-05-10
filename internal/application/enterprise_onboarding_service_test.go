package application

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

func TestEnterpriseOnboardingCreatesSAMLDraftWithMetadataHelpers(t *testing.T) {
	ctx := context.Background()
	orgs := newEnterpriseOnboardingOrgRepo()
	domains := newEnterpriseOnboardingDomainRepo()
	ssoRepo := newEnterpriseOnboardingSSORepo()
	scimRepo := newEnterpriseOnboardingSCIMRepo()
	audit := &enterpriseOnboardingAuditRepo{}
	ssoSvc := NewEnterpriseSSOService(ssoRepo, nil, nil, nil, nil, audit)
	svc := NewEnterpriseOnboardingService(domains, orgs, ssoRepo, scimRepo, audit, ssoSvc)

	orgs.membership = &domain.OrganizationMembership{
		ClientID:       "client-a",
		OrganizationID: "org-a",
		UserID:         "user-a",
		Role:           domain.OrganizationRoleAdmin,
		Status:         "active",
	}
	verifiedAt := time.Now().UTC()
	domains.byDomain["acme.com"] = &domain.EnterpriseDomainVerification{
		ID:             "domain-a",
		ClientID:       "client-a",
		OrganizationID: "org-a",
		Domain:         "acme.com",
		Status:         domain.EnterpriseDomainStatusVerified,
		TXTName:        "_authservice.acme.com",
		TXTValue:       "authservice-domain-verification=test",
		VerifiedAt:     &verifiedAt,
	}

	portal, err := svc.CreateSSOConnection(ctx, "client-a", "org-a", "user-a", CreateEnterpriseOnboardingSSORequest{
		Name:     "Acme Okta",
		Provider: domain.EnterpriseProviderOkta,
		Protocol: domain.SSOProtocolSAML,
		Domains:  []string{"acme.com"},
	}, "https://auth.example.com", "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("create sso connection: %v", err)
	}
	if portal.Connection.OrganizationID != "org-a" || portal.Connection.Status != domain.SSOConnectionStatusInactive {
		t.Fatalf("unexpected scoped draft connection: %+v", portal.Connection)
	}
	if portal.Connection.SAML.SPPrivateKeyPEM != "" {
		t.Fatalf("portal response must not expose the generated SAML private key")
	}
	if portal.Setup.ACSURL == "" || portal.Setup.SPMetadataURL == "" || !strings.Contains(portal.Setup.SPMetadataURL, portal.Connection.ID) {
		t.Fatalf("expected SAML setup helpers, got %+v", portal.Setup)
	}
	if len(audit.events) == 0 || audit.events[len(audit.events)-1].EventType != "enterprise_sso_connection_self_serve_created" {
		t.Fatalf("expected self-serve audit event, got %+v", audit.events)
	}
}

func TestEnterpriseOnboardingRejectsUnverifiedDomains(t *testing.T) {
	ctx := context.Background()
	orgs := newEnterpriseOnboardingOrgRepo()
	svc := NewEnterpriseOnboardingService(
		newEnterpriseOnboardingDomainRepo(),
		orgs,
		newEnterpriseOnboardingSSORepo(),
		newEnterpriseOnboardingSCIMRepo(),
		&enterpriseOnboardingAuditRepo{},
		NewEnterpriseSSOService(newEnterpriseOnboardingSSORepo(), nil, nil, nil, nil, nil),
	)
	orgs.membership = &domain.OrganizationMembership{
		ClientID:       "client-a",
		OrganizationID: "org-a",
		UserID:         "user-a",
		Role:           domain.OrganizationRoleAdmin,
		Status:         "active",
	}

	_, err := svc.CreateSSOConnection(ctx, "client-a", "org-a", "user-a", CreateEnterpriseOnboardingSSORequest{
		Name:     "Acme Okta",
		Protocol: domain.SSOProtocolSAML,
		Domains:  []string{"acme.com"},
	}, "https://auth.example.com", "", "")
	if err == nil || !strings.Contains(err.Error(), "must be verified") {
		t.Fatalf("expected verified domain requirement, got %v", err)
	}
}

func TestEnterpriseOnboardingCreatesSCIMDirectoryWithSetupAndToken(t *testing.T) {
	ctx := context.Background()
	orgs := newEnterpriseOnboardingOrgRepo()
	domains := newEnterpriseOnboardingDomainRepo()
	scimRepo := newEnterpriseOnboardingSCIMRepo()
	svc := NewEnterpriseOnboardingService(domains, orgs, newEnterpriseOnboardingSSORepo(), scimRepo, &enterpriseOnboardingAuditRepo{}, nil)
	orgs.membership = &domain.OrganizationMembership{
		ClientID:       "client-a",
		OrganizationID: "org-a",
		UserID:         "user-a",
		Role:           domain.OrganizationRoleAdmin,
		Status:         "active",
	}
	domains.byDomain["acme.com"] = &domain.EnterpriseDomainVerification{
		ID:             "domain-a",
		ClientID:       "client-a",
		OrganizationID: "org-a",
		Domain:         "acme.com",
		Status:         domain.EnterpriseDomainStatusVerified,
	}

	created, err := svc.CreateSCIMDirectory(ctx, "client-a", "org-a", "user-a", CreateEnterpriseOnboardingSCIMRequest{
		Name:     "Acme Directory",
		Provider: domain.EnterpriseProviderMicrosoftEntra,
		Domains:  []string{"acme.com"},
	}, "https://auth.example.com", "", "")
	if err != nil {
		t.Fatalf("create scim directory: %v", err)
	}
	if created.Token == "" || created.Directory.TokenHash == "" || created.Directory.OrganizationID != "org-a" {
		t.Fatalf("expected scoped directory and one-time token, got %+v", created)
	}
	if got := created.Setup.SCIMBaseURL; got != "https://auth.example.com/scim/v2/"+created.Directory.ID {
		t.Fatalf("unexpected scim base url %q", got)
	}
}

type enterpriseOnboardingOrgRepo struct {
	membership *domain.OrganizationMembership
	org        *domain.Organization
}

func newEnterpriseOnboardingOrgRepo() *enterpriseOnboardingOrgRepo {
	return &enterpriseOnboardingOrgRepo{org: &domain.Organization{ID: "org-a", ClientID: "client-a", Name: "Acme", Slug: "acme"}}
}

func (r *enterpriseOnboardingOrgRepo) CreateOrganization(ctx context.Context, org *domain.Organization, owner *domain.OrganizationMembership) error {
	return nil
}
func (r *enterpriseOnboardingOrgRepo) UpdateOrganization(ctx context.Context, org *domain.Organization) error {
	return nil
}
func (r *enterpriseOnboardingOrgRepo) GetOrganization(ctx context.Context, clientID, organizationID string) (*domain.Organization, error) {
	if r.org.ClientID == clientID && r.org.ID == organizationID {
		return r.org, nil
	}
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingOrgRepo) ListOrganizationsForUser(ctx context.Context, clientID, userID string) ([]domain.OrganizationMembershipDetails, error) {
	return nil, nil
}
func (r *enterpriseOnboardingOrgRepo) GetMembership(ctx context.Context, clientID, organizationID, userID string) (*domain.OrganizationMembership, error) {
	if r.membership != nil && r.membership.ClientID == clientID && r.membership.OrganizationID == organizationID && r.membership.UserID == userID {
		return r.membership, nil
	}
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingOrgRepo) ListMemberships(ctx context.Context, clientID, organizationID string) ([]*domain.OrganizationMembership, error) {
	return nil, nil
}
func (r *enterpriseOnboardingOrgRepo) UpsertMembership(ctx context.Context, membership *domain.OrganizationMembership) error {
	return nil
}
func (r *enterpriseOnboardingOrgRepo) UpdateMembership(ctx context.Context, membership *domain.OrganizationMembership) error {
	return nil
}
func (r *enterpriseOnboardingOrgRepo) DeleteMembership(ctx context.Context, clientID, organizationID, userID string) error {
	return nil
}
func (r *enterpriseOnboardingOrgRepo) CreateInvitation(ctx context.Context, invitation *domain.OrganizationInvitation) error {
	return nil
}
func (r *enterpriseOnboardingOrgRepo) ListInvitations(ctx context.Context, clientID, organizationID string) ([]*domain.OrganizationInvitation, error) {
	return nil, nil
}
func (r *enterpriseOnboardingOrgRepo) GetInvitation(ctx context.Context, clientID, organizationID, invitationID string) (*domain.OrganizationInvitation, error) {
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingOrgRepo) GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*domain.OrganizationInvitation, error) {
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingOrgRepo) MarkInvitationAccepted(ctx context.Context, invitationID, userID string) error {
	return nil
}
func (r *enterpriseOnboardingOrgRepo) RevokeInvitation(ctx context.Context, clientID, organizationID, invitationID string) error {
	return nil
}
func (r *enterpriseOnboardingOrgRepo) GetAuthorizationPolicy(ctx context.Context, clientID, organizationID string) (*domain.OrganizationAuthorizationPolicy, error) {
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingOrgRepo) UpsertAuthorizationPolicy(ctx context.Context, policy *domain.OrganizationAuthorizationPolicy) error {
	return nil
}
func (r *enterpriseOnboardingOrgRepo) ListGroupMappings(ctx context.Context, clientID, organizationID string) ([]*domain.OrganizationGroupMapping, error) {
	return nil, nil
}
func (r *enterpriseOnboardingOrgRepo) GetGroupMapping(ctx context.Context, clientID, organizationID, mappingID string) (*domain.OrganizationGroupMapping, error) {
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingOrgRepo) UpsertGroupMapping(ctx context.Context, mapping *domain.OrganizationGroupMapping) error {
	return nil
}
func (r *enterpriseOnboardingOrgRepo) DeleteGroupMapping(ctx context.Context, clientID, organizationID, mappingID string) error {
	return nil
}
func (r *enterpriseOnboardingOrgRepo) ListGroupMappingsForSource(ctx context.Context, clientID, source, sourceID string, groups []string) ([]*domain.OrganizationGroupMapping, error) {
	return nil, nil
}

type enterpriseOnboardingDomainRepo struct {
	byID     map[string]*domain.EnterpriseDomainVerification
	byDomain map[string]*domain.EnterpriseDomainVerification
}

func newEnterpriseOnboardingDomainRepo() *enterpriseOnboardingDomainRepo {
	return &enterpriseOnboardingDomainRepo{
		byID:     map[string]*domain.EnterpriseDomainVerification{},
		byDomain: map[string]*domain.EnterpriseDomainVerification{},
	}
}

func (r *enterpriseOnboardingDomainRepo) CreateDomainVerification(ctx context.Context, verification *domain.EnterpriseDomainVerification) error {
	r.byID[verification.ID] = verification
	r.byDomain[verification.Domain] = verification
	return nil
}
func (r *enterpriseOnboardingDomainRepo) ListDomainVerifications(ctx context.Context, clientID, organizationID string) ([]*domain.EnterpriseDomainVerification, error) {
	out := []*domain.EnterpriseDomainVerification{}
	for _, verification := range r.byDomain {
		if verification.ClientID == clientID && verification.OrganizationID == organizationID {
			out = append(out, verification)
		}
	}
	return out, nil
}
func (r *enterpriseOnboardingDomainRepo) GetDomainVerification(ctx context.Context, clientID, organizationID, verificationID string) (*domain.EnterpriseDomainVerification, error) {
	verification := r.byID[verificationID]
	if verification == nil || verification.ClientID != clientID || verification.OrganizationID != organizationID {
		return nil, domain.ErrNotFound
	}
	return verification, nil
}
func (r *enterpriseOnboardingDomainRepo) GetDomainVerificationByDomain(ctx context.Context, clientID, organizationID, domainName string) (*domain.EnterpriseDomainVerification, error) {
	verification := r.byDomain[domainName]
	if verification == nil || verification.ClientID != clientID || verification.OrganizationID != organizationID {
		return nil, domain.ErrNotFound
	}
	return verification, nil
}
func (r *enterpriseOnboardingDomainRepo) UpdateDomainVerification(ctx context.Context, verification *domain.EnterpriseDomainVerification) error {
	r.byID[verification.ID] = verification
	r.byDomain[verification.Domain] = verification
	return nil
}

type enterpriseOnboardingSSORepo struct {
	connections map[string]*domain.EnterpriseSSOConnection
}

func newEnterpriseOnboardingSSORepo() *enterpriseOnboardingSSORepo {
	return &enterpriseOnboardingSSORepo{connections: map[string]*domain.EnterpriseSSOConnection{}}
}
func (r *enterpriseOnboardingSSORepo) CreateConnection(ctx context.Context, connection *domain.EnterpriseSSOConnection) error {
	r.connections[connection.ID] = connection
	return nil
}
func (r *enterpriseOnboardingSSORepo) ListConnections(ctx context.Context, clientID string) ([]*domain.EnterpriseSSOConnection, error) {
	return r.ListConnectionsForOrganization(ctx, clientID, "")
}
func (r *enterpriseOnboardingSSORepo) ListConnectionsForOrganization(ctx context.Context, clientID, organizationID string) ([]*domain.EnterpriseSSOConnection, error) {
	out := []*domain.EnterpriseSSOConnection{}
	for _, connection := range r.connections {
		if connection.ClientID == clientID && (organizationID == "" || connection.OrganizationID == organizationID) {
			out = append(out, connection)
		}
	}
	return out, nil
}
func (r *enterpriseOnboardingSSORepo) GetConnection(ctx context.Context, clientID, connectionID string) (*domain.EnterpriseSSOConnection, error) {
	connection := r.connections[connectionID]
	if connection == nil || connection.ClientID != clientID {
		return nil, domain.ErrNotFound
	}
	return connection, nil
}
func (r *enterpriseOnboardingSSORepo) GetConnectionByID(ctx context.Context, connectionID string) (*domain.EnterpriseSSOConnection, error) {
	if connection := r.connections[connectionID]; connection != nil {
		return connection, nil
	}
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingSSORepo) GetConnectionBySlug(ctx context.Context, clientID, slug string) (*domain.EnterpriseSSOConnection, error) {
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingSSORepo) GetActiveConnectionByDomain(ctx context.Context, clientID, domainName string) (*domain.EnterpriseSSOConnection, error) {
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingSSORepo) UpdateConnection(ctx context.Context, connection *domain.EnterpriseSSOConnection) error {
	r.connections[connection.ID] = connection
	return nil
}
func (r *enterpriseOnboardingSSORepo) DeactivateConnection(ctx context.Context, clientID, connectionID string) error {
	return nil
}
func (r *enterpriseOnboardingSSORepo) MarkConnectionLogin(ctx context.Context, clientID, connectionID string, at time.Time) error {
	return nil
}
func (r *enterpriseOnboardingSSORepo) MarkConnectionError(ctx context.Context, clientID, connectionID, message string, at time.Time) error {
	return nil
}
func (r *enterpriseOnboardingSSORepo) FindIdentity(ctx context.Context, clientID, connectionID, externalID string) (*domain.EnterpriseSSOIdentity, error) {
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingSSORepo) UpsertIdentity(ctx context.Context, identity *domain.EnterpriseSSOIdentity) error {
	return nil
}

type enterpriseOnboardingSCIMRepo struct {
	directories map[string]*domain.SCIMDirectory
}

func newEnterpriseOnboardingSCIMRepo() *enterpriseOnboardingSCIMRepo {
	return &enterpriseOnboardingSCIMRepo{directories: map[string]*domain.SCIMDirectory{}}
}
func (r *enterpriseOnboardingSCIMRepo) CreateDirectory(ctx context.Context, directory *domain.SCIMDirectory) error {
	r.directories[directory.ID] = directory
	return nil
}
func (r *enterpriseOnboardingSCIMRepo) ListDirectories(ctx context.Context, clientID string) ([]*domain.SCIMDirectory, error) {
	return r.ListDirectoriesForOrganization(ctx, clientID, "")
}
func (r *enterpriseOnboardingSCIMRepo) ListDirectoriesForOrganization(ctx context.Context, clientID, organizationID string) ([]*domain.SCIMDirectory, error) {
	out := []*domain.SCIMDirectory{}
	for _, directory := range r.directories {
		if directory.ClientID == clientID && (organizationID == "" || directory.OrganizationID == organizationID) {
			out = append(out, directory)
		}
	}
	return out, nil
}
func (r *enterpriseOnboardingSCIMRepo) GetDirectory(ctx context.Context, clientID, directoryID string) (*domain.SCIMDirectory, error) {
	directory := r.directories[directoryID]
	if directory == nil || directory.ClientID != clientID {
		return nil, domain.ErrNotFound
	}
	return directory, nil
}
func (r *enterpriseOnboardingSCIMRepo) GetDirectoryByID(ctx context.Context, directoryID string) (*domain.SCIMDirectory, error) {
	if directory := r.directories[directoryID]; directory != nil {
		return directory, nil
	}
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingSCIMRepo) GetDirectoryByTokenHash(ctx context.Context, tokenHash string) (*domain.SCIMDirectory, error) {
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingSCIMRepo) UpdateDirectory(ctx context.Context, directory *domain.SCIMDirectory) error {
	r.directories[directory.ID] = directory
	return nil
}
func (r *enterpriseOnboardingSCIMRepo) MarkDirectorySync(ctx context.Context, clientID, directoryID string, at time.Time) error {
	return nil
}
func (r *enterpriseOnboardingSCIMRepo) MarkDirectoryError(ctx context.Context, clientID, directoryID, message string, at time.Time) error {
	return nil
}
func (r *enterpriseOnboardingSCIMRepo) UpsertUser(ctx context.Context, user *domain.SCIMUser) error {
	return nil
}
func (r *enterpriseOnboardingSCIMRepo) ListUsers(ctx context.Context, clientID, directoryID string) ([]*domain.SCIMUser, error) {
	return nil, nil
}
func (r *enterpriseOnboardingSCIMRepo) GetUser(ctx context.Context, clientID, directoryID, scimUserID string) (*domain.SCIMUser, error) {
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingSCIMRepo) GetUserByExternalID(ctx context.Context, clientID, directoryID, externalID string) (*domain.SCIMUser, error) {
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingSCIMRepo) DeleteUser(ctx context.Context, clientID, directoryID, scimUserID string) error {
	return nil
}
func (r *enterpriseOnboardingSCIMRepo) UpsertGroup(ctx context.Context, group *domain.SCIMGroup) error {
	return nil
}
func (r *enterpriseOnboardingSCIMRepo) ListGroups(ctx context.Context, clientID, directoryID string) ([]*domain.SCIMGroup, error) {
	return nil, nil
}
func (r *enterpriseOnboardingSCIMRepo) GetGroup(ctx context.Context, clientID, directoryID, scimGroupID string) (*domain.SCIMGroup, error) {
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingSCIMRepo) GetGroupByExternalID(ctx context.Context, clientID, directoryID, externalID string) (*domain.SCIMGroup, error) {
	return nil, domain.ErrNotFound
}
func (r *enterpriseOnboardingSCIMRepo) DeleteGroup(ctx context.Context, clientID, directoryID, scimGroupID string) error {
	return nil
}

type enterpriseOnboardingAuditRepo struct {
	events []*domain.AuditEvent
}

func (r *enterpriseOnboardingAuditRepo) Log(ctx context.Context, clientID string, userID *string, eventType, ip, ua string, metadata map[string]interface{}) {
	r.events = append(r.events, &domain.AuditEvent{ClientID: clientID, UserID: userID, EventType: eventType, IPAddress: ip, UserAgent: ua, Metadata: metadata, CreatedAt: time.Now().UTC()})
}
func (r *enterpriseOnboardingAuditRepo) List(ctx context.Context, filter domain.AuditEventFilter) ([]*domain.AuditEvent, error) {
	return r.events, nil
}
