package application

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
)

const (
	domainVerificationPrefix = "authservice-domain-verification="
	domainTXTRecordPrefix    = "_authservice."
)

type txtResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type EnterpriseOnboardingService struct {
	domains  EnterpriseDomainVerificationRepository
	orgs     OrganizationRepository
	sso      EnterpriseSSORepository
	scim     SCIMRepository
	audit    AuditEventRepository
	ssoSvc   *EnterpriseSSOService
	resolver txtResolver
}

func NewEnterpriseOnboardingService(domains EnterpriseDomainVerificationRepository, orgs OrganizationRepository, sso EnterpriseSSORepository, scim SCIMRepository, audit AuditEventRepository, ssoSvc *EnterpriseSSOService) *EnterpriseOnboardingService {
	return &EnterpriseOnboardingService{
		domains:  domains,
		orgs:     orgs,
		sso:      sso,
		scim:     scim,
		audit:    audit,
		ssoSvc:   ssoSvc,
		resolver: net.DefaultResolver,
	}
}

type CreateEnterpriseDomainRequest struct {
	Domain string `json:"domain"`
}

type CreateEnterpriseOnboardingSSORequest struct {
	Name              string                         `json:"name"`
	Slug              string                         `json:"slug"`
	Provider          string                         `json:"provider,omitempty"`
	Protocol          string                         `json:"protocol"`
	Status            string                         `json:"status,omitempty"`
	Domains           []string                       `json:"domains"`
	EnforceForDomains bool                           `json:"enforce_for_domains"`
	OIDC              domain.EnterpriseSSOOIDCConfig `json:"oidc,omitempty"`
	SAML              domain.EnterpriseSSOSAMLConfig `json:"saml,omitempty"`
	AttributeMapping  map[string]string              `json:"attribute_mapping,omitempty"`
}

type CreateEnterpriseOnboardingSCIMRequest struct {
	Name     string   `json:"name"`
	Provider string   `json:"provider,omitempty"`
	Domains  []string `json:"domains"`
}

type UpdateEnterpriseOnboardingSCIMRequest struct {
	Name     *string  `json:"name,omitempty"`
	Provider *string  `json:"provider,omitempty"`
	Status   *string  `json:"status,omitempty"`
	Domains  []string `json:"domains,omitempty"`
}

type EnterpriseOnboardingSummary struct {
	Organization    *domain.Organization                   `json:"organization"`
	Membership      *domain.OrganizationMembership         `json:"membership"`
	Domains         []*domain.EnterpriseDomainVerification `json:"domains"`
	SSOConnections  []EnterpriseSSOPortalConnection        `json:"sso_connections"`
	SCIMDirectories []EnterpriseSCIMPortalDirectory        `json:"scim_directories"`
	Providers       []domain.EnterpriseProviderGuide       `json:"providers"`
}

type EnterpriseSSOPortalConnection struct {
	Connection *domain.EnterpriseSSOConnection   `json:"connection"`
	Health     domain.EnterpriseConnectionHealth `json:"health"`
	Setup      domain.EnterpriseSetupHelper      `json:"setup"`
}

type EnterpriseSCIMPortalDirectory struct {
	Directory *domain.SCIMDirectory             `json:"directory"`
	Health    domain.EnterpriseConnectionHealth `json:"health"`
	Setup     domain.EnterpriseSetupHelper      `json:"setup"`
}

type EnterpriseSCIMDirectoryWithSetup struct {
	Directory *domain.SCIMDirectory             `json:"directory"`
	Token     string                            `json:"token,omitempty"`
	Health    domain.EnterpriseConnectionHealth `json:"health"`
	Setup     domain.EnterpriseSetupHelper      `json:"setup"`
}

func (s *EnterpriseOnboardingService) Summary(ctx context.Context, clientID, organizationID, actorUserID, baseURL string) (*EnterpriseOnboardingSummary, error) {
	membership, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionEnterpriseRead)
	if err != nil {
		return nil, err
	}
	org, err := s.orgs.GetOrganization(ctx, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	domains, err := s.domains.ListDomainVerifications(ctx, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	connections, err := s.sso.ListConnectionsForOrganization(ctx, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	directories, err := s.scim.ListDirectoriesForOrganization(ctx, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	return &EnterpriseOnboardingSummary{
		Organization:    org,
		Membership:      membership,
		Domains:         domains,
		SSOConnections:  s.portalSSOConnections(connections, baseURL),
		SCIMDirectories: s.portalSCIMDirectories(directories, baseURL),
		Providers:       EnterpriseProviderGuides(),
	}, nil
}

func (s *EnterpriseOnboardingService) CreateDomain(ctx context.Context, clientID, organizationID, actorUserID string, req CreateEnterpriseDomainRequest, ip, ua string) (*domain.EnterpriseDomainVerification, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionEnterpriseWrite); err != nil {
		return nil, err
	}
	domains := domain.NormalizeSSODomains([]string{req.Domain})
	if len(domains) != 1 {
		return nil, fmt.Errorf("domain is required")
	}
	if existing, err := s.domains.GetDomainVerificationByDomain(ctx, clientID, organizationID, domains[0]); err == nil {
		return existing, nil
	} else if err != domain.ErrNotFound {
		return nil, err
	}
	token, err := GenerateToken(18)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	verification := &domain.EnterpriseDomainVerification{
		ID:             uuid.NewString(),
		ClientID:       clientID,
		OrganizationID: organizationID,
		Domain:         domains[0],
		Status:         domain.EnterpriseDomainStatusPending,
		TXTName:        domainTXTRecordPrefix + domains[0],
		TXTValue:       domainVerificationPrefix + token,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.domains.CreateDomainVerification(ctx, verification); err != nil {
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "enterprise_domain_verification_created", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"domain_id":       verification.ID,
		"domain":          verification.Domain,
	})
	return verification, nil
}

func (s *EnterpriseOnboardingService) VerifyDomain(ctx context.Context, clientID, organizationID, actorUserID, verificationID, ip, ua string) (*domain.EnterpriseDomainVerification, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionEnterpriseWrite); err != nil {
		return nil, err
	}
	verification, err := s.domains.GetDomainVerification(ctx, clientID, organizationID, verificationID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	verification.LastCheckedAt = &now
	verification.UpdatedAt = now

	verified, lookupErr := s.lookupDomainVerification(ctx, verification)
	if verified {
		verification.Status = domain.EnterpriseDomainStatusVerified
		verification.VerifiedAt = &now
		verification.LastError = ""
	} else {
		verification.Status = domain.EnterpriseDomainStatusFailed
		verification.LastError = lookupErr
	}
	if err := s.domains.UpdateDomainVerification(ctx, verification); err != nil {
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "enterprise_domain_verification_checked", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"domain_id":       verification.ID,
		"domain":          verification.Domain,
		"status":          verification.Status,
	})
	return verification, nil
}

func (s *EnterpriseOnboardingService) ListSSOConnections(ctx context.Context, clientID, organizationID, actorUserID, baseURL string) ([]EnterpriseSSOPortalConnection, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionEnterpriseRead); err != nil {
		return nil, err
	}
	connections, err := s.sso.ListConnectionsForOrganization(ctx, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	return s.portalSSOConnections(connections, baseURL), nil
}

func (s *EnterpriseOnboardingService) CreateSSOConnection(ctx context.Context, clientID, organizationID, actorUserID string, req CreateEnterpriseOnboardingSSORequest, baseURL, ip, ua string) (*EnterpriseSSOPortalConnection, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionEnterpriseWrite); err != nil {
		return nil, err
	}
	domains := domain.NormalizeSSODomains(req.Domains)
	if err := s.requireVerifiedDomains(ctx, clientID, organizationID, domains); err != nil {
		return nil, err
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status == "" {
		status = domain.SSOConnectionStatusInactive
	}
	connection, err := s.ssoSvc.CreateConnection(ctx, clientID, CreateEnterpriseSSOConnectionRequest{
		Name:              req.Name,
		Slug:              req.Slug,
		OrganizationID:    organizationID,
		Provider:          req.Provider,
		Protocol:          req.Protocol,
		Status:            status,
		Domains:           domains,
		EnforceForDomains: req.EnforceForDomains,
		OIDC:              req.OIDC,
		SAML:              req.SAML,
		AttributeMapping:  req.AttributeMapping,
	}, baseURL)
	if err != nil {
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "enterprise_sso_connection_self_serve_created", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"connection_id":   connection.ID,
		"provider":        connection.Provider,
		"protocol":        connection.Protocol,
	})
	portal := s.portalSSOConnection(connection, baseURL)
	return &portal, nil
}

func (s *EnterpriseOnboardingService) UpdateSSOConnection(ctx context.Context, clientID, organizationID, actorUserID, connectionID string, req UpdateEnterpriseSSOConnectionRequest, baseURL, ip, ua string) (*EnterpriseSSOPortalConnection, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionEnterpriseWrite); err != nil {
		return nil, err
	}
	existing, err := s.sso.GetConnection(ctx, clientID, connectionID)
	if err != nil {
		return nil, err
	}
	if existing.OrganizationID != organizationID {
		return nil, domain.ErrNotFound
	}
	if req.Domains != nil {
		if err := s.requireVerifiedDomains(ctx, clientID, organizationID, domain.NormalizeSSODomains(req.Domains)); err != nil {
			return nil, err
		}
	}
	connection, err := s.ssoSvc.UpdateConnection(ctx, clientID, connectionID, req, baseURL)
	if err != nil {
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "enterprise_sso_connection_self_serve_updated", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"connection_id":   connection.ID,
		"provider":        connection.Provider,
		"status":          connection.Status,
	})
	portal := s.portalSSOConnection(connection, baseURL)
	return &portal, nil
}

func (s *EnterpriseOnboardingService) TestSSOSignIn(ctx context.Context, client *domain.Client, organizationID, actorUserID, connectionID, baseURL, ip, ua string) (string, error) {
	if _, err := s.requirePermission(ctx, client.ID, organizationID, actorUserID, domain.PermissionEnterpriseWrite); err != nil {
		return "", err
	}
	connection, err := s.sso.GetConnection(ctx, client.ID, connectionID)
	if err != nil {
		return "", err
	}
	if connection.OrganizationID != organizationID {
		return "", domain.ErrNotFound
	}
	redirectURL, err := s.ssoSvc.BeginLogin(ctx, client, BeginEnterpriseSSOLoginRequest{
		ConnectionID: connectionID,
		SessionMode:  "token",
	}, baseURL)
	if err != nil {
		return "", err
	}
	s.log(ctx, client.ID, &actorUserID, "enterprise_sso_test_sign_in_started", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"connection_id":   connectionID,
	})
	return redirectURL, nil
}

func (s *EnterpriseOnboardingService) ListSCIMDirectories(ctx context.Context, clientID, organizationID, actorUserID, baseURL string) ([]EnterpriseSCIMPortalDirectory, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionEnterpriseRead); err != nil {
		return nil, err
	}
	directories, err := s.scim.ListDirectoriesForOrganization(ctx, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	return s.portalSCIMDirectories(directories, baseURL), nil
}

func (s *EnterpriseOnboardingService) CreateSCIMDirectory(ctx context.Context, clientID, organizationID, actorUserID string, req CreateEnterpriseOnboardingSCIMRequest, baseURL, ip, ua string) (*EnterpriseSCIMDirectoryWithSetup, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionEnterpriseWrite); err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	domains := domain.NormalizeSSODomains(req.Domains)
	if err := s.requireVerifiedDomains(ctx, clientID, organizationID, domains); err != nil {
		return nil, err
	}
	token, err := GenerateToken(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	directory := &domain.SCIMDirectory{
		ID:             uuid.NewString(),
		ClientID:       clientID,
		OrganizationID: organizationID,
		Name:           name,
		Provider:       domain.NormalizeEnterpriseProvider(req.Provider, domain.SSOProtocolSAML),
		Status:         domain.SCIMDirectoryStatusActive,
		TokenHash:      HashToken(token),
		TokenPrefix:    tokenPrefix(token),
		Domains:        domains,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.scim.CreateDirectory(ctx, directory); err != nil {
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "enterprise_scim_directory_self_serve_created", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"directory_id":    directory.ID,
		"provider":        directory.Provider,
	})
	return &EnterpriseSCIMDirectoryWithSetup{
		Directory: directory,
		Token:     token,
		Health:    scimHealth(directory),
		Setup:     scimSetupHelper(directory, baseURL),
	}, nil
}

func (s *EnterpriseOnboardingService) UpdateSCIMDirectory(ctx context.Context, clientID, organizationID, actorUserID, directoryID string, req UpdateEnterpriseOnboardingSCIMRequest, baseURL, ip, ua string) (*EnterpriseSCIMDirectoryWithSetup, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionEnterpriseWrite); err != nil {
		return nil, err
	}
	directory, err := s.scim.GetDirectory(ctx, clientID, directoryID)
	if err != nil {
		return nil, err
	}
	if directory.OrganizationID != organizationID {
		return nil, domain.ErrNotFound
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			return nil, fmt.Errorf("name is required")
		}
		directory.Name = name
	}
	if req.Provider != nil {
		directory.Provider = domain.NormalizeEnterpriseProvider(*req.Provider, domain.SSOProtocolSAML)
	}
	if req.Status != nil {
		status := strings.ToLower(strings.TrimSpace(*req.Status))
		if status != domain.SCIMDirectoryStatusActive && status != domain.SCIMDirectoryStatusDisabled {
			return nil, domain.ErrInvalidSCIMResource
		}
		directory.Status = status
	}
	if req.Domains != nil {
		domains := domain.NormalizeSSODomains(req.Domains)
		if err := s.requireVerifiedDomains(ctx, clientID, organizationID, domains); err != nil {
			return nil, err
		}
		directory.Domains = domains
	}
	directory.UpdatedAt = time.Now().UTC()
	if err := s.scim.UpdateDirectory(ctx, directory); err != nil {
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "enterprise_scim_directory_self_serve_updated", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"directory_id":    directory.ID,
		"provider":        directory.Provider,
		"status":          directory.Status,
	})
	return &EnterpriseSCIMDirectoryWithSetup{
		Directory: directory,
		Health:    scimHealth(directory),
		Setup:     scimSetupHelper(directory, baseURL),
	}, nil
}

func (s *EnterpriseOnboardingService) RotateSCIMToken(ctx context.Context, clientID, organizationID, actorUserID, directoryID, baseURL, ip, ua string) (*EnterpriseSCIMDirectoryWithSetup, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionEnterpriseWrite); err != nil {
		return nil, err
	}
	directory, err := s.scim.GetDirectory(ctx, clientID, directoryID)
	if err != nil {
		return nil, err
	}
	if directory.OrganizationID != organizationID {
		return nil, domain.ErrNotFound
	}
	token, err := GenerateToken(32)
	if err != nil {
		return nil, err
	}
	directory.TokenHash = HashToken(token)
	directory.TokenPrefix = tokenPrefix(token)
	directory.UpdatedAt = time.Now().UTC()
	if err := s.scim.UpdateDirectory(ctx, directory); err != nil {
		return nil, err
	}
	s.log(ctx, clientID, &actorUserID, "enterprise_scim_directory_self_serve_token_rotated", ip, ua, map[string]interface{}{
		"organization_id": organizationID,
		"directory_id":    directory.ID,
	})
	return &EnterpriseSCIMDirectoryWithSetup{
		Directory: directory,
		Token:     token,
		Health:    scimHealth(directory),
		Setup:     scimSetupHelper(directory, baseURL),
	}, nil
}

func (s *EnterpriseOnboardingService) ListAuditEvents(ctx context.Context, clientID, organizationID, actorUserID string, limit int) ([]*domain.AuditEvent, error) {
	if _, err := s.requirePermission(ctx, clientID, organizationID, actorUserID, domain.PermissionEnterpriseAudit); err != nil {
		return nil, err
	}
	if s.audit == nil {
		return []*domain.AuditEvent{}, nil
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	connections, err := s.sso.ListConnectionsForOrganization(ctx, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	directories, err := s.scim.ListDirectoriesForOrganization(ctx, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	domains, err := s.domains.ListDomainVerifications(ctx, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	events, err := s.audit.List(ctx, domain.AuditEventFilter{ClientID: clientID, Limit: limit * 4})
	if err != nil {
		return nil, err
	}
	connectionIDs := map[string]struct{}{}
	for _, connection := range connections {
		connectionIDs[connection.ID] = struct{}{}
	}
	directoryIDs := map[string]struct{}{}
	for _, directory := range directories {
		directoryIDs[directory.ID] = struct{}{}
	}
	domainIDs := map[string]struct{}{}
	for _, verification := range domains {
		domainIDs[verification.ID] = struct{}{}
	}
	out := make([]*domain.AuditEvent, 0, limit)
	for _, event := range events {
		if enterpriseEventMatches(event, organizationID, connectionIDs, directoryIDs, domainIDs) {
			out = append(out, event)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *EnterpriseOnboardingService) requirePermission(ctx context.Context, clientID, organizationID, userID, permission string) (*domain.OrganizationMembership, error) {
	membership, err := s.orgs.GetMembership(ctx, clientID, organizationID, userID)
	if err != nil {
		return nil, err
	}
	if !domain.HasOrganizationPermission(membership, permission) {
		return nil, domain.ErrForbidden
	}
	return membership, nil
}

func (s *EnterpriseOnboardingService) requireVerifiedDomains(ctx context.Context, clientID, organizationID string, domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("at least one verified domain is required")
	}
	verified, err := s.verifiedDomainMap(ctx, clientID, organizationID)
	if err != nil {
		return err
	}
	for _, domainName := range domains {
		if _, ok := verified[domainName]; !ok {
			return fmt.Errorf("domain %s must be verified before it can be used for enterprise onboarding", domainName)
		}
	}
	return nil
}

func (s *EnterpriseOnboardingService) verifiedDomainMap(ctx context.Context, clientID, organizationID string) (map[string]struct{}, error) {
	verifications, err := s.domains.ListDomainVerifications(ctx, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	out := map[string]struct{}{}
	for _, verification := range verifications {
		if verification.Status == domain.EnterpriseDomainStatusVerified {
			out[verification.Domain] = struct{}{}
		}
	}
	return out, nil
}

func (s *EnterpriseOnboardingService) lookupDomainVerification(ctx context.Context, verification *domain.EnterpriseDomainVerification) (bool, string) {
	if s.resolver == nil {
		s.resolver = net.DefaultResolver
	}
	names := []string{verification.TXTName}
	if verification.Domain != verification.TXTName {
		names = append(names, verification.Domain)
	}
	errs := make([]string, 0, len(names))
	for _, name := range names {
		records, err := s.resolver.LookupTXT(ctx, name)
		if err != nil {
			errs = append(errs, name+": "+err.Error())
			continue
		}
		for _, record := range records {
			if normalizeTXTRecord(record) == normalizeTXTRecord(verification.TXTValue) {
				return true, ""
			}
		}
		errs = append(errs, name+": expected TXT value was not found")
	}
	return false, strings.Join(errs, "; ")
}

func (s *EnterpriseOnboardingService) portalSSOConnections(connections []*domain.EnterpriseSSOConnection, baseURL string) []EnterpriseSSOPortalConnection {
	out := make([]EnterpriseSSOPortalConnection, 0, len(connections))
	for _, connection := range connections {
		out = append(out, s.portalSSOConnection(connection, baseURL))
	}
	return out
}

func (s *EnterpriseOnboardingService) portalSSOConnection(connection *domain.EnterpriseSSOConnection, baseURL string) EnterpriseSSOPortalConnection {
	return EnterpriseSSOPortalConnection{
		Connection: sanitizePortalSSOConnection(connection),
		Health:     ssoHealth(connection, baseURL),
		Setup:      ssoSetupHelper(connection, baseURL),
	}
}

func (s *EnterpriseOnboardingService) portalSCIMDirectories(directories []*domain.SCIMDirectory, baseURL string) []EnterpriseSCIMPortalDirectory {
	out := make([]EnterpriseSCIMPortalDirectory, 0, len(directories))
	for _, directory := range directories {
		out = append(out, EnterpriseSCIMPortalDirectory{
			Directory: directory,
			Health:    scimHealth(directory),
			Setup:     scimSetupHelper(directory, baseURL),
		})
	}
	return out
}

func ssoHealth(connection *domain.EnterpriseSSOConnection, baseURL string) domain.EnterpriseConnectionHealth {
	warnings := ssoWarnings(connection)
	status := "healthy"
	if connection.Status != domain.SSOConnectionStatusActive {
		status = "inactive"
	}
	if connection.LastError != "" || hasAttentionWarning(warnings) {
		status = "attention"
	}
	return domain.EnterpriseConnectionHealth{
		Status:        status,
		LastLoginAt:   connection.LastLoginAt,
		LastErrorAt:   connection.LastErrorAt,
		LastError:     connection.LastError,
		Warnings:      warnings,
		TestSignInURL: strings.TrimRight(baseURL, "/") + "/api/auth/sso/" + connection.ID + "?session_mode=token",
	}
}

func scimHealth(directory *domain.SCIMDirectory) domain.EnterpriseConnectionHealth {
	status := "healthy"
	if directory.Status != domain.SCIMDirectoryStatusActive {
		status = "inactive"
	}
	if directory.LastError != "" {
		status = "attention"
	}
	return domain.EnterpriseConnectionHealth{
		Status:      status,
		LastSyncAt:  directory.LastSyncAt,
		LastErrorAt: directory.LastErrorAt,
		LastError:   directory.LastError,
	}
}

func ssoWarnings(connection *domain.EnterpriseSSOConnection) []domain.EnterpriseConnectionWarning {
	if connection.Protocol != domain.SSOProtocolSAML {
		return nil
	}
	warnings := []domain.EnterpriseConnectionWarning{}
	if strings.TrimSpace(connection.SAML.IDPCertificate) == "" && connection.Status == domain.SSOConnectionStatusActive {
		warnings = append(warnings, domain.EnterpriseConnectionWarning{
			Code:    "saml_certificate_missing",
			Level:   "critical",
			Message: "SAML signing certificate is missing.",
		})
	}
	if expiry, err := samlCertificateExpiry(connection.SAML.IDPCertificate); err == nil && expiry != nil {
		now := time.Now().UTC()
		switch {
		case expiry.Before(now):
			warnings = append(warnings, domain.EnterpriseConnectionWarning{
				Code:     "saml_certificate_expired",
				Level:    "critical",
				Message:  "SAML signing certificate has expired.",
				Deadline: expiry.Format(time.RFC3339),
			})
		case expiry.Before(now.Add(30 * 24 * time.Hour)):
			warnings = append(warnings, domain.EnterpriseConnectionWarning{
				Code:     "saml_certificate_expiring",
				Level:    "warning",
				Message:  "SAML signing certificate expires soon.",
				Deadline: expiry.Format(time.RFC3339),
			})
		}
	}
	if connection.SAML.IDPMetadataXML != "" {
		if connection.MetadataRefreshedAt == nil {
			warnings = append(warnings, domain.EnterpriseConnectionWarning{
				Code:    "metadata_refresh_unknown",
				Level:   "warning",
				Message: "IdP metadata has no recorded refresh time.",
			})
		} else if connection.MetadataRefreshedAt.Before(time.Now().UTC().Add(-30 * 24 * time.Hour)) {
			warnings = append(warnings, domain.EnterpriseConnectionWarning{
				Code:    "metadata_refresh_stale",
				Level:   "warning",
				Message: "IdP metadata has not been refreshed in the last 30 days.",
				Detail:  "Upload fresh metadata XML or verify the current certificate and SSO URL.",
			})
		}
	} else if connection.Status == domain.SSOConnectionStatusActive {
		warnings = append(warnings, domain.EnterpriseConnectionWarning{
			Code:    "metadata_manual",
			Level:   "info",
			Message: "IdP metadata was configured manually.",
			Detail:  "Recheck the SSO URL and signing certificate before certificate rotation windows.",
		})
	}
	return warnings
}

func ssoSetupHelper(connection *domain.EnterpriseSSOConnection, baseURL string) domain.EnterpriseSetupHelper {
	provider := domain.NormalizeEnterpriseProvider(connection.Provider, connection.Protocol)
	helper := domain.EnterpriseSetupHelper{
		Provider: provider,
		Protocol: connection.Protocol,
	}
	if connection.Protocol == domain.SSOProtocolSAML {
		helper.ACSURL = connection.SAML.ACSURL
		helper.SPEntityID = connection.SAML.SPEntityID
		helper.SPMetadataURL = connection.SAML.SPMetadataURL
		helper.Instructions = providerInstructions(provider, domain.SSOProtocolSAML)
	} else {
		helper.OIDCRedirectURI = callbackURL(baseURL, connection.ID)
		helper.Instructions = providerInstructions(provider, domain.SSOProtocolOIDC)
	}
	return helper
}

func scimSetupHelper(directory *domain.SCIMDirectory, baseURL string) domain.EnterpriseSetupHelper {
	provider := domain.NormalizeEnterpriseProvider(directory.Provider, domain.SSOProtocolSAML)
	return domain.EnterpriseSetupHelper{
		Provider:     provider,
		Protocol:     "scim",
		SCIMBaseURL:  strings.TrimRight(baseURL, "/") + "/scim/v2/" + directory.ID,
		Instructions: providerInstructions(provider, "scim"),
	}
}

func EnterpriseProviderGuides() []domain.EnterpriseProviderGuide {
	return []domain.EnterpriseProviderGuide{
		{
			Provider:          domain.EnterpriseProviderOkta,
			DisplayName:       "Okta",
			Protocols:         []string{domain.SSOProtocolSAML, domain.SSOProtocolOIDC, "scim"},
			DocumentationURL:  "https://support.okta.com/help/s/article/How-To-Configure-A-Custom-SAML-App?language=en_US",
			SCIMDocumentation: "https://developer.okta.com/docs/guides/scim-provisioning-integration-prepare/-/main/",
			SAMLInstructions:  providerInstructions(domain.EnterpriseProviderOkta, domain.SSOProtocolSAML),
			OIDCInstructions:  providerInstructions(domain.EnterpriseProviderOkta, domain.SSOProtocolOIDC),
			SCIMInstructions:  providerInstructions(domain.EnterpriseProviderOkta, "scim"),
		},
		{
			Provider:          domain.EnterpriseProviderMicrosoftEntra,
			DisplayName:       "Microsoft Entra ID",
			Protocols:         []string{domain.SSOProtocolSAML, domain.SSOProtocolOIDC, "scim"},
			DocumentationURL:  "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/add-application-portal-setup-sso",
			SCIMDocumentation: "https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups",
			SAMLInstructions:  providerInstructions(domain.EnterpriseProviderMicrosoftEntra, domain.SSOProtocolSAML),
			OIDCInstructions:  providerInstructions(domain.EnterpriseProviderMicrosoftEntra, domain.SSOProtocolOIDC),
			SCIMInstructions:  providerInstructions(domain.EnterpriseProviderMicrosoftEntra, "scim"),
		},
		{
			Provider:         domain.EnterpriseProviderGoogleWorkspace,
			DisplayName:      "Google Workspace",
			Protocols:        []string{domain.SSOProtocolSAML, "scim"},
			DocumentationURL: "https://support.google.com/a/answer/6087519?hl=en-EN",
			SAMLInstructions: providerInstructions(domain.EnterpriseProviderGoogleWorkspace, domain.SSOProtocolSAML),
			SCIMInstructions: providerInstructions(domain.EnterpriseProviderGoogleWorkspace, "scim"),
		},
		{
			Provider:         domain.EnterpriseProviderPing,
			DisplayName:      "Ping Identity",
			Protocols:        []string{domain.SSOProtocolSAML, domain.SSOProtocolOIDC, "scim"},
			SAMLInstructions: providerInstructions(domain.EnterpriseProviderPing, domain.SSOProtocolSAML),
			OIDCInstructions: providerInstructions(domain.EnterpriseProviderPing, domain.SSOProtocolOIDC),
			SCIMInstructions: providerInstructions(domain.EnterpriseProviderPing, "scim"),
		},
		{
			Provider:          domain.EnterpriseProviderOneLogin,
			DisplayName:       "OneLogin",
			Protocols:         []string{domain.SSOProtocolSAML, domain.SSOProtocolOIDC, "scim"},
			DocumentationURL:  "https://developers.onelogin.com/saml",
			SCIMDocumentation: "https://developers.onelogin.com/scim",
			SAMLInstructions:  providerInstructions(domain.EnterpriseProviderOneLogin, domain.SSOProtocolSAML),
			OIDCInstructions:  providerInstructions(domain.EnterpriseProviderOneLogin, domain.SSOProtocolOIDC),
			SCIMInstructions:  providerInstructions(domain.EnterpriseProviderOneLogin, "scim"),
		},
		{
			Provider:         domain.EnterpriseProviderGenericSAML,
			DisplayName:      "Generic SAML",
			Protocols:        []string{domain.SSOProtocolSAML, "scim"},
			SAMLInstructions: providerInstructions(domain.EnterpriseProviderGenericSAML, domain.SSOProtocolSAML),
			SCIMInstructions: providerInstructions(domain.EnterpriseProviderGenericSAML, "scim"),
		},
		{
			Provider:         domain.EnterpriseProviderGenericOIDC,
			DisplayName:      "Generic OIDC",
			Protocols:        []string{domain.SSOProtocolOIDC},
			OIDCInstructions: providerInstructions(domain.EnterpriseProviderGenericOIDC, domain.SSOProtocolOIDC),
		},
	}
}

func providerInstructions(provider, protocol string) []string {
	switch protocol {
	case domain.SSOProtocolSAML:
		switch provider {
		case domain.EnterpriseProviderMicrosoftEntra:
			return []string{"Create or open an Enterprise Application in Microsoft Entra ID.", "Choose SAML single sign-on and paste the Reply URL / ACS URL and Identifier / Entity ID from this portal.", "Download the SAML signing certificate or metadata XML and paste it back into this portal.", "Assign users or groups, then run test sign-in."}
		case domain.EnterpriseProviderGoogleWorkspace:
			return []string{"In Google Admin Console, add a custom SAML app.", "Copy the SSO URL, Entity ID, and certificate from Google.", "Paste this portal's ACS URL and Entity ID into the Service Provider details.", "Map primary email as Name ID, assign the app, then run test sign-in."}
		default:
			return []string{"Create a SAML 2.0 application in the identity provider.", "Paste the ACS URL and SP Entity ID from this portal.", "Copy the IdP SSO URL, IdP Entity ID, and X.509 signing certificate or metadata XML back into this portal.", "Assign users or groups, activate the connection, then run test sign-in."}
		}
	case domain.SSOProtocolOIDC:
		return []string{"Create an OIDC web application in the identity provider.", "Add this portal's redirect URI to the allowed callback URLs.", "Copy the issuer URL, client ID, and client secret back into this portal.", "Enable openid, email, and profile scopes, activate the connection, then run test sign-in."}
	case "scim":
		switch provider {
		case domain.EnterpriseProviderMicrosoftEntra:
			return []string{"Open Provisioning for the Enterprise Application in Microsoft Entra ID.", "Set Tenant URL to the SCIM base URL from this portal.", "Paste the SCIM bearer token into Secret Token.", "Test the connection, then enable user and group provisioning."}
		case domain.EnterpriseProviderOkta:
			return []string{"Open the app's Provisioning settings in Okta.", "Set SCIM version to 2.0 and paste the SCIM base URL from this portal.", "Use HTTP Header or Bearer token authentication with the token from this portal.", "Test connector configuration, then enable create, update, and deactivate users."}
		default:
			return []string{"Open the provider's SCIM or user provisioning settings.", "Paste the SCIM base URL from this portal.", "Use Bearer token authentication with the token shown once in this portal.", "Send a test user, then enable user and group sync."}
		}
	default:
		return nil
	}
}

func samlCertificateExpiry(value string) (*time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	var raw []byte
	if strings.Contains(value, "BEGIN CERTIFICATE") {
		block, _ := pem.Decode([]byte(value))
		if block == nil {
			return nil, fmt.Errorf("invalid certificate")
		}
		raw = block.Bytes
	} else {
		decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value), ""))
		if err != nil {
			return nil, err
		}
		raw = decoded
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}
	expiry := cert.NotAfter.UTC()
	return &expiry, nil
}

func sanitizePortalSSOConnection(connection *domain.EnterpriseSSOConnection) *domain.EnterpriseSSOConnection {
	if connection == nil {
		return nil
	}
	clone := *connection
	clone.Domains = append([]string(nil), connection.Domains...)
	clone.AttributeMapping = map[string]string{}
	for key, value := range connection.AttributeMapping {
		clone.AttributeMapping[key] = value
	}
	clone.OIDC.ClientSecret = ""
	clone.SAML.SPPrivateKeyPEM = ""
	return &clone
}

func hasAttentionWarning(warnings []domain.EnterpriseConnectionWarning) bool {
	for _, warning := range warnings {
		if warning.Level == "critical" || warning.Level == "warning" {
			return true
		}
	}
	return false
}

func enterpriseEventMatches(event *domain.AuditEvent, organizationID string, connectionIDs, directoryIDs, domainIDs map[string]struct{}) bool {
	if event == nil {
		return false
	}
	if metadataValue(event.Metadata, "organization_id") == organizationID {
		return true
	}
	if _, ok := connectionIDs[metadataValue(event.Metadata, "connection_id")]; ok {
		return true
	}
	if _, ok := directoryIDs[metadataValue(event.Metadata, "directory_id")]; ok {
		return true
	}
	if _, ok := domainIDs[metadataValue(event.Metadata, "domain_id")]; ok {
		return true
	}
	return false
}

func metadataValue(metadata map[string]interface{}, key string) string {
	if metadata == nil {
		return ""
	}
	value, ok := metadata[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func normalizeTXTRecord(value string) string {
	return strings.Trim(strings.TrimSpace(value), `"`)
}

func (s *EnterpriseOnboardingService) log(ctx context.Context, clientID string, userID *string, eventType, ip, ua string, metadata map[string]interface{}) {
	if s.audit != nil {
		s.audit.Log(ctx, clientID, userID, eventType, ip, ua, metadata)
	}
}
