package application

import (
	"context"
	"encoding/json"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
)

const scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
const scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"

type SCIMService struct {
	scim  SCIMRepository
	users UserRepository
	audit AuditRepository
}

func NewSCIMService(scim SCIMRepository, users UserRepository, audit AuditRepository) *SCIMService {
	return &SCIMService{scim: scim, users: users, audit: audit}
}

type CreateSCIMDirectoryRequest struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

type UpdateSCIMDirectoryRequest struct {
	Name    *string  `json:"name,omitempty"`
	Status  *string  `json:"status,omitempty"`
	Domains []string `json:"domains,omitempty"`
}

type SCIMUserResource struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Active      bool        `json:"active"`
	Name        SCIMName    `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []SCIMEmail `json:"emails,omitempty"`
	Meta        SCIMMeta    `json:"meta,omitempty"`
}

type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type SCIMGroupResource struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id,omitempty"`
	ExternalID  string       `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName"`
	Members     []SCIMMember `json:"members,omitempty"`
	Meta        SCIMMeta     `json:"meta,omitempty"`
}

type SCIMMember struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
}

type SCIMMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
	Location     string    `json:"location,omitempty"`
}

type SCIMListResponse struct {
	Schemas      []string      `json:"schemas"`
	TotalResults int           `json:"totalResults"`
	StartIndex   int           `json:"startIndex"`
	ItemsPerPage int           `json:"itemsPerPage"`
	Resources    []interface{} `json:"Resources"`
}

type SCIMPatchRequest struct {
	Schemas    []string        `json:"schemas,omitempty"`
	Operations []SCIMOperation `json:"Operations"`
}

type SCIMOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value,omitempty"`
}

func (s *SCIMService) CreateDirectory(ctx context.Context, clientID string, req CreateSCIMDirectoryRequest) (*domain.SCIMDirectoryWithToken, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	token, err := GenerateToken(32)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	directory := &domain.SCIMDirectory{
		ID:          uuid.NewString(),
		ClientID:    clientID,
		Name:        name,
		Status:      domain.SCIMDirectoryStatusActive,
		TokenHash:   HashToken(token),
		TokenPrefix: tokenPrefix(token),
		Domains:     domain.NormalizeSSODomains(req.Domains),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.scim.CreateDirectory(ctx, directory); err != nil {
		return nil, err
	}
	if s.audit != nil {
		s.audit.Log(ctx, clientID, nil, "scim_directory_created", "", "", map[string]interface{}{"directory_id": directory.ID})
	}
	return &domain.SCIMDirectoryWithToken{Directory: directory, Token: token}, nil
}

func (s *SCIMService) ListDirectories(ctx context.Context, clientID string) ([]*domain.SCIMDirectory, error) {
	return s.scim.ListDirectories(ctx, clientID)
}

func (s *SCIMService) GetDirectory(ctx context.Context, clientID, directoryID string) (*domain.SCIMDirectory, error) {
	return s.scim.GetDirectory(ctx, clientID, directoryID)
}

func (s *SCIMService) UpdateDirectory(ctx context.Context, clientID, directoryID string, req UpdateSCIMDirectoryRequest) (*domain.SCIMDirectory, error) {
	directory, err := s.scim.GetDirectory(ctx, clientID, directoryID)
	if err != nil {
		return nil, err
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			return nil, fmt.Errorf("name is required")
		}
		directory.Name = name
	}
	if req.Status != nil {
		status := strings.ToLower(strings.TrimSpace(*req.Status))
		if status != domain.SCIMDirectoryStatusActive && status != domain.SCIMDirectoryStatusDisabled {
			return nil, domain.ErrInvalidSCIMResource
		}
		directory.Status = status
	}
	if req.Domains != nil {
		directory.Domains = domain.NormalizeSSODomains(req.Domains)
	}
	directory.UpdatedAt = time.Now().UTC()
	if err := s.scim.UpdateDirectory(ctx, directory); err != nil {
		return nil, err
	}
	return directory, nil
}

func (s *SCIMService) RotateDirectoryToken(ctx context.Context, clientID, directoryID string) (*domain.SCIMDirectoryWithToken, error) {
	directory, err := s.scim.GetDirectory(ctx, clientID, directoryID)
	if err != nil {
		return nil, err
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
	if s.audit != nil {
		s.audit.Log(ctx, clientID, nil, "scim_directory_token_rotated", "", "", map[string]interface{}{"directory_id": directory.ID})
	}
	return &domain.SCIMDirectoryWithToken{Directory: directory, Token: token}, nil
}

func (s *SCIMService) AuthenticateDirectory(ctx context.Context, directoryID, token string) (*domain.SCIMDirectory, error) {
	directory, err := s.scim.GetDirectoryByTokenHash(ctx, HashToken(token))
	if err != nil || directory == nil || directory.ID != directoryID || directory.Status != domain.SCIMDirectoryStatusActive {
		return nil, domain.ErrInvalidSCIMToken
	}
	return directory, nil
}

func (s *SCIMService) ListUsers(ctx context.Context, directory *domain.SCIMDirectory, baseURL string) (*SCIMListResponse, error) {
	users, err := s.scim.ListUsers(ctx, directory.ClientID, directory.ID)
	if err != nil {
		return nil, err
	}
	resources := make([]interface{}, 0, len(users))
	for _, scimUser := range users {
		user, err := s.users.GetByID(ctx, scimUser.UserID)
		if err != nil {
			continue
		}
		resources = append(resources, scimUserResource(scimUser, user, baseURL))
	}
	return scimList(resources), nil
}

func (s *SCIMService) GetUser(ctx context.Context, directory *domain.SCIMDirectory, scimUserID, baseURL string) (*SCIMUserResource, error) {
	scimUser, err := s.scim.GetUser(ctx, directory.ClientID, directory.ID, scimUserID)
	if err != nil {
		return nil, err
	}
	user, err := s.users.GetByID(ctx, scimUser.UserID)
	if err != nil {
		return nil, err
	}
	resource := scimUserResource(scimUser, user, baseURL)
	return &resource, nil
}

func (s *SCIMService) UpsertUser(ctx context.Context, directory *domain.SCIMDirectory, req SCIMUserResource, baseURL string) (*SCIMUserResource, error) {
	email := scimPrimaryEmail(req)
	if email == "" {
		return nil, domain.ErrInvalidSCIMResource
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, domain.ErrInvalidSCIMResource
	}
	if !domain.SSODomainAllowed(email, directory.Domains) {
		return nil, domain.ErrSSODomainNotAllowed
	}
	externalID := strings.TrimSpace(req.ExternalID)
	if externalID == "" {
		externalID = email
	}
	active := req.Active
	if req.Schemas == nil {
		active = true
	}

	existing, err := s.scim.GetUserByExternalID(ctx, directory.ClientID, directory.ID, externalID)
	if err != nil && err != domain.ErrNotFound {
		return nil, err
	}

	var user *domain.User
	if existing != nil {
		user, err = s.users.GetByID(ctx, existing.UserID)
		if err != nil {
			return nil, err
		}
	} else {
		user, _ = s.users.GetByEmail(ctx, directory.ClientID, email)
		if user == nil {
			displayName := scimDisplayName(req)
			if displayName == "" {
				displayName = strings.Split(email, "@")[0]
			}
			user, err = s.users.CreateOAuth(ctx, directory.ClientID, email, displayName, "")
			if err != nil {
				return nil, err
			}
			if s.audit != nil {
				uid := user.ID
				s.audit.Log(ctx, directory.ClientID, &uid, "signup", "", "", map[string]interface{}{"method": "scim", "directory_id": directory.ID})
			}
		}
	}

	displayName := scimDisplayName(req)
	if displayName != "" {
		_ = s.users.UpdateProfile(ctx, user.ID, displayName, user.Timezone)
		user.DisplayName = displayName
	}
	status := "active"
	if !active {
		status = "suspended"
	}
	_ = s.users.UpdateStatus(ctx, user.ID, status)
	user.Status = status

	now := time.Now().UTC()
	raw, _ := json.Marshal(req)
	scimUser := &domain.SCIMUser{
		ID:          uuid.NewString(),
		ClientID:    directory.ClientID,
		DirectoryID: directory.ID,
		UserID:      user.ID,
		ExternalID:  externalID,
		UserName:    email,
		Active:      active,
		RawResource: raw,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if existing != nil {
		scimUser.ID = existing.ID
		scimUser.CreatedAt = existing.CreatedAt
	}
	if err := s.scim.UpsertUser(ctx, scimUser); err != nil {
		return nil, err
	}
	if s.audit != nil {
		uid := user.ID
		s.audit.Log(ctx, directory.ClientID, &uid, "scim_user_provisioned", "", "", map[string]interface{}{"directory_id": directory.ID, "active": active})
	}
	resource := scimUserResource(scimUser, user, baseURL)
	return &resource, nil
}

func (s *SCIMService) PatchUser(ctx context.Context, directory *domain.SCIMDirectory, scimUserID string, req SCIMPatchRequest, baseURL string) (*SCIMUserResource, error) {
	current, err := s.GetUser(ctx, directory, scimUserID, baseURL)
	if err != nil {
		return nil, err
	}
	for _, op := range req.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		applySCIMUserPatch(current, op)
	}
	return s.UpsertUser(ctx, directory, *current, baseURL)
}

func (s *SCIMService) DeleteUser(ctx context.Context, directory *domain.SCIMDirectory, scimUserID string) error {
	scimUser, err := s.scim.GetUser(ctx, directory.ClientID, directory.ID, scimUserID)
	if err != nil {
		return err
	}
	_ = s.users.UpdateStatus(ctx, scimUser.UserID, "suspended")
	if err := s.scim.DeleteUser(ctx, directory.ClientID, directory.ID, scimUserID); err != nil {
		return err
	}
	if s.audit != nil {
		uid := scimUser.UserID
		s.audit.Log(ctx, directory.ClientID, &uid, "scim_user_deprovisioned", "", "", map[string]interface{}{"directory_id": directory.ID})
	}
	return nil
}

func (s *SCIMService) ListGroups(ctx context.Context, directory *domain.SCIMDirectory, baseURL string) (*SCIMListResponse, error) {
	groups, err := s.scim.ListGroups(ctx, directory.ClientID, directory.ID)
	if err != nil {
		return nil, err
	}
	resources := make([]interface{}, 0, len(groups))
	for _, group := range groups {
		resources = append(resources, scimGroupResource(group, baseURL))
	}
	return scimList(resources), nil
}

func (s *SCIMService) GetGroup(ctx context.Context, directory *domain.SCIMDirectory, groupID, baseURL string) (*SCIMGroupResource, error) {
	group, err := s.scim.GetGroup(ctx, directory.ClientID, directory.ID, groupID)
	if err != nil {
		return nil, err
	}
	resource := scimGroupResource(group, baseURL)
	return &resource, nil
}

func (s *SCIMService) UpsertGroup(ctx context.Context, directory *domain.SCIMDirectory, req SCIMGroupResource, baseURL string) (*SCIMGroupResource, error) {
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		return nil, domain.ErrInvalidSCIMResource
	}
	externalID := strings.TrimSpace(req.ExternalID)
	if externalID == "" {
		externalID = displayName
	}
	existing, err := s.scim.GetGroupByExternalID(ctx, directory.ClientID, directory.ID, externalID)
	if err != nil && err != domain.ErrNotFound {
		return nil, err
	}
	now := time.Now().UTC()
	raw, _ := json.Marshal(req)
	group := &domain.SCIMGroup{
		ID:          uuid.NewString(),
		ClientID:    directory.ClientID,
		DirectoryID: directory.ID,
		ExternalID:  externalID,
		DisplayName: displayName,
		Members:     scimMemberValues(req.Members),
		RawResource: raw,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if existing != nil {
		group.ID = existing.ID
		group.CreatedAt = existing.CreatedAt
	}
	if err := s.scim.UpsertGroup(ctx, group); err != nil {
		return nil, err
	}
	if s.audit != nil {
		s.audit.Log(ctx, directory.ClientID, nil, "scim_group_synced", "", "", map[string]interface{}{"directory_id": directory.ID, "group_id": group.ID})
	}
	resource := scimGroupResource(group, baseURL)
	return &resource, nil
}

func (s *SCIMService) PatchGroup(ctx context.Context, directory *domain.SCIMDirectory, groupID string, req SCIMPatchRequest, baseURL string) (*SCIMGroupResource, error) {
	current, err := s.GetGroup(ctx, directory, groupID, baseURL)
	if err != nil {
		return nil, err
	}
	for _, op := range req.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		applySCIMGroupPatch(current, op)
	}
	return s.UpsertGroup(ctx, directory, *current, baseURL)
}

func (s *SCIMService) DeleteGroup(ctx context.Context, directory *domain.SCIMDirectory, groupID string) error {
	return s.scim.DeleteGroup(ctx, directory.ClientID, directory.ID, groupID)
}

func scimPrimaryEmail(req SCIMUserResource) string {
	if req.UserName != "" {
		return strings.ToLower(strings.TrimSpace(req.UserName))
	}
	for _, email := range req.Emails {
		if email.Primary && email.Value != "" {
			return strings.ToLower(strings.TrimSpace(email.Value))
		}
	}
	if len(req.Emails) > 0 {
		return strings.ToLower(strings.TrimSpace(req.Emails[0].Value))
	}
	return ""
}

func scimDisplayName(req SCIMUserResource) string {
	return firstNonEmpty(req.DisplayName, req.Name.Formatted, strings.TrimSpace(req.Name.GivenName+" "+req.Name.FamilyName))
}

func scimUserResource(scimUser *domain.SCIMUser, user *domain.User, baseURL string) SCIMUserResource {
	active := scimUser.Active && user.Status == "active"
	displayName := user.DisplayName
	return SCIMUserResource{
		Schemas:     []string{scimUserSchema},
		ID:          scimUser.ID,
		ExternalID:  scimUser.ExternalID,
		UserName:    scimUser.UserName,
		Active:      active,
		DisplayName: displayName,
		Name: SCIMName{
			Formatted: displayName,
		},
		Emails: []SCIMEmail{{
			Value:   user.Email,
			Type:    "work",
			Primary: true,
		}},
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      scimUser.CreatedAt,
			LastModified: scimUser.UpdatedAt,
			Location:     strings.TrimRight(baseURL, "/") + "/scim/v2/" + scimUser.DirectoryID + "/Users/" + scimUser.ID,
		},
	}
}

func scimGroupResource(group *domain.SCIMGroup, baseURL string) SCIMGroupResource {
	members := make([]SCIMMember, 0, len(group.Members))
	for _, member := range group.Members {
		members = append(members, SCIMMember{
			Value: member,
			Ref:   strings.TrimRight(baseURL, "/") + "/scim/v2/" + group.DirectoryID + "/Users/" + member,
		})
	}
	return SCIMGroupResource{
		Schemas:     []string{scimGroupSchema},
		ID:          group.ID,
		ExternalID:  group.ExternalID,
		DisplayName: group.DisplayName,
		Members:     members,
		Meta: SCIMMeta{
			ResourceType: "Group",
			Created:      group.CreatedAt,
			LastModified: group.UpdatedAt,
			Location:     strings.TrimRight(baseURL, "/") + "/scim/v2/" + group.DirectoryID + "/Groups/" + group.ID,
		},
	}
}

func scimList(resources []interface{}) *SCIMListResponse {
	return &SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: len(resources),
		StartIndex:   1,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}
}

func applySCIMUserPatch(user *SCIMUserResource, op SCIMOperation) {
	path := strings.ToLower(strings.TrimSpace(op.Path))
	if path == "" {
		if values, ok := op.Value.(map[string]interface{}); ok {
			for key, value := range values {
				applySCIMUserPatch(user, SCIMOperation{Path: key, Value: value})
			}
		}
		return
	}
	switch path {
	case "active":
		if value, ok := op.Value.(bool); ok {
			user.Active = value
		}
	case "username", "userName":
		if value, ok := op.Value.(string); ok {
			user.UserName = value
		}
	case "displayname", "displayName":
		if value, ok := op.Value.(string); ok {
			user.DisplayName = value
			user.Name.Formatted = value
		}
	}
}

func applySCIMGroupPatch(group *SCIMGroupResource, op SCIMOperation) {
	path := strings.ToLower(strings.TrimSpace(op.Path))
	switch path {
	case "displayname", "displayName":
		if value, ok := op.Value.(string); ok {
			group.DisplayName = value
		}
	case "members":
		raw, _ := json.Marshal(op.Value)
		var members []SCIMMember
		if json.Unmarshal(raw, &members) == nil {
			group.Members = members
		}
	}
}

func scimMemberValues(members []SCIMMember) []string {
	out := make([]string, 0, len(members))
	for _, member := range members {
		if strings.TrimSpace(member.Value) != "" {
			out = append(out, strings.TrimSpace(member.Value))
		}
	}
	return out
}

func tokenPrefix(token string) string {
	if len(token) <= 12 {
		return token
	}
	return token[:12]
}
