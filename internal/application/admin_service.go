package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultAdminAccessTTL        = 8 * time.Hour
	defaultBreakGlassRateLimit   = int64(10)
	defaultBreakGlassRateWindow  = time.Minute
	adminTokenIssuer             = "authservice-admin"
	AdminPermissionAll           = "*"
	AdminPermissionClientsCreate = "clients:create"
	AdminPermissionClientsRead   = "clients:read"
	AdminPermissionClientsUpdate = "clients:update"
	AdminPermissionClientsRotate = "clients:rotate_secrets"
	AdminPermissionAuditRead     = "audit:read"
	AdminPermissionAdminsRead    = "admins:read"
	AdminPermissionAdminsManage  = "admins:manage"
	AdminPermissionM2MRead       = "service_accounts:read"
	AdminPermissionM2MManage     = "service_accounts:manage"
	AdminPermissionSSORead       = "sso:read"
	AdminPermissionSSOManage     = "sso:manage"
	AdminPermissionSCIMRead      = "scim:read"
	AdminPermissionSCIMManage    = "scim:manage"
)

type AdminUserRepository interface {
	Create(ctx context.Context, admin *domain.AdminUser) error
	GetByID(ctx context.Context, id string) (*domain.AdminUser, error)
	GetByEmail(ctx context.Context, email string) (*domain.AdminUser, error)
	GetBySSOIdentity(ctx context.Context, provider, subject string) (*domain.AdminUser, error)
	List(ctx context.Context) ([]*domain.AdminUser, error)
	UpdateLastLogin(ctx context.Context, id string, at time.Time) error
}

type AdminAuditRepository interface {
	LogAdmin(ctx context.Context, event *domain.AuditEvent)
}

type AdminService struct {
	admins      AdminUserRepository
	audit       AdminAuditRepository
	rl          RateLimiter
	tokenSecret []byte
	accessTTL   time.Duration
}

func NewAdminService(admins AdminUserRepository, audit AdminAuditRepository, rl RateLimiter, tokenSecret string, accessTTL time.Duration) *AdminService {
	if accessTTL <= 0 {
		accessTTL = defaultAdminAccessTTL
	}
	tokenSecret = strings.TrimSpace(tokenSecret)
	return &AdminService{
		admins:      admins,
		audit:       audit,
		rl:          rl,
		tokenSecret: []byte(tokenSecret),
		accessTTL:   accessTTL,
	}
}

type CreateAdminUserRequest struct {
	Email               string   `json:"email"`
	DisplayName         string   `json:"display_name"`
	Password            string   `json:"password"`
	Roles               []string `json:"roles"`
	ScopeType           string   `json:"scope_type"`
	ScopeClientID       string   `json:"scope_client_id"`
	ScopeOrganizationID string   `json:"scope_organization_id"`
	MFARequired         *bool    `json:"mfa_required"`
	TOTPSecret          string   `json:"totp_secret"`
	TOTPEnabled         bool     `json:"totp_enabled"`
	SSOProvider         string   `json:"sso_provider"`
	SSOSubject          string   `json:"sso_subject"`
	Status              string   `json:"status"`
}

type AdminUserResponse struct {
	*domain.AdminUser
	TOTPSecret     string `json:"totp_secret,omitempty"`
	TOTPAuthURL    string `json:"totp_auth_url,omitempty"`
	TemporarySetup bool   `json:"temporary_setup,omitempty"`
}

type AdminLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

type AdminSSOLoginRequest struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

type AdminAuthResponse struct {
	AccessToken string            `json:"access_token,omitempty"`
	TokenType   string            `json:"token_type,omitempty"`
	ExpiresAt   time.Time         `json:"expires_at,omitempty"`
	Admin       *domain.AdminUser `json:"admin,omitempty"`
	MFARequired bool              `json:"mfa_required,omitempty"`
	Error       string            `json:"error,omitempty"`
}

type AdminAccessClaims struct {
	AdminUserID         string   `json:"admin_user_id"`
	Email               string   `json:"email"`
	Roles               []string `json:"roles"`
	ScopeType           string   `json:"scope_type"`
	ScopeClientID       string   `json:"scope_client_id,omitempty"`
	ScopeOrganizationID string   `json:"scope_organization_id,omitempty"`
	jwt.RegisteredClaims
}

func (s *AdminService) CreateAdminUser(ctx context.Context, req CreateAdminUserRequest) (*AdminUserResponse, error) {
	if s == nil || s.admins == nil {
		return nil, domain.ErrNotFound
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if strings.TrimSpace(req.Password) == "" && strings.TrimSpace(req.SSOProvider) == "" {
		return nil, fmt.Errorf("password or sso identity is required")
	}
	roles, err := normalizeAdminRoles(req.Roles)
	if err != nil {
		return nil, err
	}
	scopeType, scopeClientID, scopeOrgID, err := normalizeAdminScope(req.ScopeType, req.ScopeClientID, req.ScopeOrganizationID)
	if err != nil {
		return nil, err
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if status == "" {
		status = "active"
	}
	if status != "active" && status != "suspended" {
		return nil, fmt.Errorf("status must be active or suspended")
	}

	passwordHash := ""
	if strings.TrimSpace(req.Password) != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		passwordHash = string(hash)
	}

	mfaRequired := true
	if req.MFARequired != nil {
		mfaRequired = *req.MFARequired
	}
	totpSecret := strings.TrimSpace(req.TOTPSecret)
	totpAuthURL := ""
	temporarySetup := false
	if mfaRequired && req.TOTPEnabled && totpSecret == "" {
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "AuthService Admin",
			AccountName: email,
			Period:      30,
			SecretSize:  20,
			Digits:      otp.DigitsSix,
			Algorithm:   otp.AlgorithmSHA1,
		})
		if err != nil {
			return nil, err
		}
		totpSecret = key.Secret()
		totpAuthURL = key.URL()
		temporarySetup = true
	}

	now := time.Now().UTC()
	admin := &domain.AdminUser{
		ID:                  uuid.New().String(),
		Email:               email,
		DisplayName:         strings.TrimSpace(req.DisplayName),
		PasswordHash:        passwordHash,
		Roles:               roles,
		ScopeType:           scopeType,
		ScopeClientID:       scopeClientID,
		ScopeOrganizationID: scopeOrgID,
		MFARequired:         mfaRequired,
		TOTPSecret:          totpSecret,
		TOTPEnabled:         req.TOTPEnabled,
		SSOProvider:         strings.ToLower(strings.TrimSpace(req.SSOProvider)),
		SSOSubject:          strings.TrimSpace(req.SSOSubject),
		Status:              status,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if admin.DisplayName == "" {
		admin.DisplayName = email
	}
	if err := s.admins.Create(ctx, admin); err != nil {
		return nil, err
	}
	return &AdminUserResponse{
		AdminUser:      sanitizeAdminUser(admin),
		TOTPSecret:     totpSecret,
		TOTPAuthURL:    totpAuthURL,
		TemporarySetup: temporarySetup,
	}, nil
}

func (s *AdminService) ListAdminUsers(ctx context.Context) ([]*domain.AdminUser, error) {
	if s == nil || s.admins == nil {
		return nil, domain.ErrNotFound
	}
	admins, err := s.admins.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.AdminUser, 0, len(admins))
	for _, admin := range admins {
		out = append(out, sanitizeAdminUser(admin))
	}
	return out, nil
}

func (s *AdminService) Login(ctx context.Context, req AdminLoginRequest, ip, ua, requestID string) (*AdminAuthResponse, error) {
	if s == nil || s.admins == nil {
		return nil, domain.ErrNotFound
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	admin, err := s.admins.GetByEmail(ctx, email)
	if err != nil {
		s.logAdminAuth(ctx, "admin.login_failed", nil, ip, ua, requestID, map[string]interface{}{"email": email, "reason": "not_found"})
		return nil, domain.ErrInvalidPassword
	}
	if admin.Status != "active" {
		s.logAdminAuth(ctx, "admin.login_failed", admin, ip, ua, requestID, map[string]interface{}{"email": email, "reason": "suspended"})
		return nil, domain.ErrAccountSuspended
	}
	if admin.PasswordHash == "" || bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.Password)) != nil {
		s.logAdminAuth(ctx, "admin.login_failed", admin, ip, ua, requestID, map[string]interface{}{"email": email, "reason": "password"})
		return nil, domain.ErrInvalidPassword
	}
	if admin.MFARequired {
		if !admin.TOTPEnabled || strings.TrimSpace(admin.TOTPSecret) == "" {
			s.logAdminAuth(ctx, "admin.login_mfa_enrollment_required", admin, ip, ua, requestID, map[string]interface{}{"email": email})
			return nil, domain.ErrMFAEnrollmentRequired
		}
		if strings.TrimSpace(req.TOTPCode) == "" {
			s.logAdminAuth(ctx, "admin.login_mfa_required", admin, ip, ua, requestID, map[string]interface{}{"email": email})
			return &AdminAuthResponse{MFARequired: true, Error: "mfa_required"}, domain.ErrMFARequired
		}
		if !totp.Validate(strings.TrimSpace(req.TOTPCode), admin.TOTPSecret) {
			s.logAdminAuth(ctx, "admin.login_failed", admin, ip, ua, requestID, map[string]interface{}{"email": email, "reason": "totp"})
			return nil, domain.ErrTOTPInvalid
		}
	}
	return s.issueAdminToken(ctx, admin, "password", ip, ua, requestID)
}

func (s *AdminService) LoginWithSSO(ctx context.Context, req AdminSSOLoginRequest, ip, ua, requestID string) (*AdminAuthResponse, error) {
	if s == nil || s.admins == nil {
		return nil, domain.ErrNotFound
	}
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	subject := strings.TrimSpace(req.Subject)
	if provider == "" || subject == "" {
		return nil, fmt.Errorf("provider and subject are required")
	}
	admin, err := s.admins.GetBySSOIdentity(ctx, provider, subject)
	if err != nil {
		s.logAdminAuth(ctx, "admin.sso_login_failed", nil, ip, ua, requestID, map[string]interface{}{"provider": provider, "reason": "not_found"})
		return nil, domain.ErrInvalidPassword
	}
	if admin.Status != "active" {
		s.logAdminAuth(ctx, "admin.sso_login_failed", admin, ip, ua, requestID, map[string]interface{}{"provider": provider, "reason": "suspended"})
		return nil, domain.ErrAccountSuspended
	}
	return s.issueAdminToken(ctx, admin, "sso:"+provider, ip, ua, requestID)
}

func (s *AdminService) ValidateAccessToken(ctx context.Context, rawToken string) (*domain.AdminActor, error) {
	if s == nil || s.admins == nil || len(s.tokenSecret) == 0 {
		return nil, domain.ErrInvalidAdminToken
	}
	var claims AdminAccessClaims
	token, err := jwt.ParseWithClaims(rawToken, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, domain.ErrInvalidAdminToken
		}
		return s.tokenSecret, nil
	}, jwt.WithIssuer(adminTokenIssuer))
	if err != nil || token == nil || !token.Valid {
		return nil, domain.ErrInvalidAdminToken
	}
	if strings.TrimSpace(claims.AdminUserID) == "" {
		return nil, domain.ErrInvalidAdminToken
	}
	admin, err := s.admins.GetByID(ctx, claims.AdminUserID)
	if err != nil {
		return nil, domain.ErrInvalidAdminToken
	}
	if admin.Status != "active" {
		return nil, domain.ErrAccountSuspended
	}
	return &domain.AdminActor{
		Type:                domain.AdminActorTypeUser,
		ID:                  admin.ID,
		Email:               admin.Email,
		Roles:               append([]string(nil), admin.Roles...),
		ScopeType:           admin.ScopeType,
		ScopeClientID:       admin.ScopeClientID,
		ScopeOrganizationID: admin.ScopeOrganizationID,
	}, nil
}

func (s *AdminService) BreakGlassActor(ctx context.Context, ip string) (*domain.AdminActor, error) {
	if s != nil && s.rl != nil {
		allowed, _, err := s.rl.Allow(ctx, "admin:break_glass:"+strings.TrimSpace(ip), defaultBreakGlassRateLimit, defaultBreakGlassRateWindow)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, domain.ErrRateLimit
		}
	}
	return &domain.AdminActor{
		Type:      domain.AdminActorTypeBreakGlass,
		ID:        "master-key",
		Email:     "break-glass-master-key",
		Roles:     []string{domain.AdminRoleOwner},
		ScopeType: domain.AdminScopeAll,
	}, nil
}

func (s *AdminService) Authorize(actor *domain.AdminActor, permission, targetClientID string, requireAllScope bool) error {
	if actor == nil {
		return domain.ErrAdminPermissionDenied
	}
	if actor.ScopeType == domain.AdminScopeOrganization && strings.TrimSpace(targetClientID) == "" {
		return domain.ErrAdminPermissionDenied
	}
	if requireAllScope && !actor.IsAllScoped() {
		return domain.ErrAdminPermissionDenied
	}
	if strings.TrimSpace(targetClientID) != "" && !actor.MatchesClient(targetClientID) {
		return domain.ErrAdminPermissionDenied
	}
	if actor.IsBreakGlass() {
		return nil
	}
	if permission == "" {
		return nil
	}
	if adminActorHasPermission(actor, permission) {
		return nil
	}
	return domain.ErrAdminPermissionDenied
}

func (s *AdminService) LogAdminAction(ctx context.Context, event *domain.AuditEvent) {
	if s == nil || s.audit == nil || event == nil {
		return
	}
	s.audit.LogAdmin(ctx, event)
}

func (s *AdminService) issueAdminToken(ctx context.Context, admin *domain.AdminUser, method, ip, ua, requestID string) (*AdminAuthResponse, error) {
	now := time.Now().UTC()
	expires := now.Add(s.accessTTL)
	claims := AdminAccessClaims{
		AdminUserID:         admin.ID,
		Email:               admin.Email,
		Roles:               append([]string(nil), admin.Roles...),
		ScopeType:           admin.ScopeType,
		ScopeClientID:       admin.ScopeClientID,
		ScopeOrganizationID: admin.ScopeOrganizationID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    adminTokenIssuer,
			Subject:   admin.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
			ID:        uuid.New().String(),
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.tokenSecret)
	if err != nil {
		return nil, err
	}
	_ = s.admins.UpdateLastLogin(ctx, admin.ID, now)
	s.logAdminAuth(ctx, "admin.login_success", admin, ip, ua, requestID, map[string]interface{}{"method": method})
	return &AdminAuthResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresAt:   expires,
		Admin:       sanitizeAdminUser(admin),
	}, nil
}

func (s *AdminService) logAdminAuth(ctx context.Context, eventType string, admin *domain.AdminUser, ip, ua, requestID string, metadata map[string]interface{}) {
	if s == nil || s.audit == nil {
		return
	}
	event := &domain.AuditEvent{
		EventType: eventType,
		ActorType: domain.AdminActorTypeUser,
		RequestID: requestID,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  metadata,
	}
	if admin != nil {
		event.ActorID = admin.ID
		event.ActorEmail = admin.Email
	}
	s.audit.LogAdmin(ctx, event)
}

func normalizeAdminRoles(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, domain.ErrInvalidAdminRole
	}
	seen := map[string]struct{}{}
	roles := make([]string, 0, len(raw))
	for _, role := range raw {
		role = strings.ToLower(strings.TrimSpace(role))
		if !validAdminRoles[role] {
			return nil, domain.ErrInvalidAdminRole
		}
		if _, ok := seen[role]; ok {
			continue
		}
		seen[role] = struct{}{}
		roles = append(roles, role)
	}
	return roles, nil
}

func normalizeAdminScope(scopeType, clientID, orgID string) (string, string, string, error) {
	scopeType = strings.ToLower(strings.TrimSpace(scopeType))
	clientID = strings.TrimSpace(clientID)
	orgID = strings.TrimSpace(orgID)
	if scopeType == "" {
		scopeType = domain.AdminScopeAll
	}
	switch scopeType {
	case domain.AdminScopeAll:
		return scopeType, "", "", nil
	case domain.AdminScopeClient:
		if clientID == "" {
			return "", "", "", domain.ErrInvalidAdminScope
		}
		return scopeType, clientID, "", nil
	case domain.AdminScopeOrganization:
		if clientID == "" || orgID == "" {
			return "", "", "", domain.ErrInvalidAdminScope
		}
		return scopeType, clientID, orgID, nil
	default:
		return "", "", "", domain.ErrInvalidAdminScope
	}
}

func sanitizeAdminUser(admin *domain.AdminUser) *domain.AdminUser {
	if admin == nil {
		return nil
	}
	cp := *admin
	cp.PasswordHash = ""
	cp.TOTPSecret = ""
	cp.Roles = append([]string(nil), admin.Roles...)
	return &cp
}

func randomAdminSecret(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func HashAdminBootstrapKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

var validAdminRoles = map[string]bool{
	domain.AdminRoleOwner:           true,
	domain.AdminRoleSecurityAdmin:   true,
	domain.AdminRoleSupportAdmin:    true,
	domain.AdminRoleBillingAdmin:    true,
	domain.AdminRoleReadOnlyAuditor: true,
}

var adminRolePermissions = map[string]map[string]bool{
	domain.AdminRoleOwner: {
		AdminPermissionAll: true,
	},
	domain.AdminRoleSecurityAdmin: {
		AdminPermissionClientsRead:   true,
		AdminPermissionClientsUpdate: true,
		AdminPermissionClientsRotate: true,
		AdminPermissionAuditRead:     true,
		AdminPermissionAdminsRead:    true,
		AdminPermissionAdminsManage:  true,
		AdminPermissionM2MRead:       true,
		AdminPermissionM2MManage:     true,
		AdminPermissionSSORead:       true,
		AdminPermissionSSOManage:     true,
		AdminPermissionSCIMRead:      true,
		AdminPermissionSCIMManage:    true,
	},
	domain.AdminRoleSupportAdmin: {
		AdminPermissionClientsRead: true,
		AdminPermissionAuditRead:   true,
		AdminPermissionM2MRead:     true,
		AdminPermissionSSORead:     true,
		AdminPermissionSCIMRead:    true,
	},
	domain.AdminRoleBillingAdmin: {
		AdminPermissionClientsRead: true,
		AdminPermissionAuditRead:   true,
	},
	domain.AdminRoleReadOnlyAuditor: {
		AdminPermissionClientsRead: true,
		AdminPermissionAuditRead:   true,
		AdminPermissionM2MRead:     true,
		AdminPermissionSSORead:     true,
		AdminPermissionSCIMRead:    true,
	},
}

func adminActorHasPermission(actor *domain.AdminActor, permission string) bool {
	for _, role := range actor.Roles {
		perms := adminRolePermissions[role]
		if perms[AdminPermissionAll] || perms[permission] {
			return true
		}
	}
	return false
}

func IsAdminAuthError(err error) bool {
	return errors.Is(err, domain.ErrInvalidPassword) ||
		errors.Is(err, domain.ErrInvalidAdminToken) ||
		errors.Is(err, domain.ErrTOTPInvalid) ||
		errors.Is(err, domain.ErrMFARequired) ||
		errors.Is(err, domain.ErrMFAEnrollmentRequired) ||
		errors.Is(err, domain.ErrAccountSuspended)
}

func NewRandomAdminTokenSecret() string {
	secret, _ := randomAdminSecret(32)
	return secret
}
