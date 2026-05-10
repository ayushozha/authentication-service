package application

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

const (
	adaptiveSecuritySettingsKey = "adaptive_security"
	adaptiveSecurityPolicyKey   = "adaptive_security_policy"

	stepUpChallengeTTL = 5 * time.Minute
	defaultStepUpAge   = 10 * time.Minute
)

type UserDeviceRepository interface {
	Upsert(ctx context.Context, device *domain.UserDevice) error
	GetByFingerprint(ctx context.Context, clientID, userID, fingerprint string) (*domain.UserDevice, error)
	GetForUser(ctx context.Context, clientID, userID, deviceID string) (*domain.UserDevice, error)
	ListForUser(ctx context.Context, clientID, userID string) ([]*domain.UserDevice, error)
	Trust(ctx context.Context, clientID, userID, deviceID, name string, trusted bool, expiresAt *time.Time) (*domain.UserDevice, error)
	Delete(ctx context.Context, clientID, userID, deviceID string) error
}

type RiskSignalProvider interface {
	Assess(ctx context.Context, req RiskProviderRequest) (*RiskProviderResponse, error)
}

type RiskProviderRequest struct {
	ClientID          string `json:"client_id"`
	UserID            string `json:"user_id,omitempty"`
	OrganizationID    string `json:"organization_id,omitempty"`
	Action            string `json:"action"`
	Email             string `json:"email,omitempty"`
	IPAddress         string `json:"ip_address"`
	UserAgent         string `json:"user_agent"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
}

type RiskProviderResponse struct {
	Signals      []domain.RiskSignal    `json:"signals,omitempty"`
	IPReputation string                 `json:"ip_reputation,omitempty"`
	ASN          int                    `json:"asn,omitempty"`
	ASNName      string                 `json:"asn_name,omitempty"`
	VPN          bool                   `json:"vpn,omitempty"`
	Tor          bool                   `json:"tor,omitempty"`
	Proxy        bool                   `json:"proxy,omitempty"`
	Bot          bool                   `json:"bot,omitempty"`
	Country      string                 `json:"country,omitempty"`
	Latitude     *float64               `json:"latitude,omitempty"`
	Longitude    *float64               `json:"longitude,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

type HTTPRiskSignalProvider struct {
	endpoint string
	apiKey   string
	client   *http.Client
}

func NewHTTPRiskSignalProvider(endpoint, apiKey string, timeout time.Duration) *HTTPRiskSignalProvider {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPRiskSignalProvider{
		endpoint: endpoint,
		apiKey:   strings.TrimSpace(apiKey),
		client:   &http.Client{Timeout: timeout},
	}
}

func (p *HTTPRiskSignalProvider) Assess(ctx context.Context, req RiskProviderRequest) (*RiskProviderResponse, error) {
	if p == nil || p.endpoint == "" {
		return nil, nil
	}
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	}
	res, err := p.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("risk provider returned %d", res.StatusCode)
	}
	var out RiskProviderResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

type AdaptiveSecurityService struct {
	clients       ClientRepository
	orgs          OrganizationRepository
	users         UserRepository
	sessions      SessionRepository
	devices       UserDeviceRepository
	recoveryCodes RecoveryCodeRepository
	admins        AdminUserRepository
	cache         CacheClient
	audit         AuditRepository
	riskProvider  RiskSignalProvider
}

func NewAdaptiveSecurityService(
	clients ClientRepository,
	orgs OrganizationRepository,
	users UserRepository,
	sessions SessionRepository,
	devices UserDeviceRepository,
	recoveryCodes RecoveryCodeRepository,
	cache CacheClient,
	audit AuditRepository,
	riskProvider RiskSignalProvider,
) *AdaptiveSecurityService {
	return &AdaptiveSecurityService{
		clients:       clients,
		orgs:          orgs,
		users:         users,
		sessions:      sessions,
		devices:       devices,
		recoveryCodes: recoveryCodes,
		cache:         cache,
		audit:         audit,
		riskProvider:  riskProvider,
	}
}

func (s *AdaptiveSecurityService) SetAdminUsers(admins AdminUserRepository) {
	if s != nil {
		s.admins = admins
	}
}

type LoginSecurityDecision struct {
	Risk       domain.RiskAssessment         `json:"risk"`
	RequireMFA bool                          `json:"require_mfa"`
	Block      bool                          `json:"block"`
	Factors    []string                      `json:"factors,omitempty"`
	Policy     domain.AdaptiveSecurityPolicy `json:"policy"`
}

type ActionSecurityDecision struct {
	Action         string                `json:"action"`
	Allowed        bool                  `json:"allowed"`
	Blocked        bool                  `json:"blocked"`
	StepUpRequired bool                  `json:"step_up_required"`
	ChallengeToken string                `json:"challenge_token,omitempty"`
	Factors        []string              `json:"factors,omitempty"`
	ExpiresIn      int                   `json:"expires_in,omitempty"`
	Risk           domain.RiskAssessment `json:"risk"`
}

type StepUpVerifyResponse struct {
	StepUpToken string    `json:"step_up_token"`
	Action      string    `json:"action"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type stepUpState struct {
	ClientID       string    `json:"client_id"`
	UserID         string    `json:"user_id"`
	OrganizationID string    `json:"organization_id,omitempty"`
	Action         string    `json:"action"`
	Factors        []string  `json:"factors,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func DefaultAdaptiveSecurityPolicy() domain.AdaptiveSecurityPolicy {
	return domain.AdaptiveSecurityPolicy{
		MFA: domain.MFAPolicy{
			Mode:                domain.MFAModeAllow,
			Factors:             []string{domain.MFAFactorTOTP, domain.MFAFactorRecoveryCode},
			ChallengeRiskLevel:  domain.RiskLevelMedium,
			BlockRiskLevel:      domain.RiskLevelCritical,
			RememberDeviceDays:  30,
			TrustedDeviceBypass: true,
			EnrollmentRequired:  false,
		},
		Risk: domain.RiskPolicy{
			ChallengeLevel:          domain.RiskLevelMedium,
			BlockLevel:              domain.RiskLevelCritical,
			FailedVelocityThreshold: 3,
		},
		Actions: map[string]domain.StepUpActionPolicy{
			domain.SecurityActionPasswordChange: {
				Mode:          domain.StepUpModeNotify,
				Factors:       []string{domain.MFAFactorTOTP, domain.MFAFactorRecoveryCode},
				MaxAgeSeconds: int(defaultStepUpAge.Seconds()),
			},
			domain.SecurityActionOrganizationMemberRole: {
				Mode:          domain.StepUpModeNotify,
				Factors:       []string{domain.MFAFactorTOTP, domain.MFAFactorRecoveryCode},
				MaxAgeSeconds: int(defaultStepUpAge.Seconds()),
			},
			domain.SecurityActionClientKeyRotate: {
				Mode:          domain.StepUpModeNotify,
				Factors:       []string{domain.MFAFactorTOTP, domain.MFAFactorRecoveryCode},
				MaxAgeSeconds: int(defaultStepUpAge.Seconds()),
			},
			domain.SecurityActionAuditExport: {
				Mode:          domain.StepUpModeNotify,
				Factors:       []string{domain.MFAFactorTOTP, domain.MFAFactorRecoveryCode},
				MaxAgeSeconds: int(defaultStepUpAge.Seconds()),
			},
		},
		Alerts: domain.SecurityAlertPolicy{
			RiskLevels: []string{domain.RiskLevelHigh, domain.RiskLevelCritical},
		},
	}
}

func NormalizeAdaptiveSecurityPolicy(policy domain.AdaptiveSecurityPolicy) domain.AdaptiveSecurityPolicy {
	defaults := DefaultAdaptiveSecurityPolicy()
	if strings.TrimSpace(policy.MFA.Mode) == "" {
		policy.MFA.Mode = defaults.MFA.Mode
	}
	policy.MFA.Mode = normalizeMode(policy.MFA.Mode, []string{domain.MFAModeOff, domain.MFAModeAllow, domain.MFAModeRequired, domain.MFAModeAdaptive}, defaults.MFA.Mode)
	if len(policy.MFA.Factors) == 0 {
		policy.MFA.Factors = append([]string(nil), defaults.MFA.Factors...)
	} else {
		policy.MFA.Factors = normalizeFactors(policy.MFA.Factors)
	}
	if strings.TrimSpace(policy.MFA.ChallengeRiskLevel) == "" {
		policy.MFA.ChallengeRiskLevel = defaults.MFA.ChallengeRiskLevel
	}
	if strings.TrimSpace(policy.MFA.BlockRiskLevel) == "" {
		policy.MFA.BlockRiskLevel = defaults.MFA.BlockRiskLevel
	}
	if policy.MFA.RememberDeviceDays <= 0 {
		policy.MFA.RememberDeviceDays = defaults.MFA.RememberDeviceDays
	}

	if strings.TrimSpace(policy.Risk.ChallengeLevel) == "" {
		policy.Risk.ChallengeLevel = defaults.Risk.ChallengeLevel
	}
	if strings.TrimSpace(policy.Risk.BlockLevel) == "" {
		policy.Risk.BlockLevel = defaults.Risk.BlockLevel
	}
	if policy.Risk.FailedVelocityThreshold <= 0 {
		policy.Risk.FailedVelocityThreshold = defaults.Risk.FailedVelocityThreshold
	}
	if policy.Actions == nil {
		policy.Actions = map[string]domain.StepUpActionPolicy{}
	}
	for action, actionPolicy := range defaults.Actions {
		if _, ok := policy.Actions[action]; !ok {
			policy.Actions[action] = actionPolicy
		}
	}
	for action, actionPolicy := range policy.Actions {
		policy.Actions[action] = normalizeActionPolicy(actionPolicy)
	}
	if len(policy.Alerts.RiskLevels) == 0 {
		policy.Alerts.RiskLevels = append([]string(nil), defaults.Alerts.RiskLevels...)
	}
	return policy
}

func (s *AdaptiveSecurityService) ClientPolicy(client *domain.Client) domain.AdaptiveSecurityPolicy {
	policy := DefaultAdaptiveSecurityPolicy()
	if client == nil || client.Settings == nil {
		return NormalizeAdaptiveSecurityPolicy(policy)
	}
	if raw, ok := client.Settings[adaptiveSecuritySettingsKey]; ok {
		policy = decodeAdaptiveSecurityPolicy(raw, policy)
	} else if raw, ok := client.Settings[adaptiveSecurityPolicyKey]; ok {
		policy = decodeAdaptiveSecurityPolicy(raw, policy)
	}
	return NormalizeAdaptiveSecurityPolicy(policy)
}

func (s *AdaptiveSecurityService) OrganizationPolicy(ctx context.Context, client *domain.Client, organizationID string) domain.AdaptiveSecurityPolicy {
	policy := s.ClientPolicy(client)
	if s == nil || s.orgs == nil || strings.TrimSpace(organizationID) == "" || client == nil {
		return policy
	}
	org, err := s.orgs.GetOrganization(ctx, client.ID, organizationID)
	if err != nil || org == nil || org.Metadata == nil {
		return policy
	}
	if raw, ok := org.Metadata[adaptiveSecurityPolicyKey]; ok {
		return NormalizeAdaptiveSecurityPolicy(decodeAdaptiveSecurityPolicy(raw, policy))
	}
	if raw, ok := org.Metadata[adaptiveSecuritySettingsKey]; ok {
		return NormalizeAdaptiveSecurityPolicy(decodeAdaptiveSecurityPolicy(raw, policy))
	}
	return policy
}

func (s *AdaptiveSecurityService) EvaluateLogin(ctx context.Context, client *domain.Client, user *domain.User, email, ip, ua string) (*LoginSecurityDecision, error) {
	if s == nil || client == nil || user == nil {
		return nil, nil
	}
	policy := s.ClientPolicy(client)
	risk := s.AssessRisk(ctx, client, "", user, domain.SecurityActionLogin, email, ip, ua, policy)
	decision := &LoginSecurityDecision{
		Risk:    risk,
		Factors: append([]string(nil), policy.MFA.Factors...),
		Policy:  policy,
	}
	if riskAtLeast(risk.Level, policy.MFA.BlockRiskLevel) || riskAtLeast(risk.Level, policy.Risk.BlockLevel) {
		decision.Block = true
		return decision, nil
	}

	trusted := riskHasSignal(risk, "trusted_device")
	switch policy.MFA.Mode {
	case domain.MFAModeOff:
		decision.RequireMFA = false
	case domain.MFAModeRequired:
		decision.RequireMFA = true
	case domain.MFAModeAdaptive:
		decision.RequireMFA = riskAtLeast(risk.Level, policy.MFA.ChallengeRiskLevel)
	default:
		decision.RequireMFA = user.TOTPEnabled
	}
	if trusted && policy.MFA.TrustedDeviceBypass && policy.MFA.Mode != domain.MFAModeRequired {
		decision.RequireMFA = false
	}
	if decision.RequireMFA && !user.TOTPEnabled {
		return decision, domain.ErrStepUpEnrollmentRequired
	}
	return decision, nil
}

func (s *AdaptiveSecurityService) AssessRisk(ctx context.Context, client *domain.Client, organizationID string, user *domain.User, action, email, ip, ua string, policy domain.AdaptiveSecurityPolicy) domain.RiskAssessment {
	builder := newRiskBuilder()
	clientID := ""
	userID := ""
	if client != nil {
		clientID = client.ID
	}
	if user != nil {
		userID = user.ID
		if strings.TrimSpace(email) == "" {
			email = user.Email
		}
	}
	fingerprint := deviceFingerprint(ua)
	builder.context["action"] = action
	builder.context["device_fingerprint"] = fingerprint

	if ipMatchesAny(ip, policy.Risk.TrustedIPCidrs) {
		builder.add("trusted_ip", domain.RiskLevelLow, "request came from trusted IP range", nil)
	}
	if ipMatchesAny(ip, policy.Risk.BlockedIPCidrs) {
		builder.add("ip_reputation", domain.RiskLevelCritical, "request IP is blocked by policy", nil)
	}
	if ipMatchesAny(ip, policy.Risk.TorIPCidrs) {
		builder.add("tor", domain.RiskLevelHigh, "request IP matches configured Tor range", nil)
	}

	var currentDevice *domain.UserDevice
	if s != nil && s.devices != nil && userID != "" && fingerprint != "" {
		device, err := s.devices.GetByFingerprint(ctx, clientID, userID, fingerprint)
		if err == nil && device != nil {
			currentDevice = device
			if device.Trusted && !deviceTrustExpired(device) {
				builder.add("trusted_device", domain.RiskLevelLow, "recognized trusted device", map[string]interface{}{"device_id": device.ID})
			}
		} else {
			builder.add("new_device", domain.RiskLevelMedium, "device has not been seen for this user", nil)
		}
	}

	if s != nil && s.sessions != nil && userID != "" {
		sessions, err := s.sessions.ListForUser(ctx, clientID, userID)
		if err == nil && len(sessions) > 0 {
			if !sessionsContainIP(sessions, normalizeRiskIP(ip)) {
				builder.add("new_ip", domain.RiskLevelMedium, "IP address has not been seen on active sessions", nil)
			}
			if fingerprint != "" && !sessionsContainDevice(sessions, fingerprint) {
				builder.add("new_device", domain.RiskLevelMedium, "device differs from active sessions", nil)
			}
		}
	}

	if failed := s.failedLoginCount(ctx, clientID, email); failed >= policy.Risk.FailedVelocityThreshold {
		level := domain.RiskLevelMedium
		if failed >= policy.Risk.FailedVelocityThreshold*2 {
			level = domain.RiskLevelHigh
		}
		builder.add("failed_velocity", level, "recent failed login velocity is elevated", map[string]interface{}{"failed_attempts": failed})
	}

	providerResp := s.assessProvider(ctx, RiskProviderRequest{
		ClientID:          clientID,
		UserID:            userID,
		OrganizationID:    organizationID,
		Action:            action,
		Email:             strings.ToLower(strings.TrimSpace(email)),
		IPAddress:         ip,
		UserAgent:         ua,
		DeviceFingerprint: fingerprint,
	})
	if providerResp != nil {
		for _, signal := range providerResp.Signals {
			builder.add(signal.Type, signal.Level, signal.Reason, signal.Metadata)
		}
		if providerResp.IPReputation != "" {
			level := providerRiskLevel(providerResp.IPReputation)
			if level != domain.RiskLevelLow {
				builder.add("ip_reputation", level, "risk provider flagged IP reputation", map[string]interface{}{"reputation": providerResp.IPReputation})
			}
		}
		if providerResp.Tor {
			builder.add("tor", domain.RiskLevelHigh, "risk provider flagged Tor exit node", nil)
		}
		if providerResp.VPN || providerResp.Proxy {
			builder.add("vpn_or_proxy", domain.RiskLevelMedium, "risk provider flagged VPN or proxy", nil)
		}
		if providerResp.Bot {
			builder.add("bot", domain.RiskLevelHigh, "risk provider flagged bot behavior", nil)
		}
		if providerResp.ASN != 0 {
			meta := map[string]interface{}{"asn": providerResp.ASN}
			if providerResp.ASNName != "" {
				meta["asn_name"] = providerResp.ASNName
			}
			if intIn(providerResp.ASN, policy.Risk.VPNASNs) {
				builder.add("asn_vpn", domain.RiskLevelHigh, "ASN is configured as VPN hosting", meta)
			}
			if intIn(providerResp.ASN, policy.Risk.HighRiskASNs) {
				builder.add("asn_reputation", domain.RiskLevelHigh, "ASN is configured as high risk", meta)
			}
			builder.context["asn"] = providerResp.ASN
		}
		if providerResp.Country != "" {
			builder.context["country"] = providerResp.Country
		}
		if providerResp.Metadata != nil {
			builder.context["provider"] = providerResp.Metadata
		}
		if providerResp.Latitude != nil && providerResp.Longitude != nil {
			builder.context["latitude"] = *providerResp.Latitude
			builder.context["longitude"] = *providerResp.Longitude
			if currentDevice != nil && impossibleTravel(currentDevice, *providerResp.Latitude, *providerResp.Longitude) {
				builder.add("impossible_travel", domain.RiskLevelHigh, "distance from previous device location is implausible for elapsed time", nil)
			}
		}
	}

	risk := builder.assessment()
	if riskHasSignal(risk, "trusted_device") && risk.Level == domain.RiskLevelMedium && policy.MFA.TrustedDeviceBypass {
		risk.Level = domain.RiskLevelLow
		risk.Score = 20
		risk.Context["trusted_device_reduced_risk"] = true
	}
	return risk
}

func (s *AdaptiveSecurityService) EvaluateAction(ctx context.Context, client *domain.Client, organizationID, userID, action, stepUpToken, ip, ua string) (*ActionSecurityDecision, error) {
	if s == nil || client == nil {
		return &ActionSecurityDecision{Action: action, Allowed: true}, nil
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil || user.ClientID != client.ID {
		return nil, domain.ErrNotFound
	}
	policy := s.OrganizationPolicy(ctx, client, organizationID)
	actionPolicy := normalizeActionPolicy(policy.Actions[action])
	risk := s.AssessRisk(ctx, client, organizationID, user, action, user.Email, ip, ua, policy)
	decision := &ActionSecurityDecision{Action: action, Risk: risk, Factors: actionFactors(actionPolicy, policy)}

	if actionPolicy.Mode == domain.StepUpModeOff {
		decision.Allowed = true
		return decision, nil
	}
	if actionPolicy.Mode == domain.StepUpModeBlock || riskAtLeast(risk.Level, actionPolicy.RiskBlockLevel) || riskAtLeast(risk.Level, policy.Risk.BlockLevel) {
		decision.Blocked = true
		s.logSecurityEvent(ctx, client.ID, &user.ID, "adaptive_security_action_blocked", ip, ua, map[string]interface{}{
			"action": action,
			"risk":   risk,
		})
		return decision, nil
	}
	requiresChallenge := actionPolicy.Mode == domain.StepUpModeChallenge || riskAtLeast(risk.Level, actionPolicy.RiskChallengeLevel)
	if !requiresChallenge {
		decision.Allowed = true
		if actionPolicy.Mode == domain.StepUpModeNotify {
			s.logSecurityEvent(ctx, client.ID, &user.ID, "adaptive_security_action_notified", ip, ua, map[string]interface{}{"action": action, "risk": risk})
		}
		return decision, nil
	}
	if err := s.validateStepUpToken(ctx, client.ID, user.ID, organizationID, action, stepUpToken); err == nil {
		decision.Allowed = true
		return decision, nil
	}
	if !user.TOTPEnabled {
		return decision, domain.ErrStepUpEnrollmentRequired
	}
	challengeToken, err := s.createStepUpChallenge(ctx, client.ID, user.ID, organizationID, action, decision.Factors, stepUpChallengeTTL)
	if err != nil {
		return nil, err
	}
	decision.StepUpRequired = true
	decision.ChallengeToken = challengeToken
	decision.ExpiresIn = int(stepUpChallengeTTL.Seconds())
	s.logSecurityEvent(ctx, client.ID, &user.ID, "adaptive_security_step_up_required", ip, ua, map[string]interface{}{"action": action, "risk": risk})
	return decision, nil
}

func (s *AdaptiveSecurityService) EvaluateAdminAction(ctx context.Context, clientID, action string, actor *domain.AdminActor, stepUpToken, ip, ua string) (*ActionSecurityDecision, error) {
	if s == nil || s.clients == nil || strings.TrimSpace(clientID) == "" {
		return &ActionSecurityDecision{Action: action, Allowed: true}, nil
	}
	client, err := s.clients.GetByID(ctx, clientID)
	if err != nil || client == nil {
		return nil, domain.ErrNotFound
	}
	policy := s.ClientPolicy(client)
	actionPolicy := normalizeActionPolicy(policy.Actions[action])
	risk := s.AssessRisk(ctx, client, "", nil, action, "", ip, ua, policy)
	decision := &ActionSecurityDecision{Action: action, Risk: risk, Factors: adminActionFactors(actionPolicy, policy)}
	if actionPolicy.Mode == domain.StepUpModeOff {
		decision.Allowed = true
		return decision, nil
	}
	if actionPolicy.Mode == domain.StepUpModeBlock || riskAtLeast(risk.Level, actionPolicy.RiskBlockLevel) || riskAtLeast(risk.Level, policy.Risk.BlockLevel) {
		decision.Blocked = true
		s.logSecurityEvent(ctx, client.ID, nil, "adaptive_security_admin_action_blocked", ip, ua, map[string]interface{}{"action": action, "risk": risk})
		return decision, nil
	}
	requiresChallenge := actionPolicy.Mode == domain.StepUpModeChallenge || riskAtLeast(risk.Level, actionPolicy.RiskChallengeLevel)
	if !requiresChallenge {
		decision.Allowed = true
		if actionPolicy.Mode == domain.StepUpModeNotify || riskAtLeast(risk.Level, policy.Risk.ChallengeLevel) {
			s.logSecurityEvent(ctx, client.ID, nil, "adaptive_security_admin_action_notified", ip, ua, map[string]interface{}{"action": action, "risk": risk})
		}
		return decision, nil
	}
	if actor != nil && actor.ID != "" {
		if err := s.validateStepUpToken(ctx, client.ID, actor.ID, "", action, stepUpToken); err == nil {
			decision.Allowed = true
			return decision, nil
		}
	}
	if !s.adminCanStepUp(ctx, actor) {
		return decision, domain.ErrStepUpEnrollmentRequired
	}
	challengeToken, err := s.createStepUpChallenge(ctx, client.ID, actor.ID, "", action, decision.Factors, stepUpChallengeTTL)
	if err != nil {
		return nil, err
	}
	decision.StepUpRequired = true
	decision.ChallengeToken = challengeToken
	decision.ExpiresIn = int(stepUpChallengeTTL.Seconds())
	s.logSecurityEvent(ctx, client.ID, nil, "adaptive_security_admin_step_up_required", ip, ua, map[string]interface{}{
		"action":      action,
		"risk":        risk,
		"admin_actor": actor.ID,
	})
	return decision, nil
}

func (s *AdaptiveSecurityService) VerifyAdminStepUp(ctx context.Context, actor *domain.AdminActor, challengeToken, factor, code, ip, ua string) (*StepUpVerifyResponse, error) {
	if s == nil || s.cache == nil {
		return nil, domain.ErrRedisRequired
	}
	if actor == nil || actor.ID == "" || actor.IsBreakGlass() || s.admins == nil {
		return nil, domain.ErrStepUpEnrollmentRequired
	}
	state, err := s.loadStepUpState(ctx, "stepup:challenge:"+HashToken(challengeToken))
	if err != nil {
		return nil, err
	}
	if state.UserID != actor.ID || time.Now().UTC().After(state.ExpiresAt) {
		return nil, domain.ErrInvalidToken
	}
	admin, err := s.admins.GetByID(ctx, actor.ID)
	if err != nil || admin == nil || admin.Status != "active" {
		return nil, domain.ErrNotFound
	}
	if !admin.TOTPEnabled || strings.TrimSpace(admin.TOTPSecret) == "" {
		return nil, domain.ErrStepUpEnrollmentRequired
	}
	factor = strings.ToLower(strings.TrimSpace(factor))
	if factor == "" {
		factor = domain.MFAFactorTOTP
	}
	if factor != domain.MFAFactorTOTP || !containsString(state.Factors, factor) {
		return nil, domain.ErrInvalidToken
	}
	if !totp.Validate(strings.TrimSpace(code), admin.TOTPSecret) {
		return nil, domain.ErrTOTPInvalid
	}

	stepUpToken, err := GenerateToken(32)
	if err != nil {
		return nil, err
	}
	var client *domain.Client
	if s.clients != nil && state.ClientID != "" {
		client, _ = s.clients.GetByID(ctx, state.ClientID)
	}
	policy := s.ClientPolicy(client)
	maxAge := actionMaxAge(policy.Actions[state.Action])
	state.ExpiresAt = time.Now().UTC().Add(maxAge)
	stateJSON, _ := json.Marshal(state)
	if err := s.cache.Set(ctx, "stepup:token:"+HashToken(stepUpToken), string(stateJSON), maxAge); err != nil {
		return nil, domain.ErrRedisRequired
	}
	_ = s.cache.Del(ctx, "stepup:challenge:"+HashToken(challengeToken))
	s.logSecurityEvent(ctx, state.ClientID, nil, "adaptive_security_admin_step_up_verified", ip, ua, map[string]interface{}{
		"action":      state.Action,
		"factor":      factor,
		"admin_actor": actor.ID,
	})
	return &StepUpVerifyResponse{StepUpToken: stepUpToken, Action: state.Action, ExpiresAt: state.ExpiresAt}, nil
}

func (s *AdaptiveSecurityService) VerifyStepUp(ctx context.Context, client *domain.Client, userID, challengeToken, factor, code, ip, ua string) (*StepUpVerifyResponse, error) {
	if s == nil || s.cache == nil {
		return nil, domain.ErrRedisRequired
	}
	if client == nil {
		return nil, domain.ErrInvalidClient
	}
	state, err := s.loadStepUpState(ctx, "stepup:challenge:"+HashToken(challengeToken))
	if err != nil {
		return nil, err
	}
	if state.ClientID != client.ID || state.UserID != userID || time.Now().UTC().After(state.ExpiresAt) {
		return nil, domain.ErrInvalidToken
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil || user.ClientID != client.ID {
		return nil, domain.ErrNotFound
	}
	factor = strings.ToLower(strings.TrimSpace(factor))
	if factor == "" {
		factor = domain.MFAFactorTOTP
	}
	if !containsString(state.Factors, factor) {
		return nil, domain.ErrInvalidToken
	}
	switch factor {
	case domain.MFAFactorTOTP:
		if user.TOTPSecret == nil || !totp.Validate(strings.TrimSpace(code), *user.TOTPSecret) {
			return nil, domain.ErrTOTPInvalid
		}
	case domain.MFAFactorRecoveryCode:
		if s.recoveryCodes == nil {
			return nil, domain.ErrNotFound
		}
		used, err := s.recoveryCodes.MarkUsedByHash(ctx, user.ID, HashToken(normalizeRecoveryCode(code)))
		if err != nil {
			return nil, err
		}
		if !used {
			return nil, domain.ErrTOTPInvalid
		}
	default:
		return nil, domain.ErrInvalidToken
	}

	stepUpToken, err := GenerateToken(32)
	if err != nil {
		return nil, err
	}
	policy := s.OrganizationPolicy(ctx, client, state.OrganizationID)
	maxAge := actionMaxAge(policy.Actions[state.Action])
	state.ExpiresAt = time.Now().UTC().Add(maxAge)
	stateJSON, _ := json.Marshal(state)
	if err := s.cache.Set(ctx, "stepup:token:"+HashToken(stepUpToken), string(stateJSON), maxAge); err != nil {
		return nil, domain.ErrRedisRequired
	}
	_ = s.cache.Del(ctx, "stepup:challenge:"+HashToken(challengeToken))
	s.logSecurityEvent(ctx, client.ID, &user.ID, "adaptive_security_step_up_verified", ip, ua, map[string]interface{}{"action": state.Action, "factor": factor})
	return &StepUpVerifyResponse{StepUpToken: stepUpToken, Action: state.Action, ExpiresAt: state.ExpiresAt}, nil
}

func (s *AdaptiveSecurityService) RememberLoginDevice(ctx context.Context, client *domain.Client, user *domain.User, ip, ua, name string, trusted bool, metadata map[string]interface{}) {
	if s == nil || s.devices == nil || client == nil || user == nil {
		return
	}
	policy := s.ClientPolicy(client)
	now := time.Now().UTC()
	var expiresAt *time.Time
	if trusted {
		exp := now.Add(time.Duration(policy.MFA.RememberDeviceDays) * 24 * time.Hour)
		expiresAt = &exp
	}
	device := &domain.UserDevice{
		ID:             uuid.NewString(),
		ClientID:       client.ID,
		UserID:         user.ID,
		Fingerprint:    deviceFingerprint(ua),
		Name:           defaultDeviceName(name, ua),
		UserAgent:      ua,
		IPAddress:      ip,
		Trusted:        trusted,
		Remembered:     trusted,
		TrustExpiresAt: expiresAt,
		LastSeenAt:     now,
		Metadata:       metadata,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if device.Fingerprint == "" {
		return
	}
	_ = s.devices.Upsert(ctx, device)
}

func (s *AdaptiveSecurityService) ListDevices(ctx context.Context, client *domain.Client, userID string) ([]*domain.UserDevice, error) {
	if s == nil || s.devices == nil || client == nil {
		return nil, domain.ErrNotFound
	}
	return s.devices.ListForUser(ctx, client.ID, userID)
}

func (s *AdaptiveSecurityService) TrustDevice(ctx context.Context, client *domain.Client, userID, deviceID, name string, trusted bool) (*domain.UserDevice, error) {
	if s == nil || s.devices == nil || client == nil {
		return nil, domain.ErrNotFound
	}
	var expiresAt *time.Time
	if trusted {
		policy := s.ClientPolicy(client)
		exp := time.Now().UTC().Add(time.Duration(policy.MFA.RememberDeviceDays) * 24 * time.Hour)
		expiresAt = &exp
	}
	return s.devices.Trust(ctx, client.ID, userID, deviceID, name, trusted, expiresAt)
}

func (s *AdaptiveSecurityService) DeleteDevice(ctx context.Context, client *domain.Client, userID, deviceID string) error {
	if s == nil || s.devices == nil || client == nil {
		return domain.ErrNotFound
	}
	return s.devices.Delete(ctx, client.ID, userID, deviceID)
}

func (s *AdaptiveSecurityService) RecordFailedLogin(ctx context.Context, clientID, email string) {
	if s == nil || s.cache == nil {
		return
	}
	key := failedVelocityKey(clientID, email)
	count, err := s.cache.Incr(ctx, key)
	if err == nil && count == 1 {
		_ = s.cache.Expire(ctx, key, 15*time.Minute)
	}
}

func (s *AdaptiveSecurityService) ClearFailedLoginVelocity(ctx context.Context, clientID, email string) {
	if s == nil || s.cache == nil {
		return
	}
	_ = s.cache.Del(ctx, failedVelocityKey(clientID, email))
}

func (s *AdaptiveSecurityService) failedLoginCount(ctx context.Context, clientID, email string) int {
	if s == nil || s.cache == nil || strings.TrimSpace(email) == "" {
		return 0
	}
	raw, err := s.cache.Get(ctx, failedVelocityKey(clientID, email))
	if err != nil || raw == "" {
		return 0
	}
	count, _ := strconv.Atoi(raw)
	return count
}

func (s *AdaptiveSecurityService) LogSuspiciousTokenReuse(ctx context.Context, client *domain.Client, ip, ua string) {
	if s == nil || client == nil {
		return
	}
	s.logSecurityEvent(ctx, client.ID, nil, "suspicious_token_reuse", ip, ua, map[string]interface{}{
		"signal": "refresh_token_reuse_or_invalid",
		"risk": domain.RiskAssessment{
			Level: domain.RiskLevelHigh,
			Score: 80,
			Signals: []domain.RiskSignal{{
				Type:   "suspicious_token_reuse",
				Level:  domain.RiskLevelHigh,
				Reason: "invalid or already-rotated refresh token was presented",
			}},
		},
	})
}

func (s *AdaptiveSecurityService) adminCanStepUp(ctx context.Context, actor *domain.AdminActor) bool {
	if s == nil || s.admins == nil || actor == nil || actor.ID == "" || actor.IsBreakGlass() {
		return false
	}
	admin, err := s.admins.GetByID(ctx, actor.ID)
	return err == nil && admin != nil && admin.Status == "active" && admin.TOTPEnabled && strings.TrimSpace(admin.TOTPSecret) != ""
}

func (s *AdaptiveSecurityService) logSecurityEvent(ctx context.Context, clientID string, userID *string, eventType, ip, ua string, metadata map[string]interface{}) {
	if s != nil && s.audit != nil {
		s.audit.Log(ctx, clientID, userID, eventType, ip, ua, metadata)
	}
}

func (s *AdaptiveSecurityService) assessProvider(ctx context.Context, req RiskProviderRequest) *RiskProviderResponse {
	if s == nil || s.riskProvider == nil {
		return nil
	}
	resp, err := s.riskProvider.Assess(ctx, req)
	if err != nil {
		return &RiskProviderResponse{Signals: []domain.RiskSignal{{
			Type:   "risk_provider_error",
			Level:  domain.RiskLevelLow,
			Reason: err.Error(),
		}}}
	}
	return resp
}

func (s *AdaptiveSecurityService) createStepUpChallenge(ctx context.Context, clientID, userID, organizationID, action string, factors []string, ttl time.Duration) (string, error) {
	if s.cache == nil {
		return "", domain.ErrRedisRequired
	}
	token, err := GenerateToken(32)
	if err != nil {
		return "", err
	}
	state := stepUpState{
		ClientID:       clientID,
		UserID:         userID,
		OrganizationID: organizationID,
		Action:         action,
		Factors:        normalizeFactors(factors),
		ExpiresAt:      time.Now().UTC().Add(ttl),
	}
	stateJSON, _ := json.Marshal(state)
	if err := s.cache.Set(ctx, "stepup:challenge:"+HashToken(token), string(stateJSON), ttl); err != nil {
		return "", domain.ErrRedisRequired
	}
	return token, nil
}

func (s *AdaptiveSecurityService) validateStepUpToken(ctx context.Context, clientID, userID, organizationID, action, token string) error {
	if s == nil || s.cache == nil || strings.TrimSpace(token) == "" {
		return domain.ErrInvalidToken
	}
	state, err := s.loadStepUpState(ctx, "stepup:token:"+HashToken(token))
	if err != nil {
		return err
	}
	if state.ClientID != clientID || state.UserID != userID || state.Action != action {
		return domain.ErrInvalidToken
	}
	if strings.TrimSpace(state.OrganizationID) != strings.TrimSpace(organizationID) {
		return domain.ErrInvalidToken
	}
	if time.Now().UTC().After(state.ExpiresAt) {
		return domain.ErrInvalidToken
	}
	return nil
}

func (s *AdaptiveSecurityService) loadStepUpState(ctx context.Context, key string) (*stepUpState, error) {
	raw, err := s.cache.Get(ctx, key)
	if err != nil || raw == "" {
		return nil, domain.ErrInvalidToken
	}
	var state stepUpState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, domain.ErrInvalidToken
	}
	return &state, nil
}

type riskBuilder struct {
	score   int
	level   string
	signals []domain.RiskSignal
	context map[string]interface{}
}

func newRiskBuilder() *riskBuilder {
	return &riskBuilder{level: domain.RiskLevelLow, context: map[string]interface{}{}}
}

func (b *riskBuilder) add(signalType, level, reason string, metadata map[string]interface{}) {
	signalType = strings.TrimSpace(signalType)
	level = normalizeRiskLevel(level, domain.RiskLevelLow)
	if signalType == "" {
		signalType = "risk_signal"
	}
	b.signals = append(b.signals, domain.RiskSignal{Type: signalType, Level: level, Reason: reason, Metadata: metadata})
	points := riskScore(level)
	if points > b.score {
		b.score = points
	}
	if riskAtLeast(level, b.level) {
		b.level = level
	}
}

func (b *riskBuilder) assessment() domain.RiskAssessment {
	if b.level == "" {
		b.level = domain.RiskLevelLow
	}
	return domain.RiskAssessment{
		Level:   b.level,
		Score:   b.score,
		Signals: b.signals,
		Context: b.context,
	}
}

func decodeAdaptiveSecurityPolicy(raw interface{}, fallback domain.AdaptiveSecurityPolicy) domain.AdaptiveSecurityPolicy {
	if raw == nil {
		return fallback
	}
	payload, err := json.Marshal(raw)
	if err != nil {
		return fallback
	}
	var policy domain.AdaptiveSecurityPolicy
	if err := json.Unmarshal(payload, &policy); err != nil {
		return fallback
	}
	return policy
}

func normalizeActionPolicy(policy domain.StepUpActionPolicy) domain.StepUpActionPolicy {
	policy.Mode = normalizeMode(policy.Mode, []string{domain.StepUpModeOff, domain.StepUpModeChallenge, domain.StepUpModeBlock, domain.StepUpModeNotify}, domain.StepUpModeOff)
	if len(policy.Factors) == 0 {
		policy.Factors = []string{domain.MFAFactorTOTP, domain.MFAFactorRecoveryCode}
	} else {
		policy.Factors = normalizeFactors(policy.Factors)
	}
	if strings.TrimSpace(policy.RiskChallengeLevel) == "" {
		policy.RiskChallengeLevel = domain.RiskLevelMedium
	}
	if strings.TrimSpace(policy.RiskBlockLevel) == "" {
		policy.RiskBlockLevel = domain.RiskLevelCritical
	}
	if policy.MaxAgeSeconds <= 0 {
		policy.MaxAgeSeconds = int(defaultStepUpAge.Seconds())
	}
	return policy
}

func actionFactors(actionPolicy domain.StepUpActionPolicy, policy domain.AdaptiveSecurityPolicy) []string {
	if len(actionPolicy.Factors) > 0 {
		return normalizeFactors(actionPolicy.Factors)
	}
	return normalizeFactors(policy.MFA.Factors)
}

func adminActionFactors(actionPolicy domain.StepUpActionPolicy, policy domain.AdaptiveSecurityPolicy) []string {
	for _, factor := range actionFactors(actionPolicy, policy) {
		if factor == domain.MFAFactorTOTP {
			return []string{domain.MFAFactorTOTP}
		}
	}
	return []string{domain.MFAFactorTOTP}
}

func actionMaxAge(policy domain.StepUpActionPolicy) time.Duration {
	policy = normalizeActionPolicy(policy)
	return time.Duration(policy.MaxAgeSeconds) * time.Second
}

func normalizeMode(mode string, allowed []string, fallback string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	for _, candidate := range allowed {
		if mode == candidate {
			return mode
		}
	}
	return fallback
}

func normalizeRiskLevel(level, fallback string) string {
	level = strings.ToLower(strings.TrimSpace(level))
	switch level {
	case domain.RiskLevelLow, domain.RiskLevelMedium, domain.RiskLevelHigh, domain.RiskLevelCritical:
		return level
	default:
		return fallback
	}
}

func normalizeFactors(factors []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(factors))
	for _, factor := range factors {
		factor = strings.ToLower(strings.TrimSpace(factor))
		switch factor {
		case domain.MFAFactorTOTP, domain.MFAFactorRecoveryCode:
		default:
			continue
		}
		if _, ok := seen[factor]; ok {
			continue
		}
		seen[factor] = struct{}{}
		out = append(out, factor)
	}
	if len(out) == 0 {
		return []string{domain.MFAFactorTOTP, domain.MFAFactorRecoveryCode}
	}
	return out
}

func riskAtLeast(level, threshold string) bool {
	return riskRank(level) >= riskRank(threshold)
}

func riskRank(level string) int {
	switch normalizeRiskLevel(level, domain.RiskLevelLow) {
	case domain.RiskLevelCritical:
		return 4
	case domain.RiskLevelHigh:
		return 3
	case domain.RiskLevelMedium:
		return 2
	default:
		return 1
	}
}

func riskScore(level string) int {
	switch normalizeRiskLevel(level, domain.RiskLevelLow) {
	case domain.RiskLevelCritical:
		return 100
	case domain.RiskLevelHigh:
		return 80
	case domain.RiskLevelMedium:
		return 50
	default:
		return 10
	}
}

func riskHasSignal(risk domain.RiskAssessment, signalType string) bool {
	for _, signal := range risk.Signals {
		if signal.Type == signalType {
			return true
		}
	}
	return false
}

func providerRiskLevel(reputation string) string {
	switch strings.ToLower(strings.TrimSpace(reputation)) {
	case "critical", "malicious", "blocked":
		return domain.RiskLevelCritical
	case "high", "bad", "abuse":
		return domain.RiskLevelHigh
	case "medium", "suspicious", "unknown":
		return domain.RiskLevelMedium
	default:
		return domain.RiskLevelLow
	}
}

func ipMatchesAny(rawIP string, cidrs []string) bool {
	rawIP = strings.TrimSpace(rawIP)
	if rawIP == "" || len(cidrs) == 0 {
		return false
	}
	ip := net.ParseIP(rawIP)
	if ip == nil {
		return false
	}
	for _, rawCIDR := range cidrs {
		rawCIDR = strings.TrimSpace(rawCIDR)
		if rawCIDR == "" {
			continue
		}
		if candidate := net.ParseIP(rawCIDR); candidate != nil {
			if candidate.Equal(ip) {
				return true
			}
			continue
		}
		_, network, err := net.ParseCIDR(rawCIDR)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func intIn(value int, values []int) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsString(values []string, value string) bool {
	value = strings.TrimSpace(value)
	for _, candidate := range values {
		if strings.TrimSpace(candidate) == value {
			return true
		}
	}
	return false
}

func failedVelocityKey(clientID, email string) string {
	return "risk:failed_login:" + strings.TrimSpace(clientID) + ":" + strings.ToLower(strings.TrimSpace(email))
}

func deviceTrustExpired(device *domain.UserDevice) bool {
	if device == nil || !device.Trusted {
		return true
	}
	return device.TrustExpiresAt != nil && time.Now().UTC().After(*device.TrustExpiresAt)
}

func defaultDeviceName(name, ua string) string {
	name = strings.TrimSpace(name)
	if name != "" {
		return name
	}
	fp := deviceFingerprint(ua)
	if fp == "" {
		return "Device"
	}
	return strings.Title(strings.ReplaceAll(fp, "/", " "))
}

func impossibleTravel(device *domain.UserDevice, lat, lon float64) bool {
	if device == nil || device.Metadata == nil {
		return false
	}
	prevLat, okLat := floatFromMetadata(device.Metadata, "latitude")
	prevLon, okLon := floatFromMetadata(device.Metadata, "longitude")
	if !okLat || !okLon {
		return false
	}
	hours := time.Since(device.LastSeenAt).Hours()
	if hours <= 0 {
		hours = 0.1
	}
	speed := haversineKM(prevLat, prevLon, lat, lon) / hours
	return speed > 900
}

func floatFromMetadata(metadata map[string]interface{}, key string) (float64, bool) {
	switch v := metadata[key].(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case json.Number:
		out, err := v.Float64()
		return out, err == nil
	default:
		return 0, false
	}
}

func haversineKM(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKM = 6371
	toRad := func(deg float64) float64 { return deg * math.Pi / 180 }
	dLat := toRad(lat2 - lat1)
	dLon := toRad(lon2 - lon1)
	lat1 = toRad(lat1)
	lat2 = toRad(lat2)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1)*math.Cos(lat2)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return earthRadiusKM * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}
