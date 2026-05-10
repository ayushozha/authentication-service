package rest

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/pquerna/otp/totp"
)

func TestE2EAdaptiveLoginChallengesAndRemembersDevice(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{adaptive: true})
	env.clients.setSettings(env.client.ID, map[string]interface{}{"adaptive_security": domain.AdaptiveSecurityPolicy{
		MFA: domain.MFAPolicy{
			Mode:                domain.MFAModeAdaptive,
			ChallengeRiskLevel:  domain.RiskLevelMedium,
			BlockRiskLevel:      domain.RiskLevelCritical,
			Factors:             []string{domain.MFAFactorTOTP, domain.MFAFactorRecoveryCode},
			RememberDeviceDays:  30,
			TrustedDeviceBypass: true,
		},
	}})

	user := signupE2EUser(t, env, "adaptive-login@example.com", e2ePassword)
	secret := enableTOTPForE2EUser(t, env, user.AccessToken)

	riskHeaders := env.apiHeaders()
	riskHeaders["X-Forwarded-For"] = "203.0.113.71"
	riskHeaders["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/136.0.0.0 Safari/537.36"
	loginRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":        user.User.Email,
		"password":     e2ePassword,
		"session_mode": "token",
	}, riskHeaders)
	assertStatus(t, loginRec, http.StatusOK)
	var challenge application.AuthResponse
	decodeBody(t, loginRec, &challenge)
	if !challenge.Requires2FA || challenge.TwoFAToken == "" || challenge.Risk == nil {
		t.Fatalf("expected adaptive MFA challenge with risk, got %+v", challenge)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	verifyRec := env.request(t, http.MethodPost, "/api/auth/totp/verify", map[string]interface{}{
		"two_factor_token": challenge.TwoFAToken,
		"code":             code,
		"session_mode":     "token",
		"remember_device":  true,
		"device_name":      "Work laptop",
	}, riskHeaders)
	assertStatus(t, verifyRec, http.StatusOK)

	devicesRec := env.request(t, http.MethodGet, "/api/auth/devices", nil, env.bearerHeaders(user.AccessToken))
	assertStatus(t, devicesRec, http.StatusOK)
	var devicesPayload struct {
		Devices []domain.UserDevice `json:"devices"`
	}
	decodeBody(t, devicesRec, &devicesPayload)
	if len(devicesPayload.Devices) != 1 || !devicesPayload.Devices[0].Trusted {
		t.Fatalf("expected one trusted remembered device, got %+v", devicesPayload.Devices)
	}

	secondLoginRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":        user.User.Email,
		"password":     e2ePassword,
		"session_mode": "token",
	}, riskHeaders)
	assertStatus(t, secondLoginRec, http.StatusOK)
	var secondLogin application.AuthResponse
	decodeBody(t, secondLoginRec, &secondLogin)
	if secondLogin.Requires2FA || secondLogin.AccessToken == "" {
		t.Fatalf("trusted device should bypass adaptive challenge, got %+v", secondLogin)
	}
}

func TestE2EStepUpProtectsOrganizationMemberRoleChange(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{adaptive: true})
	owner := signupE2EUser(t, env, "step-up-owner@example.com", e2ePassword)
	member := signupE2EUser(t, env, "step-up-member@example.com", e2ePassword)
	secret := enableTOTPForE2EUser(t, env, owner.AccessToken)

	createRec := env.request(t, http.MethodPost, "/api/auth/organizations", map[string]string{
		"name": "Step Up Workspace",
	}, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, createRec, http.StatusCreated)
	var created domain.OrganizationMembershipDetails
	decodeBody(t, createRec, &created)
	orgID := created.Organization.ID

	policyRec := env.request(t, http.MethodPut, "/api/auth/organizations/"+orgID+"/security-policy", domain.AdaptiveSecurityPolicy{
		MFA: domain.MFAPolicy{Mode: domain.MFAModeAllow, Factors: []string{domain.MFAFactorTOTP, domain.MFAFactorRecoveryCode}},
		Actions: map[string]domain.StepUpActionPolicy{
			domain.SecurityActionOrganizationMemberRole: {
				Mode:               domain.StepUpModeChallenge,
				RiskChallengeLevel: domain.RiskLevelLow,
				MaxAgeSeconds:      600,
			},
		},
	}, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, policyRec, http.StatusOK)

	inviteRec := env.request(t, http.MethodPost, "/api/auth/organizations/"+orgID+"/invitations", map[string]string{
		"email": member.User.Email,
		"role":  domain.OrganizationRoleMember,
	}, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, inviteRec, http.StatusCreated)
	var invite domain.OrganizationInvitationWithToken
	decodeBody(t, inviteRec, &invite)
	acceptRec := env.request(t, http.MethodPost, "/api/auth/organization-invitations/accept", map[string]string{
		"token": invite.Token,
	}, env.bearerHeaders(member.AccessToken))
	assertStatus(t, acceptRec, http.StatusOK)

	updateBody := map[string]interface{}{
		"role":        domain.OrganizationRoleAdmin,
		"permissions": []string{"billing:manage"},
	}
	challengeRec := env.request(t, http.MethodPatch, "/api/auth/organizations/"+orgID+"/members/"+member.User.ID, updateBody, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, challengeRec, http.StatusForbidden)
	var challenge struct {
		Error          string   `json:"error"`
		ChallengeToken string   `json:"challenge_token"`
		Factors        []string `json:"factors"`
	}
	decodeBody(t, challengeRec, &challenge)
	if challenge.Error != "step_up_required" || challenge.ChallengeToken == "" {
		t.Fatalf("expected step-up challenge, got %+v", challenge)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate step-up code: %v", err)
	}
	verifyRec := env.request(t, http.MethodPost, "/api/auth/step-up/verify", map[string]string{
		"challenge_token": challenge.ChallengeToken,
		"factor":          domain.MFAFactorTOTP,
		"code":            code,
	}, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, verifyRec, http.StatusOK)
	var verified application.StepUpVerifyResponse
	decodeBody(t, verifyRec, &verified)
	if verified.StepUpToken == "" {
		t.Fatalf("expected step-up token, got %+v", verified)
	}

	headers := env.bearerHeaders(owner.AccessToken)
	headers["X-Step-Up-Token"] = verified.StepUpToken
	updateRec := env.request(t, http.MethodPatch, "/api/auth/organizations/"+orgID+"/members/"+member.User.ID, updateBody, headers)
	assertStatus(t, updateRec, http.StatusOK)
	var updated domain.OrganizationMembership
	decodeBody(t, updateRec, &updated)
	if updated.Role != domain.OrganizationRoleAdmin {
		t.Fatalf("expected role update after step-up, got %+v", updated)
	}
}

func TestE2EAdaptivePolicyBlocksHighRiskAdminKeyRotation(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{adaptive: true})
	env.clients.setSettings(env.client.ID, map[string]interface{}{"adaptive_security": domain.AdaptiveSecurityPolicy{
		Risk: domain.RiskPolicy{
			BlockLevel:     domain.RiskLevelCritical,
			BlockedIPCidrs: []string{"203.0.113.0/24"},
		},
		Actions: map[string]domain.StepUpActionPolicy{
			domain.SecurityActionClientKeyRotate: {
				Mode:           domain.StepUpModeNotify,
				RiskBlockLevel: domain.RiskLevelCritical,
			},
		},
	}})

	headers := map[string]string{
		"X-Admin-Key":     e2eAdminKey,
		"X-Forwarded-For": "203.0.113.25",
	}
	rotateRec := env.request(t, http.MethodPost, "/api/admin/clients/"+env.client.ID+"/rotate-api-key", nil, headers)
	assertStatus(t, rotateRec, http.StatusForbidden)
	if !strings.Contains(rotateRec.Body.String(), "blocked_by_security_policy") {
		t.Fatalf("expected policy block response, got %s", rotateRec.Body.String())
	}

	events, err := env.audit.List(context.Background(), domain.AuditEventFilter{ClientID: env.client.ID, EventType: "adaptive_security_admin_action_blocked", Limit: 10})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected adaptive security admin block audit event")
	}
}

func TestE2EAdaptiveAdminKeyRotationStepUpChallenge(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{adaptive: true})
	const adminTOTPSecret = "JBSWY3DPEHPK3PXP"
	createAdminRec := env.request(t, http.MethodPost, "/api/admin/users", map[string]interface{}{
		"email":        "adaptive-admin@example.com",
		"display_name": "Adaptive Admin",
		"password":     "AdaptiveAdmin123!",
		"roles":        []string{domain.AdminRoleSecurityAdmin},
		"scope_type":   domain.AdminScopeAll,
		"mfa_required": true,
		"totp_enabled": true,
		"totp_secret":  adminTOTPSecret,
	}, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, createAdminRec, http.StatusCreated)

	code, err := totp.GenerateCode(adminTOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("generate admin TOTP code: %v", err)
	}
	loginRec := env.request(t, http.MethodPost, "/api/admin/auth/login", map[string]string{
		"email":     "adaptive-admin@example.com",
		"password":  "AdaptiveAdmin123!",
		"totp_code": code,
	}, nil)
	assertStatus(t, loginRec, http.StatusOK)
	var login application.AdminAuthResponse
	decodeBody(t, loginRec, &login)
	if login.AccessToken == "" {
		t.Fatalf("expected admin access token, got %+v", login)
	}

	env.clients.setSettings(env.client.ID, map[string]interface{}{"adaptive_security": domain.AdaptiveSecurityPolicy{
		Actions: map[string]domain.StepUpActionPolicy{
			domain.SecurityActionClientKeyRotate: {
				Mode:               domain.StepUpModeChallenge,
				RiskChallengeLevel: domain.RiskLevelLow,
				MaxAgeSeconds:      600,
			},
		},
	}})

	adminHeaders := map[string]string{"Authorization": "Bearer " + login.AccessToken}
	challengeRec := env.request(t, http.MethodPost, "/api/admin/clients/"+env.client.ID+"/rotate-api-key", nil, adminHeaders)
	assertStatus(t, challengeRec, http.StatusForbidden)
	var challenge struct {
		Error          string   `json:"error"`
		ChallengeToken string   `json:"challenge_token"`
		Factors        []string `json:"factors"`
	}
	decodeBody(t, challengeRec, &challenge)
	if challenge.Error != "step_up_required" || challenge.ChallengeToken == "" || !containsString(challenge.Factors, domain.MFAFactorTOTP) {
		t.Fatalf("expected admin step-up challenge, got %+v", challenge)
	}

	stepUpCode, err := totp.GenerateCode(adminTOTPSecret, time.Now())
	if err != nil {
		t.Fatalf("generate admin step-up code: %v", err)
	}
	verifyRec := env.request(t, http.MethodPost, "/api/admin/step-up/verify", map[string]string{
		"challenge_token": challenge.ChallengeToken,
		"factor":          domain.MFAFactorTOTP,
		"code":            stepUpCode,
	}, adminHeaders)
	assertStatus(t, verifyRec, http.StatusOK)
	var verified application.StepUpVerifyResponse
	decodeBody(t, verifyRec, &verified)
	if verified.StepUpToken == "" {
		t.Fatalf("expected admin step-up token, got %+v", verified)
	}

	retryHeaders := map[string]string{
		"Authorization":   "Bearer " + login.AccessToken,
		"X-Step-Up-Token": verified.StepUpToken,
	}
	rotateRec := env.request(t, http.MethodPost, "/api/admin/clients/"+env.client.ID+"/rotate-api-key", nil, retryHeaders)
	assertStatus(t, rotateRec, http.StatusOK)
	if !strings.Contains(rotateRec.Body.String(), "api_key") {
		t.Fatalf("expected rotated api key response, got %s", rotateRec.Body.String())
	}
}

func enableTOTPForE2EUser(t *testing.T, env *e2eEnv, accessToken string) string {
	t.Helper()
	setupRec := env.request(t, http.MethodPost, "/api/auth/totp/setup", nil, env.bearerHeaders(accessToken))
	assertStatus(t, setupRec, http.StatusOK)
	var setup application.TOTPSetupResponse
	decodeBody(t, setupRec, &setup)
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	enableRec := env.request(t, http.MethodPost, "/api/auth/totp/enable", map[string]string{
		"code": code,
	}, env.bearerHeaders(accessToken))
	assertStatus(t, enableRec, http.StatusOK)
	return setup.Secret
}
