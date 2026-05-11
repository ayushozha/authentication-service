package rest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/oauth2"
)

const (
	e2eAdminKey = "admin-e2e-key"
	e2eAPIKey   = "client-e2e-api-key"
	e2ePassword = "ValidPass123!"
)

type e2eEnv struct {
	router  *Router
	handler http.Handler
	cfg     *HandlerConfig

	clients  *memoryClientRepo
	users    *memoryUserRepo
	sessions *memorySessionRepo
	tokens   *memoryTokenRepo
	cache    *memoryCache
	audit    *memoryAuditRepo
	admins   *memoryAdminRepo
	recovery *memoryRecoveryCodeRepo
	mailer   *recordingMailer
	rl       *memoryRateLimiter
	oauth    *memoryOAuthRepo
	webauthn *memoryWebAuthnRepo
	orgs     *memoryOrganizationRepo
	devices  *memoryDeviceRepo
	m2m      *memoryServiceAccountRepo
	sso      *memoryEnterpriseSSORepo
	scim     *memorySCIMRepo

	client *domain.Client
	apiKey string
}

type e2eOptions struct {
	oauthProviders map[string]*application.OAuthProviderConfig
	cache          application.CacheClient
	adaptive       bool
	riskProvider   application.RiskSignalProvider
}

func newE2EEnv(t *testing.T, opts e2eOptions) *e2eEnv {
	t.Helper()

	cache := opts.cache
	memCache, _ := cache.(*memoryCache)
	if cache == nil {
		memCache = newMemoryCache()
		cache = memCache
	}

	clients := newMemoryClientRepo()
	client := clients.addClient("client-a", "Client A", "client-a", e2eAPIKey)
	clients.setAllowedOrigins(client.ID, []string{"https://app.example.com"})
	client.AllowedOrigins = []string{"https://app.example.com"}

	users := newMemoryUserRepo()
	sessions := newMemorySessionRepo()
	tokens := newMemoryTokenRepo()
	recoveryCodes := newMemoryRecoveryCodeRepo()
	audit := &memoryAuditRepo{}
	adminRepo := newMemoryAdminRepo()
	mailer := &recordingMailer{}
	rl := newMemoryRateLimiter()
	oauthRepo := newMemoryOAuthRepo()
	webauthnRepo := newMemoryWebAuthnRepo()
	orgRepo := newMemoryOrganizationRepo()
	deviceRepo := newMemoryDeviceRepo()
	serviceAccountRepo := newMemoryServiceAccountRepo()
	ssoRepo := newMemoryEnterpriseSSORepo()
	scimRepo := newMemorySCIMRepo()

	clientSvc := application.NewClientService(clients)
	adminSvc := application.NewAdminService(adminRepo, audit, rl, e2eAdminKey, time.Hour)
	authSvc := application.NewAuthService(users, sessions, cache, audit, rl)
	verifySvc := application.NewEmailVerifyService(users, tokens, mailer)
	resetSvc := application.NewPasswordResetService(users, tokens, sessions, mailer)
	magicSvc := application.NewMagicLinkService(clients, users, sessions, cache, mailer, audit, rl)
	totpSvc := application.NewTOTPService(users, sessions, cache, audit, recoveryCodes)
	oauthSvc := application.NewOAuthService(users, clients, oauthRepo, sessions, cache, audit)
	auditSvc := application.NewAuditService(audit)
	orgSvc := application.NewOrganizationService(orgRepo, users, audit)
	var adaptiveSvc *application.AdaptiveSecurityService
	if opts.adaptive {
		adaptiveSvc = application.NewAdaptiveSecurityService(clients, orgRepo, users, sessions, deviceRepo, recoveryCodes, cache, audit, opts.riskProvider)
		adaptiveSvc.SetAdminUsers(adminRepo)
		authSvc.SetAdaptiveSecurity(adaptiveSvc)
		totpSvc.SetAdaptiveSecurity(adaptiveSvc)
	}
	m2mSvc := application.NewM2MService(serviceAccountRepo, clients, audit)
	ssoSvc := application.NewEnterpriseSSOService(ssoRepo, users, clients, sessions, cache, audit, orgRepo)
	authSvc.SetEnterpriseSSORepository(ssoRepo)
	resetSvc.SetEnterpriseSSORepository(ssoRepo)
	magicSvc.SetEnterpriseSSORepository(ssoRepo)
	oauthSvc.SetEnterpriseSSORepository(ssoRepo)
	scimSvc := application.NewSCIMService(scimRepo, users, audit, orgRepo)
	oidcSvc := application.NewOIDCService(clients, users, sessions, cache, audit)
	passkeySvc, err := application.NewPasskeyService(users, webauthnRepo, sessions, cache, audit, "E2E Auth", "example.com", "https://example.com")
	if err != nil {
		t.Fatalf("new passkey service: %v", err)
	}

	verifySvc.WireSignupHook("https://auth.example.com")
	application.SetSigningKeyRepository(&signingKeyRepoRouteStub{})
	t.Cleanup(func() {
		application.OnSignup = nil
		application.SetSigningKeyRepository(nil)
		application.SetBlockedSignupEmailDomains(defaultBlockedSignupEmailDomains())
	})

	cfg := &HandlerConfig{
		AllowOrigin:    "*",
		BaseURL:        "https://auth.example.com",
		Cache:          cache,
		BcryptCost:     10,
		AccessTTL:      15 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		CookieSameSite: "lax",
	}
	router := NewRouter(
		authSvc, verifySvc, resetSvc, magicSvc, totpSvc,
		oauthSvc, passkeySvc, adminSvc, clientSvc, auditSvc, orgSvc, adaptiveSvc, m2mSvc, ssoSvc, scimSvc,
		nil, oidcSvc,
		opts.oauthProviders, cfg,
		e2eAdminKey, false, "",
	)

	return &e2eEnv{
		router:   router,
		handler:  router.Handler(),
		cfg:      cfg,
		clients:  clients,
		users:    users,
		sessions: sessions,
		tokens:   tokens,
		cache:    memCache,
		audit:    audit,
		admins:   adminRepo,
		recovery: recoveryCodes,
		mailer:   mailer,
		rl:       rl,
		oauth:    oauthRepo,
		webauthn: webauthnRepo,
		orgs:     orgRepo,
		devices:  deviceRepo,
		m2m:      serviceAccountRepo,
		sso:      ssoRepo,
		scim:     scimRepo,
		client:   client,
		apiKey:   e2eAPIKey,
	}
}

func TestE2EEmailPasswordSessionLifecycle(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{})

	signupRec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]interface{}{
		"email":        "Alice@Example.com",
		"password":     e2ePassword,
		"display_name": "Alice",
		"session_mode": "token",
	}, env.apiHeaders())
	assertStatus(t, signupRec, http.StatusCreated)
	var signup application.AuthResponse
	decodeBody(t, signupRec, &signup)
	if signup.AccessToken == "" || signup.RefreshToken == "" {
		t.Fatalf("signup should return access and refresh tokens in token mode: %+v", signup)
	}
	if signup.User.Email != "alice@example.com" {
		t.Fatalf("expected normalized email, got %q", signup.User.Email)
	}

	dupRec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]interface{}{
		"email":    "alice@example.com",
		"password": e2ePassword,
	}, env.apiHeaders())
	assertStatus(t, dupRec, http.StatusConflict)

	weakRec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]interface{}{
		"email":    "weak@example.com",
		"password": "short",
	}, env.apiHeaders())
	assertStatus(t, weakRec, http.StatusBadRequest)

	commonPasswordRec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]interface{}{
		"email":    "common-password@example.com",
		"password": "password123",
	}, env.apiHeaders())
	assertStatus(t, commonPasswordRec, http.StatusBadRequest)

	blockedEmailDomainRec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]interface{}{
		"email":    "throwaway@mailinator.com",
		"password": e2ePassword,
	}, env.apiHeaders())
	assertStatus(t, blockedEmailDomainRec, http.StatusBadRequest)

	invalidSignupHeaders := env.apiHeaders()
	invalidSignupHeaders["X-Forwarded-For"] = "198.51.100.64"
	invalidSignupEmailRec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]interface{}{
		"email":    "Alice <alice@example.com>",
		"password": e2ePassword,
	}, invalidSignupHeaders)
	assertStatus(t, invalidSignupEmailRec, http.StatusBadRequest)

	invalidLoginEmailRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":    "alice",
		"password": e2ePassword,
	}, env.apiHeaders())
	assertStatus(t, invalidLoginEmailRec, http.StatusBadRequest)
	var invalidLoginEmail map[string]string
	decodeBody(t, invalidLoginEmailRec, &invalidLoginEmail)
	if invalidLoginEmail["error"] != domain.ErrInvalidEmail.Error() {
		t.Fatalf("expected invalid email error, got %q", invalidLoginEmail["error"])
	}

	invalidMagicEmailRec := env.request(t, http.MethodPost, "/api/auth/magic-link/send", map[string]string{
		"email": "not-an-email",
	}, env.apiHeaders())
	assertStatus(t, invalidMagicEmailRec, http.StatusBadRequest)

	invalidForgotEmailRec := env.request(t, http.MethodPost, "/api/auth/forgot-password", map[string]string{
		"email": "not-an-email",
	}, env.apiHeaders())
	assertStatus(t, invalidForgotEmailRec, http.StatusBadRequest)

	meRec := env.request(t, http.MethodGet, "/api/auth/me", nil, env.bearerHeaders(signup.AccessToken))
	assertStatus(t, meRec, http.StatusOK)

	patchRec := env.request(t, http.MethodPatch, "/api/auth/me", map[string]string{
		"display_name": "Alice Updated",
		"timezone":     "America/Los_Angeles",
	}, env.bearerHeaders(signup.AccessToken))
	assertStatus(t, patchRec, http.StatusOK)
	var patched domain.User
	decodeBody(t, patchRec, &patched)
	if patched.DisplayName != "Alice Updated" || patched.Timezone != "America/Los_Angeles" {
		t.Fatalf("profile was not updated: %+v", patched)
	}

	refreshRec := env.request(t, http.MethodPost, "/api/auth/refresh", map[string]string{
		"refresh_token": signup.RefreshToken,
		"session_mode":  "token",
	}, env.apiHeaders())
	assertStatus(t, refreshRec, http.StatusOK)
	var refreshed application.AuthResponse
	decodeBody(t, refreshRec, &refreshed)
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" || refreshed.RefreshToken == signup.RefreshToken {
		t.Fatalf("refresh should rotate tokens: %+v", refreshed)
	}

	reuseRec := env.request(t, http.MethodPost, "/api/auth/refresh", map[string]string{
		"refresh_token": signup.RefreshToken,
		"session_mode":  "token",
	}, env.apiHeaders())
	assertStatus(t, reuseRec, http.StatusUnauthorized)

	badLoginRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":        "alice@example.com",
		"password":     "wrong-password",
		"session_mode": "token",
	}, env.apiHeaders())
	assertStatus(t, badLoginRec, http.StatusUnauthorized)

	loginRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":        "alice@example.com",
		"password":     e2ePassword,
		"session_mode": "token",
	}, env.apiHeaders())
	assertStatus(t, loginRec, http.StatusOK)
	var login application.AuthResponse
	decodeBody(t, loginRec, &login)

	sessionsRec := env.request(t, http.MethodGet, "/api/auth/sessions", nil, env.bearerHeaders(login.AccessToken))
	assertStatus(t, sessionsRec, http.StatusOK)
	var sessionsBody struct {
		Sessions []domain.Session `json:"sessions"`
	}
	decodeBody(t, sessionsRec, &sessionsBody)
	if len(sessionsBody.Sessions) < 2 {
		t.Fatalf("expected active sessions from refresh and login, got %+v", sessionsBody.Sessions)
	}
	revokedSessionID := sessionsBody.Sessions[0].ID
	revokeSessionRec := env.request(t, http.MethodDelete, "/api/auth/sessions/"+revokedSessionID, nil, env.bearerHeaders(login.AccessToken))
	assertStatus(t, revokeSessionRec, http.StatusOK)
	sessionsAfterRevokeRec := env.request(t, http.MethodGet, "/api/auth/sessions", nil, env.bearerHeaders(login.AccessToken))
	assertStatus(t, sessionsAfterRevokeRec, http.StatusOK)
	var sessionsAfterRevoke struct {
		Sessions []domain.Session `json:"sessions"`
	}
	decodeBody(t, sessionsAfterRevokeRec, &sessionsAfterRevoke)
	for _, session := range sessionsAfterRevoke.Sessions {
		if session.ID == revokedSessionID {
			t.Fatalf("revoked session still listed: %+v", sessionsAfterRevoke.Sessions)
		}
	}

	riskHeaders := env.apiHeaders()
	riskHeaders["X-Forwarded-For"] = "203.0.113.44"
	riskHeaders["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/136.0.0.0 Safari/537.36"
	riskLoginRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":        "alice@example.com",
		"password":     e2ePassword,
		"session_mode": "token",
	}, riskHeaders)
	assertStatus(t, riskLoginRec, http.StatusOK)
	var riskLogin application.AuthResponse
	decodeBody(t, riskLoginRec, &riskLogin)
	if riskLogin.Risk == nil || riskLogin.Risk.Level != "medium" || !riskLogin.Risk.NewIP || !riskLogin.Risk.NewDevice {
		t.Fatalf("expected medium suspicious-login risk response, got %+v", riskLogin.Risk)
	}

	userInfoPasswordRec := env.request(t, http.MethodPost, "/api/auth/change-password", map[string]string{
		"old_password": e2ePassword,
		"new_password": "alice2026!",
	}, env.bearerHeaders(login.AccessToken))
	assertStatus(t, userInfoPasswordRec, http.StatusBadRequest)
	riskEvents, err := env.audit.List(context.Background(), domain.AuditEventFilter{ClientID: env.client.ID, Limit: 100})
	if err != nil {
		t.Fatalf("list risk audit events: %v", err)
	}
	for _, eventType := range []string{"signup_blocked", "password_change_blocked", "session_revoked", "suspicious_login"} {
		if !auditEventsContain(riskEvents, eventType) {
			t.Fatalf("expected risk audit event %q in %+v", eventType, riskEvents)
		}
	}

	changeRec := env.request(t, http.MethodPost, "/api/auth/change-password", map[string]string{
		"old_password": e2ePassword,
		"new_password": "newpassword123",
	}, env.bearerHeaders(login.AccessToken))
	assertStatus(t, changeRec, http.StatusOK)

	oldRefreshRec := env.request(t, http.MethodPost, "/api/auth/refresh", map[string]string{
		"refresh_token": login.RefreshToken,
		"session_mode":  "token",
	}, env.apiHeaders())
	assertStatus(t, oldRefreshRec, http.StatusUnauthorized)

	oldPasswordRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":        "alice@example.com",
		"password":     e2ePassword,
		"session_mode": "token",
	}, env.apiHeaders())
	assertStatus(t, oldPasswordRec, http.StatusUnauthorized)

	newPasswordRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":        "alice@example.com",
		"password":     "newpassword123",
		"session_mode": "token",
	}, env.apiHeaders())
	assertStatus(t, newPasswordRec, http.StatusOK)
	var newLogin application.AuthResponse
	decodeBody(t, newPasswordRec, &newLogin)

	logoutRec := env.request(t, http.MethodPost, "/api/auth/logout", map[string]string{
		"refresh_token": newLogin.RefreshToken,
	}, env.apiHeaders())
	assertStatus(t, logoutRec, http.StatusOK)

	afterLogoutRec := env.request(t, http.MethodPost, "/api/auth/refresh", map[string]string{
		"refresh_token": newLogin.RefreshToken,
		"session_mode":  "token",
	}, env.apiHeaders())
	assertStatus(t, afterLogoutRec, http.StatusUnauthorized)
}

func TestE2ERefreshTransportContract(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{})

	cookieSignupRec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]interface{}{
		"email":    "cookie-transport@example.com",
		"password": e2ePassword,
	}, env.apiHeaders())
	assertStatus(t, cookieSignupRec, http.StatusCreated)
	var cookieSignup application.AuthResponse
	decodeBody(t, cookieSignupRec, &cookieSignup)
	if cookieSignup.AccessToken == "" || cookieSignup.RefreshToken != "" || cookieSignup.Refresh == nil {
		t.Fatalf("cookie transport should return access token and refresh metadata only: %+v", cookieSignup)
	}
	if cookieSignup.Refresh.Transport != "cookie" || cookieSignup.Refresh.CookieName != "auth_refresh" || cookieSignup.Refresh.ExpiresIn != int(env.cfg.RefreshTTL.Seconds()) {
		t.Fatalf("unexpected cookie refresh metadata: %+v", cookieSignup.Refresh)
	}
	var refreshCookie *http.Cookie
	for _, cookie := range cookieSignupRec.Result().Cookies() {
		if cookie.Name == "auth_refresh" {
			refreshCookie = cookie
			break
		}
	}
	if refreshCookie == nil || refreshCookie.Value == "" {
		t.Fatalf("cookie transport should set auth_refresh cookie: %v", cookieSignupRec.Result().Cookies())
	}

	refreshReq := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", strings.NewReader("{}"))
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshReq.Header.Set("X-API-Key", env.apiKey)
	refreshReq.AddCookie(refreshCookie)
	refreshRec := httptest.NewRecorder()
	env.handler.ServeHTTP(refreshRec, refreshReq)
	assertStatus(t, refreshRec, http.StatusOK)
	var cookieRefresh application.AuthResponse
	decodeBody(t, refreshRec, &cookieRefresh)
	if cookieRefresh.AccessToken == "" || cookieRefresh.RefreshToken != "" || cookieRefresh.Refresh == nil || cookieRefresh.Refresh.Transport != "cookie" {
		t.Fatalf("cookie refresh should rotate cookie and return cookie metadata: %+v", cookieRefresh)
	}

	jsonLoginRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":           "cookie-transport@example.com",
		"password":        e2ePassword,
		"token_transport": "json",
	}, env.apiHeaders())
	assertStatus(t, jsonLoginRec, http.StatusOK)
	var jsonLogin application.AuthResponse
	decodeBody(t, jsonLoginRec, &jsonLogin)
	if jsonLogin.AccessToken == "" || jsonLogin.RefreshToken == "" || jsonLogin.Refresh == nil || jsonLogin.Refresh.Transport != "json" {
		t.Fatalf("json transport should return refresh token and metadata: %+v", jsonLogin)
	}

	missingRefreshRec := env.request(t, http.MethodPost, "/api/auth/refresh", map[string]string{}, env.apiHeaders())
	assertStatus(t, missingRefreshRec, http.StatusBadRequest)
	var missingRefresh errorPayload
	decodeBody(t, missingRefreshRec, &missingRefresh)
	if missingRefresh.Code != "refresh_token_missing" {
		t.Fatalf("expected refresh_token_missing, got %+v", missingRefresh)
	}
}

func TestE2EEmailVerificationPasswordResetMagicLinkAndTOTP(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{})

	signup := signupE2EUser(t, env, "bob@example.com", e2ePassword)
	verifyToken := env.tokens.latestFor(t, signup.User.ID, "email_verify")

	verifyRec := env.request(t, http.MethodPost, "/api/auth/verify-email", map[string]string{
		"token": verifyToken,
	}, nil)
	assertStatus(t, verifyRec, http.StatusOK)
	if user := env.users.mustGet(t, signup.User.ID); !user.EmailVerified {
		t.Fatalf("expected email to be verified")
	}

	reuseVerifyRec := env.request(t, http.MethodPost, "/api/auth/verify-email", map[string]string{
		"token": verifyToken,
	}, nil)
	assertStatus(t, reuseVerifyRec, http.StatusBadRequest)

	forgotRec := env.request(t, http.MethodPost, "/api/auth/forgot-password", map[string]string{
		"email": "bob@example.com",
	}, env.apiHeaders())
	assertStatus(t, forgotRec, http.StatusOK)
	resetToken := env.tokens.latestFor(t, signup.User.ID, "password_reset")

	resetRec := env.request(t, http.MethodPost, "/api/auth/reset-password", map[string]string{
		"token":        resetToken,
		"new_password": "resetpassword123",
	}, nil)
	assertStatus(t, resetRec, http.StatusOK)

	oldLoginRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":        "bob@example.com",
		"password":     e2ePassword,
		"session_mode": "token",
	}, env.apiHeaders())
	assertStatus(t, oldLoginRec, http.StatusUnauthorized)

	magicSendRec := env.request(t, http.MethodPost, "/api/auth/magic-link/send", map[string]string{
		"email": "bob@example.com",
	}, env.apiHeaders())
	assertStatus(t, magicSendRec, http.StatusOK)
	magicURL := env.mailer.waitForMagicURL(t)
	magicToken := tokenFromURL(t, magicURL)

	magicVerifyRec := env.request(t, http.MethodGet, "/api/auth/magic-link/verify?session_mode=token&token="+url.QueryEscape(magicToken), nil, map[string]string{
		"Accept": "application/json",
	})
	assertStatus(t, magicVerifyRec, http.StatusOK)
	var magicLogin application.AuthResponse
	decodeBody(t, magicVerifyRec, &magicLogin)
	if magicLogin.AccessToken == "" || magicLogin.RefreshToken == "" {
		t.Fatalf("magic link verify should authenticate in token mode: %+v", magicLogin)
	}

	magicReuseRec := env.request(t, http.MethodGet, "/api/auth/magic-link/verify?token="+url.QueryEscape(magicToken), nil, map[string]string{
		"Accept": "application/json",
	})
	assertStatus(t, magicReuseRec, http.StatusBadRequest)

	setupRec := env.request(t, http.MethodPost, "/api/auth/totp/setup", nil, env.bearerHeaders(magicLogin.AccessToken))
	assertStatus(t, setupRec, http.StatusOK)
	var setup application.TOTPSetupResponse
	decodeBody(t, setupRec, &setup)
	if setup.Secret == "" || setup.URI == "" || setup.QR == "" {
		t.Fatalf("unexpected totp setup response: %+v", setup)
	}

	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	enableRec := env.request(t, http.MethodPost, "/api/auth/totp/enable", map[string]string{
		"code": code,
	}, env.bearerHeaders(magicLogin.AccessToken))
	assertStatus(t, enableRec, http.StatusOK)

	recoveryCodesRec := env.request(t, http.MethodPost, "/api/auth/recovery-codes", nil, env.bearerHeaders(magicLogin.AccessToken))
	assertStatus(t, recoveryCodesRec, http.StatusOK)
	var recoveryCodes application.RecoveryCodesResponse
	decodeBody(t, recoveryCodesRec, &recoveryCodes)
	if recoveryCodes.UnusedCount != 10 || len(recoveryCodes.RecoveryCodes) != 10 {
		t.Fatalf("expected one-time recovery codes, got %+v", recoveryCodes)
	}

	recoveryCountRec := env.request(t, http.MethodGet, "/api/auth/recovery-codes", nil, env.bearerHeaders(magicLogin.AccessToken))
	assertStatus(t, recoveryCountRec, http.StatusOK)
	var recoveryCount application.RecoveryCodesResponse
	decodeBody(t, recoveryCountRec, &recoveryCount)
	if recoveryCount.UnusedCount != 10 || len(recoveryCount.RecoveryCodes) != 0 {
		t.Fatalf("recovery code count should not expose codes: %+v", recoveryCount)
	}

	challengeRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":        "bob@example.com",
		"password":     "resetpassword123",
		"session_mode": "token",
	}, env.apiHeaders())
	assertStatus(t, challengeRec, http.StatusOK)
	var challenge application.AuthResponse
	decodeBody(t, challengeRec, &challenge)
	if !challenge.Requires2FA || challenge.TwoFAToken == "" || !containsString(challenge.TwoFAMethods, "totp") || !containsString(challenge.TwoFAMethods, "recovery_code") {
		t.Fatalf("expected 2FA challenge, got %+v", challenge)
	}
	if challenge.AccessToken != "" || challenge.RefreshToken != "" {
		t.Fatalf("2FA challenge must not include session tokens: %+v", challenge)
	}

	badTOTPRec := env.request(t, http.MethodPost, "/api/auth/totp/verify", map[string]string{
		"two_factor_token": challenge.TwoFAToken,
		"code":             "000000",
		"session_mode":     "token",
	}, env.apiHeaders())
	assertStatus(t, badTOTPRec, http.StatusUnauthorized)

	validCode, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	verifyTOTPRec := env.request(t, http.MethodPost, "/api/auth/totp/verify", map[string]string{
		"two_factor_token": challenge.TwoFAToken,
		"code":             validCode,
		"token_transport":  "json",
	}, env.apiHeaders())
	assertStatus(t, verifyTOTPRec, http.StatusOK)
	var twoFALogin application.AuthResponse
	decodeBody(t, verifyTOTPRec, &twoFALogin)
	if twoFALogin.AccessToken == "" || twoFALogin.RefreshToken == "" {
		t.Fatalf("2FA verify should issue tokens: %+v", twoFALogin)
	}
	if twoFALogin.Refresh == nil || twoFALogin.Refresh.Transport != "json" || twoFALogin.Refresh.ExpiresIn <= 0 {
		t.Fatalf("2FA verify should describe JSON refresh transport: %+v", twoFALogin.Refresh)
	}

	recoveryChallengeRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":        "bob@example.com",
		"password":     "resetpassword123",
		"session_mode": "token",
	}, env.apiHeaders())
	assertStatus(t, recoveryChallengeRec, http.StatusOK)
	var recoveryChallenge application.AuthResponse
	decodeBody(t, recoveryChallengeRec, &recoveryChallenge)
	if !recoveryChallenge.Requires2FA || recoveryChallenge.TwoFAToken == "" {
		t.Fatalf("expected recovery-code 2FA challenge, got %+v", recoveryChallenge)
	}
	recoveryVerifyRec := env.request(t, http.MethodPost, "/api/auth/recovery-codes/verify", map[string]string{
		"two_factor_token": recoveryChallenge.TwoFAToken,
		"code":             recoveryCodes.RecoveryCodes[0],
		"token_transport":  "json",
	}, env.apiHeaders())
	assertStatus(t, recoveryVerifyRec, http.StatusOK)
	var recoveryLogin application.AuthResponse
	decodeBody(t, recoveryVerifyRec, &recoveryLogin)
	if recoveryLogin.AccessToken == "" || recoveryLogin.RefreshToken == "" {
		t.Fatalf("recovery code verify should issue tokens: %+v", recoveryLogin)
	}
	if recoveryLogin.Refresh == nil || recoveryLogin.Refresh.Transport != "json" || recoveryLogin.Refresh.ExpiresIn <= 0 {
		t.Fatalf("recovery code verify should describe JSON refresh transport: %+v", recoveryLogin.Refresh)
	}
	recoveryCountAfterUseRec := env.request(t, http.MethodGet, "/api/auth/recovery-codes", nil, env.bearerHeaders(recoveryLogin.AccessToken))
	assertStatus(t, recoveryCountAfterUseRec, http.StatusOK)
	var recoveryCountAfterUse application.RecoveryCodesResponse
	decodeBody(t, recoveryCountAfterUseRec, &recoveryCountAfterUse)
	if recoveryCountAfterUse.UnusedCount != 9 {
		t.Fatalf("expected one recovery code to be consumed, got %+v", recoveryCountAfterUse)
	}

	reuseChallengeRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":        "bob@example.com",
		"password":     "resetpassword123",
		"session_mode": "token",
	}, env.apiHeaders())
	assertStatus(t, reuseChallengeRec, http.StatusOK)
	var reuseChallenge application.AuthResponse
	decodeBody(t, reuseChallengeRec, &reuseChallenge)
	reuseRecoveryRec := env.request(t, http.MethodPost, "/api/auth/recovery-codes/verify", map[string]string{
		"two_factor_token": reuseChallenge.TwoFAToken,
		"code":             recoveryCodes.RecoveryCodes[0],
		"session_mode":     "token",
	}, env.apiHeaders())
	assertStatus(t, reuseRecoveryRec, http.StatusUnauthorized)

	disableCode, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	disableRec := env.request(t, http.MethodPost, "/api/auth/totp/disable", map[string]string{
		"code": disableCode,
	}, env.bearerHeaders(recoveryLogin.AccessToken))
	assertStatus(t, disableRec, http.StatusOK)

	postDisableLoginRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":        "bob@example.com",
		"password":     "resetpassword123",
		"session_mode": "token",
	}, env.apiHeaders())
	assertStatus(t, postDisableLoginRec, http.StatusOK)
	var postDisableLogin application.AuthResponse
	decodeBody(t, postDisableLoginRec, &postDisableLogin)
	if postDisableLogin.Requires2FA || postDisableLogin.AccessToken == "" {
		t.Fatalf("login after TOTP disable should not require 2FA: %+v", postDisableLogin)
	}
}

func TestE2ETenantIsolationAdminAndAbuseControls(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{})

	noAPIKeyRec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]string{
		"email":    "missing@example.com",
		"password": e2ePassword,
	}, nil)
	assertStatus(t, noAPIKeyRec, http.StatusUnauthorized)
	var noAPIKey errorPayload
	decodeBody(t, noAPIKeyRec, &noAPIKey)
	if noAPIKey.Code != "missing_api_key" {
		t.Fatalf("expected missing_api_key code, got %+v", noAPIKey)
	}

	blockedOriginRec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]string{
		"email":    "origin@example.com",
		"password": e2ePassword,
	}, map[string]string{
		"X-API-Key": env.apiKey,
		"Origin":    "https://evil.example.com",
	})
	assertStatus(t, blockedOriginRec, http.StatusForbidden)

	allowedOriginRec := env.request(t, http.MethodOptions, "/api/auth/signup", nil, map[string]string{
		"X-API-Key": env.apiKey,
		"Origin":    "https://app.example.com",
	})
	assertStatus(t, allowedOriginRec, http.StatusNoContent)
	allowedOriginSignupRec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]string{
		"email":    "allowed-origin@example.com",
		"password": e2ePassword,
	}, map[string]string{
		"X-API-Key": env.apiKey,
		"Origin":    "https://app.example.com",
	})
	assertStatus(t, allowedOriginSignupRec, http.StatusCreated)
	if got := allowedOriginSignupRec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("expected tenant CORS origin, got %q", got)
	}

	noAdminRec := env.request(t, http.MethodGet, "/api/admin/clients", nil, nil)
	assertStatus(t, noAdminRec, http.StatusUnauthorized)

	createClientRec := env.request(t, http.MethodPost, "/api/admin/clients", map[string]interface{}{
		"name":            "Client B",
		"slug":            "client-b",
		"allowed_origins": []string{"https://b.example.com"},
	}, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, createClientRec, http.StatusCreated)
	var created application.CreateClientResponse
	decodeBody(t, createClientRec, &created)
	if created.Client.ID == "" || created.APIKey == "" || created.JWTSecret == "" {
		t.Fatalf("admin create client returned incomplete payload: %+v", created)
	}

	updateClientRec := env.request(t, http.MethodPatch, "/api/admin/clients/"+created.Client.ID, map[string]interface{}{
		"settings": map[string]interface{}{
			"webauthn_attestation":                 "enterprise",
			"webauthn_require_attestation":         true,
			"webauthn_allowed_attestation_formats": []string{"packed", "tpm"},
		},
	}, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, updateClientRec, http.StatusOK)
	var updatedClient domain.Client
	decodeBody(t, updateClientRec, &updatedClient)
	if updatedClient.Settings["webauthn_attestation"] != "enterprise" || updatedClient.Settings["webauthn_require_attestation"] != true {
		t.Fatalf("client settings were not updated: %+v", updatedClient.Settings)
	}

	listClientRec := env.request(t, http.MethodGet, "/api/admin/clients", nil, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, listClientRec, http.StatusOK)

	rotateAPIKeyRec := env.request(t, http.MethodPost, "/api/admin/clients/"+created.Client.ID+"/rotate-api-key", nil, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, rotateAPIKeyRec, http.StatusOK)
	var rotated map[string]interface{}
	decodeBody(t, rotateAPIKeyRec, &rotated)
	newAPIKey, _ := rotated["api_key"].(string)
	if newAPIKey == "" || newAPIKey == created.APIKey {
		t.Fatalf("expected rotated api key, got %#v", rotated)
	}

	alice := signupE2EUser(t, env, "tenant-a@example.com", e2ePassword)
	clientBSignupRec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]interface{}{
		"email":        "tenant-b@example.com",
		"password":     e2ePassword,
		"session_mode": "token",
	}, map[string]string{"X-API-Key": newAPIKey})
	assertStatus(t, clientBSignupRec, http.StatusCreated)
	var clientBSignup application.AuthResponse
	decodeBody(t, clientBSignupRec, &clientBSignup)

	crossTenantMeRec := env.request(t, http.MethodGet, "/api/auth/me", nil, map[string]string{
		"X-API-Key":     newAPIKey,
		"Authorization": "Bearer " + alice.AccessToken,
	})
	assertStatus(t, crossTenantMeRec, http.StatusUnauthorized)

	crossTenantRefreshRec := env.request(t, http.MethodPost, "/api/auth/refresh", map[string]string{
		"refresh_token": alice.RefreshToken,
		"session_mode":  "token",
	}, map[string]string{"X-API-Key": newAPIKey})
	assertStatus(t, crossTenantRefreshRec, http.StatusUnauthorized)

	clientBMeRec := env.request(t, http.MethodGet, "/api/auth/me", nil, map[string]string{
		"X-API-Key":     newAPIKey,
		"Authorization": "Bearer " + clientBSignup.AccessToken,
	})
	assertStatus(t, clientBMeRec, http.StatusOK)

	for i := 0; i < 6; i++ {
		rec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]string{
			"email":    fmt.Sprintf("burst-%d@example.com", i),
			"password": e2ePassword,
		}, map[string]string{
			"X-API-Key":       env.apiKey,
			"X-Forwarded-For": "203.0.113.10",
		})
		if i < 5 {
			assertStatus(t, rec, http.StatusCreated)
		} else {
			assertStatus(t, rec, http.StatusTooManyRequests)
			if rec.Header().Get("Retry-After") == "" {
				t.Fatal("expected Retry-After header on signup rate limit")
			}
		}
	}

	locked := signupE2EUser(t, env, "locked@example.com", e2ePassword)
	if locked.User.ID == "" {
		t.Fatalf("expected locked user id")
	}
	for i := 0; i < 5; i++ {
		rec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
			"email":    "locked@example.com",
			"password": "wrong-password",
		}, map[string]string{
			"X-API-Key":       env.apiKey,
			"X-Forwarded-For": "198.51.100.25",
		})
		assertStatus(t, rec, http.StatusUnauthorized)
	}
	lockedRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":    "locked@example.com",
		"password": e2ePassword,
	}, map[string]string{
		"X-API-Key":       env.apiKey,
		"X-Forwarded-For": "198.51.100.25",
	})
	assertStatus(t, lockedRec, http.StatusTooManyRequests)
	if lockedRec.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on account lock")
	}

	auditRec := env.request(t, http.MethodGet, "/api/admin/audit-events?client_id="+url.QueryEscape(env.client.ID)+"&event_type=signup&limit=3", nil, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, auditRec, http.StatusOK)
	var auditPayload struct {
		Events []domain.AuditEvent `json:"events"`
	}
	decodeBody(t, auditRec, &auditPayload)
	if len(auditPayload.Events) == 0 || len(auditPayload.Events) > 3 {
		t.Fatalf("expected 1-3 filtered audit events, got %+v", auditPayload.Events)
	}
	for _, event := range auditPayload.Events {
		if event.ClientID != env.client.ID || event.EventType != "signup" {
			t.Fatalf("unexpected audit event returned by filter: %+v", event)
		}
	}

	auditCSVRec := env.request(t, http.MethodGet, "/api/admin/audit-events/export?client_id="+url.QueryEscape(env.client.ID)+"&event_type=signup&limit=2&format=csv", nil, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, auditCSVRec, http.StatusOK)
	if contentType := auditCSVRec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/csv") {
		t.Fatalf("expected CSV content type, got %q", contentType)
	}
	if body := auditCSVRec.Body.String(); !strings.Contains(body, "event_type") || !strings.Contains(body, "signup") {
		t.Fatalf("audit CSV export missing expected data: %s", body)
	}

	auditJSONLRec := env.request(t, http.MethodGet, "/api/admin/audit-events/export?client_id="+url.QueryEscape(env.client.ID)+"&event_type=signup&limit=1&format=jsonl", nil, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, auditJSONLRec, http.StatusOK)
	if contentType := auditJSONLRec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/x-ndjson") {
		t.Fatalf("expected NDJSON content type, got %q", contentType)
	}
	if body := auditJSONLRec.Body.String(); !strings.Contains(body, `"event_type":"signup"`) {
		t.Fatalf("audit JSONL export missing expected data: %s", body)
	}

	badAuditLimitRec := env.request(t, http.MethodGet, "/api/admin/audit-events?limit=not-a-number", nil, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, badAuditLimitRec, http.StatusBadRequest)

	badAuditFormatRec := env.request(t, http.MethodGet, "/api/admin/audit-events/export?format=xml", nil, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, badAuditFormatRec, http.StatusBadRequest)
}

func TestE2EOAuthAndPasskeyRouteCoverage(t *testing.T) {
	var providerURL string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			if r.FormValue("code") != "oauth-code" || r.FormValue("code_verifier") == "" {
				t.Fatalf("unexpected token exchange form: %s", r.Form.Encode())
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"access_token":  "provider-access",
				"refresh_token": "provider-refresh",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		case "/userinfo":
			if got := r.Header.Get("Authorization"); got != "Bearer provider-access" {
				t.Fatalf("unexpected userinfo authorization: %q", got)
			}
			writeJSON(w, http.StatusOK, map[string]string{
				"id":     "provider-user-1",
				"email":  "oauth@example.com",
				"name":   "OAuth User",
				"avatar": "https://cdn.example.com/avatar.png",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	providerURL = provider.URL

	providers := map[string]*application.OAuthProviderConfig{
		"test": {
			OAuth2Config: &oauth2.Config{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "https://auth.example.com/api/auth/oauth/test/callback",
				Scopes:       []string{"profile", "email"},
				Endpoint: oauth2.Endpoint{
					AuthURL:  providerURL + "/authorize",
					TokenURL: providerURL + "/token",
				},
			},
			UserInfoURL: providerURL + "/userinfo",
			ParseUser: func(data []byte) (string, string, string, string, error) {
				var payload struct {
					ID     string `json:"id"`
					Email  string `json:"email"`
					Name   string `json:"name"`
					Avatar string `json:"avatar"`
				}
				if err := json.Unmarshal(data, &payload); err != nil {
					return "", "", "", "", err
				}
				return payload.ID, payload.Email, payload.Name, payload.Avatar, nil
			},
		},
	}

	env := newE2EEnv(t, e2eOptions{oauthProviders: providers})
	user := signupE2EUser(t, env, "passkey@example.com", e2ePassword)

	oauthBeginRec := env.request(t, http.MethodGet, "/api/auth/oauth/test", nil, env.apiHeaders())
	assertStatus(t, oauthBeginRec, http.StatusFound)
	location := oauthBeginRec.Header().Get("Location")
	if !strings.HasPrefix(location, providerURL+"/authorize?") {
		t.Fatalf("unexpected oauth begin redirect: %s", location)
	}
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse oauth redirect: %v", err)
	}
	state := redirectURL.Query().Get("state")
	if state == "" || redirectURL.Query().Get("code_challenge") == "" {
		t.Fatalf("oauth begin redirect missing state or PKCE challenge: %s", location)
	}

	oauthCallbackRec := env.request(t, http.MethodGet, "/api/auth/oauth/test/callback?code=oauth-code&state="+url.QueryEscape(state), nil, nil)
	assertStatus(t, oauthCallbackRec, http.StatusFound)
	callbackLocation := oauthCallbackRec.Header().Get("Location")
	if !strings.HasPrefix(callbackLocation, "https://auth.example.com/login.html?auth_code=") {
		t.Fatalf("unexpected oauth callback redirect: %s", callbackLocation)
	}
	redirectCode := redirectAuthCodeFromURL(t, callbackLocation)
	oauthRedirectResp := authResponseFromRedirect(t, env, callbackLocation)
	if oauthRedirectResp.AccessToken == "" {
		t.Fatalf("oauth redirect code did not exchange for an access token")
	}
	replayCodeRec := env.request(t, http.MethodPost, "/api/auth/redirect/exchange", map[string]string{"code": redirectCode}, nil)
	assertStatus(t, replayCodeRec, http.StatusBadRequest)
	if len(oauthCallbackRec.Result().Cookies()) == 0 {
		t.Fatalf("oauth callback should set refresh cookie")
	}

	replayCallbackRec := env.request(t, http.MethodGet, "/api/auth/oauth/test/callback?code=oauth-code&state="+url.QueryEscape(state), nil, nil)
	assertStatus(t, replayCallbackRec, http.StatusFound)
	if !strings.Contains(replayCallbackRec.Header().Get("Location"), "error=invalid_state") {
		t.Fatalf("expected replayed oauth state to fail, got %s", replayCallbackRec.Header().Get("Location"))
	}

	passkeysRec := env.request(t, http.MethodGet, "/api/auth/passkeys", nil, env.bearerHeaders(user.AccessToken))
	assertStatus(t, passkeysRec, http.StatusOK)
	var passkeys []domain.WebAuthnCredential
	decodeBody(t, passkeysRec, &passkeys)
	if len(passkeys) != 0 {
		t.Fatalf("expected no passkeys, got %d", len(passkeys))
	}

	passkeyLoginBeginRec := env.request(t, http.MethodPost, "/api/auth/passkey/login/begin", nil, env.apiHeaders())
	assertStatus(t, passkeyLoginBeginRec, http.StatusOK)
	var loginBegin map[string]interface{}
	decodeBody(t, passkeyLoginBeginRec, &loginBegin)
	if loginBegin["session_id"] == "" || loginBegin["publicKey"] == nil {
		t.Fatalf("unexpected passkey login begin payload: %#v", loginBegin)
	}

	env.clients.setSettings(env.client.ID, map[string]interface{}{
		"webauthn_attestation":                 "direct",
		"webauthn_allowed_attestation_formats": []interface{}{"packed", "apple"},
	})
	passkeyRegisterBeginRec := env.request(t, http.MethodPost, "/api/auth/passkey/register/begin", nil, env.bearerHeaders(user.AccessToken))
	assertStatus(t, passkeyRegisterBeginRec, http.StatusOK)
	var registrationBegin map[string]interface{}
	decodeBody(t, passkeyRegisterBeginRec, &registrationBegin)
	publicKey, _ := registrationBegin["publicKey"].(map[string]interface{})
	formats, _ := publicKey["attestationFormats"].([]interface{})
	if publicKey["attestation"] != "direct" || len(formats) != 2 {
		t.Fatalf("expected passkey attestation policy in options, got %#v", registrationBegin)
	}

	missingSessionFinishRec := env.request(t, http.MethodPost, "/api/auth/passkey/login/finish", nil, env.apiHeaders())
	assertStatus(t, missingSessionFinishRec, http.StatusBadRequest)
}

func TestE2ERedisRequiredFeaturesFailExplicitlyWithoutCache(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{cache: nilCache{}})
	user := signupE2EUser(t, env, "noredis@example.com", e2ePassword)

	magicRec := env.request(t, http.MethodPost, "/api/auth/magic-link/send", map[string]string{
		"email": "noredis@example.com",
	}, env.apiHeaders())
	assertStatus(t, magicRec, http.StatusServiceUnavailable)

	totpRec := env.request(t, http.MethodPost, "/api/auth/totp/setup", nil, env.bearerHeaders(user.AccessToken))
	assertStatus(t, totpRec, http.StatusServiceUnavailable)

	passkeyRec := env.request(t, http.MethodPost, "/api/auth/passkey/login/begin", nil, env.apiHeaders())
	assertStatus(t, passkeyRec, http.StatusServiceUnavailable)
}

func TestE2EOrganizationRBACLifecycle(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{})
	owner := signupE2EUser(t, env, "owner@example.com", e2ePassword)
	member := signupE2EUser(t, env, "member@example.com", e2ePassword)
	finance := signupE2EUser(t, env, "finance-member@example.com", e2ePassword)

	createRec := env.request(t, http.MethodPost, "/api/auth/organizations", map[string]string{
		"name": "Acme Workspace",
	}, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, createRec, http.StatusCreated)
	var created domain.OrganizationMembershipDetails
	decodeBody(t, createRec, &created)
	if created.Organization == nil || created.Organization.Slug != "acme-workspace" {
		t.Fatalf("unexpected organization response: %+v", created)
	}
	if created.Membership == nil || created.Membership.Role != domain.OrganizationRoleOwner {
		t.Fatalf("creator should be owner: %+v", created.Membership)
	}
	orgID := created.Organization.ID

	duplicateRec := env.request(t, http.MethodPost, "/api/auth/organizations", map[string]string{
		"name": "Acme Workspace",
		"slug": "acme-workspace",
	}, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, duplicateRec, http.StatusConflict)

	listRec := env.request(t, http.MethodGet, "/api/auth/organizations", nil, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, listRec, http.StatusOK)
	var listResp struct {
		Organizations []domain.OrganizationMembershipDetails `json:"organizations"`
	}
	decodeBody(t, listRec, &listResp)
	if len(listResp.Organizations) != 1 {
		t.Fatalf("expected owner organization in list, got %d", len(listResp.Organizations))
	}

	inviteRec := env.request(t, http.MethodPost, "/api/auth/organizations/"+orgID+"/invitations", map[string]string{
		"email": member.User.Email,
		"role":  domain.OrganizationRoleMember,
	}, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, inviteRec, http.StatusCreated)
	var invite domain.OrganizationInvitationWithToken
	decodeBody(t, inviteRec, &invite)
	if invite.Token == "" || invite.Invitation == nil || invite.Invitation.Email != member.User.Email {
		t.Fatalf("unexpected invitation response: %+v", invite)
	}

	acceptRec := env.request(t, http.MethodPost, "/api/auth/organization-invitations/accept", map[string]string{
		"token": invite.Token,
	}, env.bearerHeaders(member.AccessToken))
	assertStatus(t, acceptRec, http.StatusOK)

	memberOrgRec := env.request(t, http.MethodGet, "/api/auth/organizations/"+orgID, nil, env.bearerHeaders(member.AccessToken))
	assertStatus(t, memberOrgRec, http.StatusOK)

	memberInviteRec := env.request(t, http.MethodPost, "/api/auth/organizations/"+orgID+"/invitations", map[string]string{
		"email": "blocked@example.com",
	}, env.bearerHeaders(member.AccessToken))
	assertStatus(t, memberInviteRec, http.StatusForbidden)

	updateMemberRec := env.request(t, http.MethodPatch, "/api/auth/organizations/"+orgID+"/members/"+member.User.ID, map[string]interface{}{
		"role":        domain.OrganizationRoleAdmin,
		"permissions": []string{"billing:manage"},
	}, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, updateMemberRec, http.StatusOK)
	var updatedMember domain.OrganizationMembership
	decodeBody(t, updateMemberRec, &updatedMember)
	if updatedMember.Role != domain.OrganizationRoleAdmin {
		t.Fatalf("expected admin role, got %+v", updatedMember)
	}
	if !containsString(updatedMember.Permissions, "billing:manage") {
		t.Fatalf("expected custom billing permission, got %+v", updatedMember.Permissions)
	}

	escalateInviteRec := env.request(t, http.MethodPost, "/api/auth/organizations/"+orgID+"/invitations", map[string]interface{}{
		"email":       "finance@example.com",
		"role":        "org:finance",
		"permissions": []string{"billing:delete"},
	}, env.bearerHeaders(member.AccessToken))
	assertStatus(t, escalateInviteRec, http.StatusForbidden)

	tokenRec := env.request(t, http.MethodPost, "/api/auth/organizations/"+orgID+"/token", nil, env.bearerHeaders(member.AccessToken))
	assertStatus(t, tokenRec, http.StatusOK)
	var orgToken organizationTokenResponse
	decodeBody(t, tokenRec, &orgToken)
	claims, err := application.ValidateAccessToken(context.Background(), env.client, orgToken.AccessToken)
	if err != nil {
		t.Fatalf("validate org token: %v", err)
	}
	if claims.OrganizationID != orgID || claims.OrganizationRole != domain.OrganizationRoleAdmin {
		t.Fatalf("missing org claims: %+v", claims)
	}
	if !containsString(claims.OrganizationPermissions, domain.PermissionInvitationsWrite) {
		t.Fatalf("admin org token missing invitation permission: %+v", claims.OrganizationPermissions)
	}
	if !containsString(claims.OrganizationPermissions, "billing:manage") {
		t.Fatalf("org token missing custom permission: %+v", claims.OrganizationPermissions)
	}

	policyRec := env.request(t, http.MethodGet, "/api/auth/organizations/"+orgID+"/authorization/policy", nil, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, policyRec, http.StatusOK)
	var policy domain.OrganizationAuthorizationPolicy
	decodeBody(t, policyRec, &policy)
	if policy.Version == 0 || len(policy.Resources) == 0 {
		t.Fatalf("expected default authorization policy, got %+v", policy)
	}

	updatePolicyRec := env.request(t, http.MethodPut, "/api/auth/organizations/"+orgID+"/authorization/policy", map[string]interface{}{
		"expected_version": policy.Version,
		"description":      "Product authorization policy",
		"resources": []map[string]interface{}{
			{
				"key":         "billing",
				"description": "Billing settings and invoices",
				"actions": []map[string]interface{}{
					{"key": "manage", "description": "Manage billing"},
				},
			},
			{
				"key":         "documents",
				"description": "Shared workspace documents",
				"actions": []map[string]interface{}{
					{"key": "read", "description": "Read documents"},
				},
			},
		},
		"roles": []map[string]interface{}{
			{
				"key":         "billing-admin",
				"name":        "Billing Admin",
				"description": "Can manage billing, read documents, and invite members",
				"permissions": []string{domain.PermissionOrganizationRead, domain.PermissionMembersRead, "billing:manage", "documents:read", domain.PermissionMembersInvite},
			},
		},
	}, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, updatePolicyRec, http.StatusOK)
	var updatedPolicy domain.OrganizationAuthorizationPolicy
	decodeBody(t, updatePolicyRec, &updatedPolicy)
	if updatedPolicy.Version != policy.Version+1 {
		t.Fatalf("expected policy version increment, got %+v", updatedPolicy)
	}

	customRoleRec := env.request(t, http.MethodPatch, "/api/auth/organizations/"+orgID+"/members/"+member.User.ID, map[string]interface{}{
		"role": "billing-admin",
	}, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, customRoleRec, http.StatusOK)

	customTokenRec := env.request(t, http.MethodPost, "/api/auth/organizations/"+orgID+"/token", nil, env.bearerHeaders(member.AccessToken))
	assertStatus(t, customTokenRec, http.StatusOK)
	var customOrgToken organizationTokenResponse
	decodeBody(t, customTokenRec, &customOrgToken)
	customClaims, err := application.ValidateAccessToken(context.Background(), env.client, customOrgToken.AccessToken)
	if err != nil {
		t.Fatalf("validate custom org token: %v", err)
	}
	for _, permission := range []string{"billing:manage", "documents:read", domain.PermissionMembersInvite} {
		if !containsString(customClaims.OrganizationPermissions, permission) {
			t.Fatalf("custom org token missing %s: %+v", permission, customClaims.OrganizationPermissions)
		}
	}

	allowSimRec := env.request(t, http.MethodPost, "/api/auth/organizations/"+orgID+"/authorization/simulate", map[string]string{
		"user_id":  member.User.ID,
		"resource": "documents",
		"action":   "read",
	}, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, allowSimRec, http.StatusOK)
	var allowDecision domain.AuthorizationDecision
	decodeBody(t, allowSimRec, &allowDecision)
	if !allowDecision.Allowed || allowDecision.Permission != "documents:read" {
		t.Fatalf("expected documents:read simulator allow, got %+v", allowDecision)
	}

	denySimRec := env.request(t, http.MethodPost, "/api/auth/organizations/"+orgID+"/authorization/simulate", map[string]string{
		"user_id":  member.User.ID,
		"resource": "billing",
		"action":   "delete",
	}, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, denySimRec, http.StatusOK)
	var denyDecision domain.AuthorizationDecision
	decodeBody(t, denySimRec, &denyDecision)
	if denyDecision.Allowed || !containsString(denyDecision.Missing, "billing:delete") {
		t.Fatalf("expected billing:delete simulator denial, got %+v", denyDecision)
	}

	groupMappingRec := env.request(t, http.MethodPost, "/api/auth/organizations/"+orgID+"/authorization/group-mappings", map[string]interface{}{
		"source":      domain.GroupMappingSourceSCIM,
		"source_id":   "directory-1",
		"group":       "Finance Team",
		"role":        "billing-admin",
		"permissions": []string{domain.PermissionMembersInvite},
	}, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, groupMappingRec, http.StatusCreated)
	if err := application.ApplyOrganizationGroupMappings(context.Background(), env.orgs, env.client.ID, domain.GroupMappingSourceSCIM, "directory-1", finance.User.ID, []string{"Finance Team"}); err != nil {
		t.Fatalf("apply scim group mappings: %v", err)
	}
	financeTokenRec := env.request(t, http.MethodPost, "/api/auth/organizations/"+orgID+"/token", nil, env.bearerHeaders(finance.AccessToken))
	assertStatus(t, financeTokenRec, http.StatusOK)
	var financeOrgToken organizationTokenResponse
	decodeBody(t, financeTokenRec, &financeOrgToken)
	financeClaims, err := application.ValidateAccessToken(context.Background(), env.client, financeOrgToken.AccessToken)
	if err != nil {
		t.Fatalf("validate finance org token: %v", err)
	}
	if financeClaims.OrganizationRole != "billing-admin" || !containsString(financeClaims.OrganizationPermissions, "billing:manage") {
		t.Fatalf("expected scim group mapping to grant billing-admin, got %+v", financeClaims)
	}

	membersRec := env.request(t, http.MethodGet, "/api/auth/organizations/"+orgID+"/members", nil, env.bearerHeaders(member.AccessToken))
	assertStatus(t, membersRec, http.StatusOK)

	removeMemberRec := env.request(t, http.MethodDelete, "/api/auth/organizations/"+orgID+"/members/"+member.User.ID, nil, env.bearerHeaders(owner.AccessToken))
	assertStatus(t, removeMemberRec, http.StatusOK)

	removedAccessRec := env.request(t, http.MethodGet, "/api/auth/organizations/"+orgID, nil, env.bearerHeaders(member.AccessToken))
	assertStatus(t, removedAccessRec, http.StatusNotFound)

	events, err := env.audit.List(context.Background(), domain.AuditEventFilter{ClientID: env.client.ID, Limit: 50})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	for _, eventType := range []string{"organization_created", "organization_invitation_accepted", "organization_member_updated", "organization_member_removed"} {
		if !auditEventsContain(events, eventType) {
			t.Fatalf("expected audit event %q in %+v", eventType, events)
		}
	}
}

func TestE2EMachineToMachineClientCredentialsLifecycle(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{})

	createRec := env.request(t, http.MethodPost, "/api/admin/clients/"+env.client.ID+"/service-accounts", map[string]interface{}{
		"name":   "Billing Worker",
		"scopes": []string{"invoices:read", "invoices:write"},
	}, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, createRec, http.StatusCreated)
	var created domain.ServiceAccountKeyWithSecret
	decodeBody(t, createRec, &created)
	if created.ServiceAccount == nil || created.Key == nil || created.ClientID == "" || created.ClientSecret == "" {
		t.Fatalf("create service account returned incomplete response: %+v", created)
	}
	serviceAccountID := created.ClientID
	initialSecret := created.ClientSecret

	tokenRec := env.request(t, http.MethodPost, "/oauth/token", map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     serviceAccountID,
		"client_secret": initialSecret,
		"scope":         "invoices:read",
	}, nil)
	assertStatus(t, tokenRec, http.StatusOK)
	var token application.M2MTokenResponse
	decodeBody(t, tokenRec, &token)
	if token.AccessToken == "" || token.Scope != "invoices:read" {
		t.Fatalf("unexpected token response: %+v", token)
	}

	claims, err := application.ValidateAccessToken(context.Background(), env.client, token.AccessToken)
	if err != nil {
		t.Fatalf("validate m2m token: %v", err)
	}
	if claims.TokenUse != domain.TokenUseClientCredentials || claims.ServiceAccountID != serviceAccountID || claims.Subject != serviceAccountID {
		t.Fatalf("missing m2m claims: %+v", claims)
	}
	if !containsString(claims.Scopes, "invoices:read") {
		t.Fatalf("m2m token missing requested scope: %+v", claims.Scopes)
	}

	introspectRec := env.request(t, http.MethodPost, "/oauth/introspect", map[string]string{
		"token":         token.AccessToken,
		"client_id":     serviceAccountID,
		"client_secret": initialSecret,
	}, nil)
	assertStatus(t, introspectRec, http.StatusOK)
	var introspection application.M2MIntrospectionResponse
	decodeBody(t, introspectRec, &introspection)
	if !introspection.Active || introspection.ServiceAccountID != serviceAccountID || introspection.Scope != "invoices:read" {
		t.Fatalf("unexpected introspection response: %+v", introspection)
	}

	deniedScopeRec := env.request(t, http.MethodPost, "/oauth/token", map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     serviceAccountID,
		"client_secret": initialSecret,
		"scope":         "invoices:delete",
	}, nil)
	assertStatus(t, deniedScopeRec, http.StatusBadRequest)

	createKeyRec := env.request(t, http.MethodPost, "/api/admin/clients/"+env.client.ID+"/service-accounts/"+serviceAccountID+"/keys", map[string]interface{}{
		"name":   "read-only",
		"scopes": []string{"invoices:read"},
	}, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, createKeyRec, http.StatusCreated)
	var createdKey domain.ServiceAccountKeyWithSecret
	decodeBody(t, createKeyRec, &createdKey)
	if createdKey.Key == nil || createdKey.ClientSecret == "" || createdKey.ClientSecret == initialSecret {
		t.Fatalf("unexpected key creation response: %+v", createdKey)
	}

	revokeInitialRec := env.request(t, http.MethodDelete, "/api/admin/clients/"+env.client.ID+"/service-accounts/"+serviceAccountID+"/keys/"+created.Key.ID, nil, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, revokeInitialRec, http.StatusOK)

	revokedTokenRec := env.request(t, http.MethodPost, "/oauth/token", map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     serviceAccountID,
		"client_secret": initialSecret,
	}, nil)
	assertStatus(t, revokedTokenRec, http.StatusUnauthorized)

	newTokenRec := env.request(t, http.MethodPost, "/oauth/token", map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     serviceAccountID,
		"client_secret": createdKey.ClientSecret,
	}, nil)
	assertStatus(t, newTokenRec, http.StatusOK)

	rotateRec := env.request(t, http.MethodPost, "/api/admin/clients/"+env.client.ID+"/service-accounts/"+serviceAccountID+"/keys/"+createdKey.Key.ID+"/rotate", nil, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, rotateRec, http.StatusOK)
	var rotatedKey domain.ServiceAccountKeyWithSecret
	decodeBody(t, rotateRec, &rotatedKey)
	if rotatedKey.ClientSecret == "" || rotatedKey.ClientSecret == createdKey.ClientSecret {
		t.Fatalf("unexpected rotated key response: %+v", rotatedKey)
	}

	rotatedOldSecretRec := env.request(t, http.MethodPost, "/oauth/token", map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     serviceAccountID,
		"client_secret": createdKey.ClientSecret,
	}, nil)
	assertStatus(t, rotatedOldSecretRec, http.StatusUnauthorized)

	rotatedTokenRec := env.request(t, http.MethodPost, "/oauth/token", map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     serviceAccountID,
		"client_secret": rotatedKey.ClientSecret,
	}, nil)
	assertStatus(t, rotatedTokenRec, http.StatusOK)

	events, err := env.audit.List(context.Background(), domain.AuditEventFilter{ClientID: env.client.ID, Limit: 50})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	for _, eventType := range []string{"service_account_created", "m2m_token_issued", "service_account_key_revoked", "service_account_key_rotated"} {
		if !auditEventsContain(events, eventType) {
			t.Fatalf("expected audit event %q in %+v", eventType, events)
		}
	}
}

func TestE2EOIDCProviderAuthorizationCodePKCE(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{})
	env.clients.setSettings(env.client.ID, map[string]interface{}{
		"oidc_redirect_uris":             []string{"https://app.example.com/callback"},
		"oidc_post_logout_redirect_uris": []string{"https://app.example.com/signed-out"},
		"oidc_allowed_scopes":            []string{"openid", "profile", "email", "offline_access", "api:read"},
		"oidc_audiences":                 []string{"api://default"},
		"oidc_trusted":                   true,
		"oidc_require_consent":           false,
	})

	discoveryRec := env.request(t, http.MethodGet, "/.well-known/openid-configuration", nil, nil)
	assertStatus(t, discoveryRec, http.StatusOK)
	var discovery map[string]interface{}
	decodeBody(t, discoveryRec, &discovery)
	if discovery["authorization_endpoint"] != "https://auth.example.com/authorize" || discovery["token_endpoint"] != "https://auth.example.com/token" {
		t.Fatalf("unexpected discovery document: %+v", discovery)
	}

	unauthValues := url.Values{}
	unauthValues.Set("client_id", env.client.ID)
	unauthValues.Set("redirect_uri", "https://app.example.com/callback")
	unauthValues.Set("response_type", "code")
	unauthValues.Set("scope", "openid")
	unauthValues.Set("code_challenge", strings.Repeat("b", 64))
	unauthValues.Set("code_challenge_method", "plain")
	unauthRec := env.request(t, http.MethodGet, "/authorize?"+unauthValues.Encode(), nil, nil)
	assertStatus(t, unauthRec, http.StatusFound)
	if location := unauthRec.Header().Get("Location"); !strings.HasPrefix(location, "/oidc/login?") {
		t.Fatalf("expected hosted login redirect, got %q", location)
	}

	session := signupE2EUser(t, env, "oidc-user@example.com", e2ePassword)
	verifier := strings.Repeat("a", 64)
	challengeSum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeSum[:])
	state := "state-123"
	nonce := "nonce-123"

	values := url.Values{}
	values.Set("client_id", env.client.ID)
	values.Set("redirect_uri", "https://app.example.com/callback")
	values.Set("response_type", "code")
	values.Set("scope", "openid profile email offline_access api:read")
	values.Set("audience", "api://default")
	values.Set("state", state)
	values.Set("nonce", nonce)
	values.Set("code_challenge", challenge)
	values.Set("code_challenge_method", "S256")
	authorizeReq := httptest.NewRequest(http.MethodGet, "/authorize?"+values.Encode(), nil)
	authorizeReq.Header.Set("Authorization", "Bearer "+session.AccessToken)
	authorizeRec := httptest.NewRecorder()
	env.handler.ServeHTTP(authorizeRec, authorizeReq)
	assertStatus(t, authorizeRec, http.StatusFound)
	callback, err := url.Parse(authorizeRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize redirect: %v", err)
	}
	code := callback.Query().Get("code")
	if callback.Scheme != "https" || callback.Host != "app.example.com" || code == "" || callback.Query().Get("state") != state {
		t.Fatalf("unexpected authorize redirect: %s", callback.String())
	}

	tokenRec := env.request(t, http.MethodPost, "/token", map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     env.client.ID,
		"code":          code,
		"redirect_uri":  "https://app.example.com/callback",
		"code_verifier": verifier,
	}, nil)
	assertStatus(t, tokenRec, http.StatusOK)
	var tokenResp application.OIDCTokenResponse
	decodeBody(t, tokenRec, &tokenResp)
	if tokenResp.AccessToken == "" || tokenResp.IDToken == "" || tokenResp.RefreshToken == "" || tokenResp.Scope == "" {
		t.Fatalf("OIDC token response was incomplete: %+v", tokenResp)
	}

	accessClaims, err := application.ValidateAccessToken(context.Background(), env.client, tokenResp.AccessToken)
	if err != nil {
		t.Fatalf("validate OIDC access token: %v", err)
	}
	if accessClaims.Issuer != env.cfg.BaseURL || accessClaims.AuthorizedParty != env.client.ID || accessClaims.Scope == "" || !containsString(accessClaims.Scopes, "api:read") || !containsString([]string(accessClaims.Audience), "api://default") {
		t.Fatalf("access token missing OIDC audience/scope claims: %+v", accessClaims)
	}

	var idClaims application.IDTokenClaims
	if _, _, err := jwt.NewParser().ParseUnverified(tokenResp.IDToken, &idClaims); err != nil {
		t.Fatalf("parse id token: %v", err)
	}
	if idClaims.Issuer != env.cfg.BaseURL || !containsString([]string(idClaims.Audience), env.client.ID) || idClaims.AuthorizedParty != env.client.ID || idClaims.Nonce != nonce || idClaims.AuthTime == 0 || idClaims.ACR == "" || !containsString(idClaims.AMR, "pwd") {
		t.Fatalf("ID token missing required OIDC claims: %+v", idClaims)
	}

	userInfoReq := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	userInfoReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userInfoRec := httptest.NewRecorder()
	env.handler.ServeHTTP(userInfoRec, userInfoReq)
	assertStatus(t, userInfoRec, http.StatusOK)
	var userInfo application.OIDCUserInfoResponse
	decodeBody(t, userInfoRec, &userInfo)
	if userInfo.Subject != session.User.ID || userInfo.Email != "oidc-user@example.com" || userInfo.Name == "" {
		t.Fatalf("unexpected userinfo response: %+v", userInfo)
	}

	refreshRec := env.request(t, http.MethodPost, "/token", map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     env.client.ID,
		"refresh_token": tokenResp.RefreshToken,
	}, nil)
	assertStatus(t, refreshRec, http.StatusOK)
	var refreshed application.OIDCTokenResponse
	decodeBody(t, refreshRec, &refreshed)
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" || refreshed.RefreshToken == tokenResp.RefreshToken {
		t.Fatalf("refresh grant did not rotate token: %+v", refreshed)
	}

	introspectRec := env.request(t, http.MethodPost, "/introspect", map[string]string{
		"token":         refreshed.AccessToken,
		"client_id":     env.client.ID,
		"client_secret": e2eAPIKey,
	}, nil)
	assertStatus(t, introspectRec, http.StatusOK)
	var introspection application.OIDCIntrospectionResponse
	decodeBody(t, introspectRec, &introspection)
	if !introspection.Active || introspection.ClientID != env.client.ID || introspection.Subject != session.User.ID {
		t.Fatalf("unexpected introspection response: %+v", introspection)
	}

	revokeRec := env.request(t, http.MethodPost, "/revoke", map[string]string{
		"token":         refreshed.AccessToken,
		"client_id":     env.client.ID,
		"client_secret": e2eAPIKey,
	}, nil)
	assertStatus(t, revokeRec, http.StatusOK)
	introspectRevokedRec := env.request(t, http.MethodPost, "/introspect", map[string]string{
		"token":         refreshed.AccessToken,
		"client_id":     env.client.ID,
		"client_secret": e2eAPIKey,
	}, nil)
	assertStatus(t, introspectRevokedRec, http.StatusOK)
	var revokedIntrospection application.OIDCIntrospectionResponse
	decodeBody(t, introspectRevokedRec, &revokedIntrospection)
	if revokedIntrospection.Active {
		t.Fatalf("revoked access token introspected as active: %+v", revokedIntrospection)
	}

	logoutRec := env.request(t, http.MethodGet, "/logout?client_id="+url.QueryEscape(env.client.ID)+"&post_logout_redirect_uri="+url.QueryEscape("https://app.example.com/signed-out")+"&state=bye", nil, nil)
	assertStatus(t, logoutRec, http.StatusFound)
	logoutURL, err := url.Parse(logoutRec.Header().Get("Location"))
	if err != nil || logoutURL.String() != "https://app.example.com/signed-out?state=bye" {
		t.Fatalf("unexpected logout redirect: %q err=%v", logoutRec.Header().Get("Location"), err)
	}
}

func TestE2EEnterpriseSSOOIDCLifecycle(t *testing.T) {
	oidcProvider := newTestOIDCProvider(t, testOIDCProfile{
		Subject:       "okta-user-123",
		Email:         "sso.user@acme.com",
		Name:          "SSO User",
		EmailVerified: true,
	})
	defer oidcProvider.Close()

	env := newE2EEnv(t, e2eOptions{})

	createRec := env.request(t, http.MethodPost, "/api/admin/clients/"+env.client.ID+"/sso-connections", map[string]interface{}{
		"name":                "Acme Okta",
		"slug":                "acme-okta",
		"protocol":            "oidc",
		"domains":             []string{"acme.com"},
		"enforce_for_domains": true,
		"oidc": map[string]interface{}{
			"issuer":        oidcProvider.URL(),
			"client_id":     "enterprise-client",
			"client_secret": "enterprise-secret",
			"scopes":        []string{"openid", "email", "profile"},
		},
	}, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, createRec, http.StatusCreated)
	var connection domain.EnterpriseSSOConnection
	decodeBody(t, createRec, &connection)
	if connection.ID == "" || connection.Protocol != domain.SSOProtocolOIDC || connection.OIDC.ClientSecret != "" {
		t.Fatalf("unexpected sanitized OIDC connection response: %+v", connection)
	}

	beginRec := env.request(t, http.MethodGet, "/api/auth/sso?domain=acme.com", nil, env.apiHeaders())
	assertStatus(t, beginRec, http.StatusFound)
	providerRedirect := beginRec.Header().Get("Location")
	if !strings.HasPrefix(providerRedirect, oidcProvider.URL()+"/authorize") {
		t.Fatalf("expected OIDC provider redirect, got %s", providerRedirect)
	}

	callbackURL := followRedirectOnce(t, providerRedirect)
	callbackRec := env.request(t, http.MethodGet, callbackURL, nil, nil)
	assertStatus(t, callbackRec, http.StatusFound)
	loginRedirect := callbackRec.Header().Get("Location")
	accessToken := authResponseFromRedirect(t, env, loginRedirect).AccessToken
	claims, err := application.ValidateAccessToken(context.Background(), env.client, accessToken)
	if err != nil {
		t.Fatalf("validate SSO access token: %v", err)
	}
	if claims.Email != "sso.user@acme.com" || claims.ClientID != env.client.ID {
		t.Fatalf("unexpected SSO claims: %+v", claims)
	}

	user, err := env.users.GetByEmail(context.Background(), env.client.ID, "sso.user@acme.com")
	if err != nil {
		t.Fatalf("expected SSO-provisioned user: %v", err)
	}
	if !user.EmailVerified || user.DisplayName != "SSO User" {
		t.Fatalf("unexpected SSO user: %+v", user)
	}
	identity, err := env.sso.FindIdentity(context.Background(), env.client.ID, connection.ID, "okta-user-123")
	if err != nil || identity.UserID != user.ID {
		t.Fatalf("expected linked SSO identity, got %+v err=%v", identity, err)
	}

	events, err := env.audit.List(context.Background(), domain.AuditEventFilter{ClientID: env.client.ID, Limit: 50})
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	for _, eventType := range []string{"enterprise_sso_connection_created", "signup", "login_success"} {
		if !auditEventsContain(events, eventType) {
			t.Fatalf("expected audit event %q in %+v", eventType, events)
		}
	}
}

func TestE2EEnterpriseSSOEnforcedDomainsBlockPasswordFlows(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{})
	now := time.Now().UTC()
	connection := &domain.EnterpriseSSOConnection{
		ID:                "enforced-acme",
		ClientID:          env.client.ID,
		Name:              "Acme SSO",
		Slug:              "acme-sso",
		Protocol:          domain.SSOProtocolOIDC,
		Status:            domain.SSOConnectionStatusActive,
		Domains:           []string{"acme.com"},
		EnforceForDomains: true,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := env.sso.CreateConnection(context.Background(), connection); err != nil {
		t.Fatalf("create enforced sso connection: %v", err)
	}

	signupRec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]string{
		"email":        "new@acme.com",
		"password":     e2ePassword,
		"display_name": "New Acme",
	}, env.apiHeaders())
	assertStatus(t, signupRec, http.StatusForbidden)

	hash, err := application.HashPassword(e2ePassword, 10)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := env.users.Create(context.Background(), env.client.ID, "member@acme.com", hash, "Acme Member")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	loginRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":    user.Email,
		"password": e2ePassword,
	}, env.apiHeaders())
	assertStatus(t, loginRec, http.StatusForbidden)

	accessToken, err := application.CreateAccessToken(context.Background(), env.client, time.Minute, user)
	if err != nil {
		t.Fatalf("create access token: %v", err)
	}
	changeRec := env.request(t, http.MethodPost, "/api/auth/change-password", map[string]string{
		"old_password": e2ePassword,
		"new_password": "NewValidPass123!",
	}, env.bearerHeaders(accessToken))
	assertStatus(t, changeRec, http.StatusForbidden)

	forgotRec := env.request(t, http.MethodPost, "/api/auth/forgot-password", map[string]string{"email": user.Email}, env.apiHeaders())
	assertStatus(t, forgotRec, http.StatusOK)
	if len(env.mailer.passwordResetURLs) != 0 {
		t.Fatalf("password reset email should not be sent for enforced SSO domains")
	}

	magicRec := env.request(t, http.MethodPost, "/api/auth/magic-link/send", map[string]string{"email": user.Email}, env.apiHeaders())
	assertStatus(t, magicRec, http.StatusOK)
	if len(env.mailer.magicURLs) != 0 {
		t.Fatalf("magic link email should not be sent for enforced SSO domains")
	}
}

func TestE2EEnterpriseSSOSAMLMetadataAndRedirect(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{})
	idpCert := generateTestCertificateBase64(t)

	createRec := env.request(t, http.MethodPost, "/api/admin/clients/"+env.client.ID+"/sso-connections", map[string]interface{}{
		"name":     "Acme SAML",
		"slug":     "acme-saml",
		"protocol": "saml",
		"domains":  []string{"acme.com"},
		"saml": map[string]interface{}{
			"idp_entity_id":   "https://idp.example.com/metadata",
			"idp_sso_url":     "https://idp.example.com/sso",
			"idp_certificate": idpCert,
		},
		"attribute_mapping": map[string]string{
			"email":       "mail",
			"name":        "displayName",
			"external_id": "uid",
		},
	}, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, createRec, http.StatusCreated)
	var connection domain.EnterpriseSSOConnection
	decodeBody(t, createRec, &connection)
	if connection.ID == "" || connection.Protocol != domain.SSOProtocolSAML || connection.SAML.SPPrivateKeyPEM != "" {
		t.Fatalf("unexpected sanitized SAML connection response: %+v", connection)
	}
	if connection.SAML.SPCertificatePEM == "" {
		t.Fatalf("expected generated SP certificate in sanitized SAML response")
	}

	metadataRec := env.request(t, http.MethodGet, "/api/auth/sso/metadata/"+connection.ID, nil, nil)
	assertStatus(t, metadataRec, http.StatusOK)
	metadata := metadataRec.Body.String()
	if !strings.Contains(metadata, "EntityDescriptor") || !strings.Contains(metadata, "AssertionConsumerService") {
		t.Fatalf("unexpected SAML metadata: %s", metadata)
	}

	beginRec := env.request(t, http.MethodGet, "/api/auth/sso/"+connection.ID, nil, env.apiHeaders())
	assertStatus(t, beginRec, http.StatusFound)
	redirectURL := beginRec.Header().Get("Location")
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse SAML redirect: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host != "idp.example.com" || parsed.Query().Get("SAMLRequest") == "" || parsed.Query().Get("RelayState") == "" {
		t.Fatalf("unexpected SAML redirect: %s", redirectURL)
	}
}

func TestE2ESCIMDirectorySyncLifecycle(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{})

	createDirectoryRec := env.request(t, http.MethodPost, "/api/admin/clients/"+env.client.ID+"/scim-directories", map[string]interface{}{
		"name":    "Acme Directory",
		"domains": []string{"acme.com"},
	}, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, createDirectoryRec, http.StatusCreated)
	var directoryWithToken domain.SCIMDirectoryWithToken
	decodeBody(t, createDirectoryRec, &directoryWithToken)
	if directoryWithToken.Directory == nil || directoryWithToken.Directory.ID == "" || directoryWithToken.Token == "" {
		t.Fatalf("unexpected SCIM directory response: %+v", directoryWithToken)
	}

	scimHeaders := map[string]string{"Authorization": "Bearer " + directoryWithToken.Token}
	configRec := env.request(t, http.MethodGet, "/scim/v2/"+directoryWithToken.Directory.ID+"/ServiceProviderConfig", nil, scimHeaders)
	assertStatus(t, configRec, http.StatusOK)

	createUserRec := env.request(t, http.MethodPost, "/scim/v2/"+directoryWithToken.Directory.ID+"/Users", map[string]interface{}{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"externalId":  "00u-acme-1",
		"userName":    "provisioned@acme.com",
		"active":      true,
		"displayName": "Provisioned User",
		"emails": []map[string]interface{}{{
			"value":   "provisioned@acme.com",
			"type":    "work",
			"primary": true,
		}},
	}, scimHeaders)
	assertStatus(t, createUserRec, http.StatusCreated)
	var scimUser application.SCIMUserResource
	decodeBody(t, createUserRec, &scimUser)
	if scimUser.ID == "" || scimUser.UserName != "provisioned@acme.com" || !scimUser.Active {
		t.Fatalf("unexpected SCIM user: %+v", scimUser)
	}
	user, err := env.users.GetByEmail(context.Background(), env.client.ID, "provisioned@acme.com")
	if err != nil || user.DisplayName != "Provisioned User" || user.Status != "active" {
		t.Fatalf("expected provisioned active user, got %+v err=%v", user, err)
	}

	listUsersRec := env.request(t, http.MethodGet, "/scim/v2/"+directoryWithToken.Directory.ID+"/Users", nil, scimHeaders)
	assertStatus(t, listUsersRec, http.StatusOK)
	var listUsers application.SCIMListResponse
	decodeBody(t, listUsersRec, &listUsers)
	if listUsers.TotalResults != 1 {
		t.Fatalf("expected one SCIM user, got %+v", listUsers)
	}

	patchUserRec := env.request(t, http.MethodPatch, "/scim/v2/"+directoryWithToken.Directory.ID+"/Users/"+scimUser.ID, map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]interface{}{{
			"op":    "replace",
			"path":  "active",
			"value": false,
		}},
	}, scimHeaders)
	assertStatus(t, patchUserRec, http.StatusOK)
	user, err = env.users.GetByEmail(context.Background(), env.client.ID, "provisioned@acme.com")
	if err != nil || user.Status != "suspended" {
		t.Fatalf("expected SCIM patch to suspend user, got %+v err=%v", user, err)
	}

	createGroupRec := env.request(t, http.MethodPost, "/scim/v2/"+directoryWithToken.Directory.ID+"/Groups", map[string]interface{}{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"externalId":  "group-1",
		"displayName": "Engineering",
		"members": []map[string]string{{
			"value": scimUser.ID,
		}},
	}, scimHeaders)
	assertStatus(t, createGroupRec, http.StatusCreated)
	var scimGroup application.SCIMGroupResource
	decodeBody(t, createGroupRec, &scimGroup)
	if scimGroup.ID == "" || len(scimGroup.Members) != 1 {
		t.Fatalf("unexpected SCIM group: %+v", scimGroup)
	}

	deleteUserRec := env.request(t, http.MethodDelete, "/scim/v2/"+directoryWithToken.Directory.ID+"/Users/"+scimUser.ID, nil, scimHeaders)
	assertStatus(t, deleteUserRec, http.StatusNoContent)
	deletedGetRec := env.request(t, http.MethodGet, "/scim/v2/"+directoryWithToken.Directory.ID+"/Users/"+scimUser.ID, nil, scimHeaders)
	assertStatus(t, deletedGetRec, http.StatusNotFound)

	rotateRec := env.request(t, http.MethodPost, "/api/admin/clients/"+env.client.ID+"/scim-directories/"+directoryWithToken.Directory.ID+"/rotate-token", nil, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, rotateRec, http.StatusOK)
	var rotated domain.SCIMDirectoryWithToken
	decodeBody(t, rotateRec, &rotated)
	oldTokenRec := env.request(t, http.MethodGet, "/scim/v2/"+directoryWithToken.Directory.ID+"/Users", nil, scimHeaders)
	assertStatus(t, oldTokenRec, http.StatusUnauthorized)
	newTokenRec := env.request(t, http.MethodGet, "/scim/v2/"+directoryWithToken.Directory.ID+"/Users", nil, map[string]string{"Authorization": "Bearer " + rotated.Token})
	assertStatus(t, newTokenRec, http.StatusOK)
}

func TestAdminPlaneIdentityMFADelegationSSOAndActorAudit(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{})
	secondary := env.clients.addClient("client-b", "Client B", "client-b", "client-b-api-key")

	ownerRec := env.request(t, http.MethodPost, "/api/admin/users", map[string]interface{}{
		"email":        "owner@example.com",
		"display_name": "Owner Admin",
		"password":     "OwnerPass123!",
		"roles":        []string{domain.AdminRoleOwner},
		"scope_type":   domain.AdminScopeAll,
		"mfa_required": false,
	}, map[string]string{"X-Admin-Key": e2eAdminKey, "X-Request-ID": "req-admin-create-owner", "User-Agent": "admin-test"})
	assertStatus(t, ownerRec, http.StatusCreated)

	ownerLoginRec := env.request(t, http.MethodPost, "/api/admin/auth/login", map[string]interface{}{
		"email":    "owner@example.com",
		"password": "OwnerPass123!",
	}, map[string]string{"X-Request-ID": "req-admin-owner-login", "User-Agent": "admin-test"})
	assertStatus(t, ownerLoginRec, http.StatusOK)
	var ownerLogin application.AdminAuthResponse
	decodeBody(t, ownerLoginRec, &ownerLogin)
	if ownerLogin.AccessToken == "" || ownerLogin.Admin == nil || ownerLogin.Admin.Email != "owner@example.com" {
		t.Fatalf("owner admin login returned incomplete response: %+v", ownerLogin)
	}
	ownerLoginEvents, err := env.audit.List(context.Background(), domain.AuditEventFilter{RequestID: "req-admin-owner-login", Limit: 1})
	if err != nil || len(ownerLoginEvents) != 1 {
		t.Fatalf("expected owner login audit event, got events=%+v err=%v", ownerLoginEvents, err)
	}
	if ownerLoginEvents[0].ActorEmail != "owner@example.com" || ownerLoginEvents[0].RequestID != "req-admin-owner-login" || ownerLoginEvents[0].UserAgent != "admin-test" {
		t.Fatalf("expected owner login actor/request audit event: %+v", ownerLoginEvents[0])
	}

	const totpSecret = "JBSWY3DPEHPK3PXP"
	securityRec := env.request(t, http.MethodPost, "/api/admin/users", map[string]interface{}{
		"email":        "security@example.com",
		"display_name": "Security Admin",
		"password":     "SecurityPass123!",
		"roles":        []string{domain.AdminRoleSecurityAdmin},
		"scope_type":   domain.AdminScopeAll,
		"mfa_required": true,
		"totp_enabled": true,
		"totp_secret":  totpSecret,
	}, map[string]string{"Authorization": "Bearer " + ownerLogin.AccessToken, "X-Request-ID": "req-admin-create-security", "User-Agent": "admin-test"})
	assertStatus(t, securityRec, http.StatusCreated)

	mfaRequiredRec := env.request(t, http.MethodPost, "/api/admin/auth/login", map[string]interface{}{
		"email":    "security@example.com",
		"password": "SecurityPass123!",
	}, map[string]string{"User-Agent": "admin-test"})
	assertStatus(t, mfaRequiredRec, http.StatusUnauthorized)
	var challenge application.AdminAuthResponse
	decodeBody(t, mfaRequiredRec, &challenge)
	if !challenge.MFARequired {
		t.Fatalf("expected MFA challenge, got %+v", challenge)
	}

	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	securityLoginRec := env.request(t, http.MethodPost, "/api/admin/auth/login", map[string]interface{}{
		"email":     "security@example.com",
		"password":  "SecurityPass123!",
		"totp_code": code,
	}, map[string]string{"User-Agent": "admin-test"})
	assertStatus(t, securityLoginRec, http.StatusOK)
	var securityLogin application.AdminAuthResponse
	decodeBody(t, securityLoginRec, &securityLogin)
	if securityLogin.AccessToken == "" {
		t.Fatalf("security admin login should return token")
	}

	supportRec := env.request(t, http.MethodPost, "/api/admin/users", map[string]interface{}{
		"email":           "support@example.com",
		"display_name":    "Support Admin",
		"password":        "SupportPass123!",
		"roles":           []string{domain.AdminRoleSupportAdmin},
		"scope_type":      domain.AdminScopeClient,
		"scope_client_id": env.client.ID,
		"mfa_required":    false,
	}, map[string]string{"Authorization": "Bearer " + securityLogin.AccessToken, "X-Request-ID": "req-admin-create-support", "User-Agent": "admin-test"})
	assertStatus(t, supportRec, http.StatusCreated)

	supportLoginRec := env.request(t, http.MethodPost, "/api/admin/auth/login", map[string]interface{}{
		"email":    "support@example.com",
		"password": "SupportPass123!",
	}, map[string]string{"User-Agent": "admin-test"})
	assertStatus(t, supportLoginRec, http.StatusOK)
	var supportLogin application.AdminAuthResponse
	decodeBody(t, supportLoginRec, &supportLogin)

	scopedListRec := env.request(t, http.MethodGet, "/api/admin/clients", nil, map[string]string{
		"Authorization": "Bearer " + supportLogin.AccessToken,
		"X-Request-ID":  "req-support-list",
		"User-Agent":    "admin-test",
	})
	assertStatus(t, scopedListRec, http.StatusOK)
	var scopedClients []domain.Client
	decodeBody(t, scopedListRec, &scopedClients)
	if len(scopedClients) != 1 || scopedClients[0].ID != env.client.ID || scopedClients[0].ID == secondary.ID {
		t.Fatalf("support admin should see only scoped client, got %+v", scopedClients)
	}

	denyTenantRec := env.request(t, http.MethodGet, "/api/admin/clients/"+secondary.ID, nil, map[string]string{
		"Authorization": "Bearer " + supportLogin.AccessToken,
		"X-Request-ID":  "req-support-denied-client",
		"User-Agent":    "admin-test",
	})
	assertStatus(t, denyTenantRec, http.StatusForbidden)

	denyRoleRec := env.request(t, http.MethodPatch, "/api/admin/clients/"+env.client.ID, map[string]string{"name": "Nope"}, map[string]string{
		"Authorization": "Bearer " + supportLogin.AccessToken,
		"X-Request-ID":  "req-support-denied-role",
		"User-Agent":    "admin-test",
	})
	assertStatus(t, denyRoleRec, http.StatusForbidden)

	orgScopedRec := env.request(t, http.MethodPost, "/api/admin/users", map[string]interface{}{
		"email":                 "org-auditor@example.com",
		"display_name":          "Org Auditor",
		"password":              "OrgAuditPass123!",
		"roles":                 []string{domain.AdminRoleReadOnlyAuditor},
		"scope_type":            domain.AdminScopeOrganization,
		"scope_client_id":       env.client.ID,
		"scope_organization_id": "org-1",
		"mfa_required":          false,
	}, map[string]string{"Authorization": "Bearer " + ownerLogin.AccessToken, "X-Request-ID": "req-admin-create-org-scoped", "User-Agent": "admin-test"})
	assertStatus(t, orgScopedRec, http.StatusCreated)
	orgLoginRec := env.request(t, http.MethodPost, "/api/admin/auth/login", map[string]interface{}{
		"email":    "org-auditor@example.com",
		"password": "OrgAuditPass123!",
	}, map[string]string{"User-Agent": "admin-test"})
	assertStatus(t, orgLoginRec, http.StatusOK)
	var orgLogin application.AdminAuthResponse
	decodeBody(t, orgLoginRec, &orgLogin)
	orgDeniedRec := env.request(t, http.MethodGet, "/api/admin/clients", nil, map[string]string{
		"Authorization": "Bearer " + orgLogin.AccessToken,
		"X-Request-ID":  "req-org-denied-client-list",
		"User-Agent":    "admin-test",
	})
	assertStatus(t, orgDeniedRec, http.StatusForbidden)

	ssoAdminRec := env.request(t, http.MethodPost, "/api/admin/users", map[string]interface{}{
		"email":        "auditor@example.com",
		"display_name": "Auditor",
		"roles":        []string{domain.AdminRoleReadOnlyAuditor},
		"scope_type":   domain.AdminScopeAll,
		"mfa_required": false,
		"sso_provider": "okta",
		"sso_subject":  "okta-subject-1",
	}, map[string]string{"Authorization": "Bearer " + ownerLogin.AccessToken, "X-Request-ID": "req-admin-create-sso", "User-Agent": "admin-test"})
	assertStatus(t, ssoAdminRec, http.StatusCreated)
	ssoLoginRec := env.request(t, http.MethodPost, "/api/admin/auth/sso", map[string]string{
		"provider": "okta",
		"subject":  "okta-subject-1",
	}, map[string]string{"User-Agent": "admin-test"})
	assertStatus(t, ssoLoginRec, http.StatusOK)
	var ssoLogin application.AdminAuthResponse
	decodeBody(t, ssoLoginRec, &ssoLogin)
	if ssoLogin.AccessToken == "" || ssoLogin.Admin == nil || ssoLogin.Admin.Email != "auditor@example.com" {
		t.Fatalf("admin SSO login returned incomplete response: %+v", ssoLogin)
	}

	events, err := env.audit.List(context.Background(), domain.AuditEventFilter{RequestID: "req-support-denied-client", Limit: 1})
	if err != nil || len(events) != 1 {
		t.Fatalf("expected denied tenant audit event, got events=%+v err=%v", events, err)
	}
	deniedEvent := events[0]
	if deniedEvent.ActorType != domain.AdminActorTypeUser || deniedEvent.ActorEmail != "support@example.com" {
		t.Fatalf("expected support actor in audit event: %+v", deniedEvent)
	}
	if deniedEvent.TargetType != "client" || deniedEvent.TargetID != secondary.ID || deniedEvent.RequestID != "req-support-denied-client" {
		t.Fatalf("expected client target/request in audit event: %+v", deniedEvent)
	}
	if deniedEvent.IPAddress == "" || deniedEvent.UserAgent != "admin-test" || deniedEvent.Metadata["status"] != http.StatusForbidden {
		t.Fatalf("expected status/ip/user-agent metadata in audit event: %+v", deniedEvent)
	}
}

func TestBreakGlassAdminKeyIsRateLimitedAndAudited(t *testing.T) {
	env := newE2EEnv(t, e2eOptions{})

	for i := 0; i < 10; i++ {
		rec := env.request(t, http.MethodGet, "/api/admin/clients", nil, map[string]string{
			"X-Admin-Key":  e2eAdminKey,
			"X-Request-ID": fmt.Sprintf("req-breakglass-%d", i),
			"User-Agent":   "breakglass-test",
		})
		assertStatus(t, rec, http.StatusOK)
	}
	limitedRec := env.request(t, http.MethodGet, "/api/admin/clients", nil, map[string]string{
		"X-Admin-Key":  e2eAdminKey,
		"X-Request-ID": "req-breakglass-limited",
		"User-Agent":   "breakglass-test",
	})
	assertStatus(t, limitedRec, http.StatusTooManyRequests)

	events, err := env.audit.List(context.Background(), domain.AuditEventFilter{RequestID: "req-breakglass-0", Limit: 1})
	if err != nil || len(events) != 1 {
		t.Fatalf("expected break-glass audit event, got events=%+v err=%v", events, err)
	}
	if events[0].ActorType != domain.AdminActorTypeBreakGlass || events[0].ActorID != "master-key" || events[0].UserAgent != "breakglass-test" {
		t.Fatalf("expected break-glass actor audit event: %+v", events[0])
	}
	limitedEvents, err := env.audit.List(context.Background(), domain.AuditEventFilter{RequestID: "req-breakglass-limited", Limit: 1})
	if err != nil || len(limitedEvents) != 1 {
		t.Fatalf("expected limited break-glass audit event, got events=%+v err=%v", limitedEvents, err)
	}
	if limitedEvents[0].Metadata["status"] != http.StatusTooManyRequests {
		t.Fatalf("expected rate-limited audit metadata, got %+v", limitedEvents[0])
	}
}

func signupE2EUser(t *testing.T, env *e2eEnv, email, password string) application.AuthResponse {
	t.Helper()
	rec := env.request(t, http.MethodPost, "/api/auth/signup", map[string]interface{}{
		"email":        email,
		"password":     password,
		"session_mode": "token",
	}, env.apiHeaders())
	assertStatus(t, rec, http.StatusCreated)
	var resp application.AuthResponse
	decodeBody(t, rec, &resp)
	if resp.AccessToken == "" || resp.RefreshToken == "" || resp.User == nil {
		t.Fatalf("signup returned incomplete response: %+v", resp)
	}
	return resp
}

func (e *e2eEnv) apiHeaders() map[string]string {
	return map[string]string{"X-API-Key": e.apiKey}
}

func (e *e2eEnv) bearerHeaders(accessToken string) map[string]string {
	return map[string]string{
		"X-API-Key":     e.apiKey,
		"Authorization": "Bearer " + accessToken,
	}
}

func (e *e2eEnv) request(t *testing.T, method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("expected status %d, got %d: %s", want, rec.Code, rec.Body.String())
	}
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, out interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(out); err != nil {
		t.Fatalf("decode response %d %s: %v", rec.Code, rec.Body.String(), err)
	}
}

func tokenFromURL(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url %q: %v", rawURL, err)
	}
	token := parsed.Query().Get("token")
	if token == "" {
		t.Fatalf("url %q did not include token", rawURL)
	}
	return token
}

func authResponseFromRedirect(t *testing.T, env *e2eEnv, rawURL string) application.AuthResponse {
	t.Helper()
	code := redirectAuthCodeFromURL(t, rawURL)
	rec := env.request(t, http.MethodPost, "/api/auth/redirect/exchange", map[string]string{"code": code}, nil)
	assertStatus(t, rec, http.StatusOK)
	var resp application.AuthResponse
	decodeBody(t, rec, &resp)
	if resp.AccessToken == "" {
		t.Fatalf("redirect code exchange returned no access token: %+v", resp)
	}
	return resp
}

func redirectAuthCodeFromURL(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url %q: %v", rawURL, err)
	}
	code := parsed.Query().Get("auth_code")
	if code == "" {
		t.Fatalf("url %q did not include auth_code", rawURL)
	}
	return code
}

func followRedirectOnce(t *testing.T, rawURL string) string {
	t.Helper()
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatalf("follow redirect %q: %v", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected redirect from %q, got %d: %s", rawURL, resp.StatusCode, string(body))
	}
	location := resp.Header.Get("Location")
	if location == "" {
		t.Fatalf("redirect from %q did not include Location", rawURL)
	}
	return location
}

type testOIDCProfile struct {
	Subject       string
	Email         string
	Name          string
	EmailVerified bool
}

type testOIDCProvider struct {
	server  *httptest.Server
	key     *rsa.PrivateKey
	kid     string
	profile testOIDCProfile
	mu      sync.Mutex
	nonces  map[string]string
}

func newTestOIDCProvider(t *testing.T, profile testOIDCProfile) *testOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate oidc key: %v", err)
	}
	provider := &testOIDCProvider{
		key:     key,
		kid:     "test-oidc-key",
		profile: profile,
		nonces:  map[string]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"issuer":                                provider.server.URL,
			"authorization_endpoint":                provider.server.URL + "/authorize",
			"token_endpoint":                        provider.server.URL + "/token",
			"jwks_uri":                              provider.server.URL + "/keys",
			"userinfo_endpoint":                     provider.server.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		code := "oidc-code-" + r.URL.Query().Get("state")
		provider.mu.Lock()
		provider.nonces[code] = r.URL.Query().Get("nonce")
		provider.mu.Unlock()
		redirectURI := r.URL.Query().Get("redirect_uri")
		callback, _ := url.Parse(redirectURI)
		q := callback.Query()
		q.Set("code", code)
		q.Set("state", r.URL.Query().Get("state"))
		callback.RawQuery = q.Encode()
		http.Redirect(w, r, callback.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		clientID, clientSecret, _ := r.BasicAuth()
		if clientID == "" {
			clientID = r.FormValue("client_id")
		}
		if clientSecret == "" {
			clientSecret = r.FormValue("client_secret")
		}
		code := r.FormValue("code")
		provider.mu.Lock()
		nonce := provider.nonces[code]
		delete(provider.nonces, code)
		provider.mu.Unlock()
		if nonce == "" || clientID != "enterprise-client" || clientSecret != "enterprise-secret" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_grant"})
			return
		}
		idToken := provider.signIDToken(t, nonce)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"access_token": "provider-access-token",
			"id_token":     idToken,
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"keys": []map[string]string{rsaPublicJWK(&provider.key.PublicKey, provider.kid)},
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"sub":            profile.Subject,
			"email":          profile.Email,
			"email_verified": profile.EmailVerified,
			"name":           profile.Name,
		})
	})
	provider.server = httptest.NewServer(mux)
	return provider
}

func (p *testOIDCProvider) URL() string {
	return p.server.URL
}

func (p *testOIDCProvider) Close() {
	p.server.Close()
}

func (p *testOIDCProvider) signIDToken(t *testing.T, nonce string) string {
	t.Helper()
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":            p.server.URL,
		"sub":            p.profile.Subject,
		"aud":            "enterprise-client",
		"exp":            now.Add(5 * time.Minute).Unix(),
		"iat":            now.Unix(),
		"nonce":          nonce,
		"email":          p.profile.Email,
		"email_verified": p.profile.EmailVerified,
		"name":           p.profile.Name,
	})
	token.Header["kid"] = p.kid
	signed, err := token.SignedString(p.key)
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return signed
}

func rsaPublicJWK(pub *rsa.PublicKey, kid string) map[string]string {
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"kid": kid,
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func generateTestCertificateBase64(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test cert key: %v", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "idp.example.com",
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test cert: %v", err)
	}
	return base64.StdEncoding.EncodeToString(certDER)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func auditEventsContain(events []*domain.AuditEvent, eventType string) bool {
	for _, event := range events {
		if event.EventType == eventType {
			return true
		}
	}
	return false
}

func defaultBlockedSignupEmailDomains() []string {
	defaults := application.DefaultBlockedSignupEmailDomains()
	domains := make([]string, 0, len(defaults))
	for domain := range defaults {
		domains = append(domains, domain)
	}
	return domains
}

type memoryClientRepo struct {
	mu      sync.Mutex
	clients map[string]*domain.Client
}

func newMemoryClientRepo() *memoryClientRepo {
	return &memoryClientRepo{clients: map[string]*domain.Client{}}
}

func (r *memoryClientRepo) addClient(id, name, slug, apiKey string) *domain.Client {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	client := &domain.Client{
		ID:         id,
		Name:       name,
		Slug:       slug,
		JWTSecret:  "test-jwt-secret-" + id,
		Settings:   map[string]interface{}{},
		Status:     "active",
		TokenMode:  "v1_hs256",
		APIKeyHash: hashE2EKey(apiKey),
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	r.clients[id] = cloneClient(client)
	return cloneClient(client)
}

func (r *memoryClientRepo) setAllowedOrigins(id string, origins []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if client := r.clients[id]; client != nil {
		client.AllowedOrigins = append([]string(nil), origins...)
	}
}

func (r *memoryClientRepo) setSettings(id string, settings map[string]interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if client := r.clients[id]; client != nil {
		client.Settings = map[string]interface{}{}
		for key, value := range settings {
			client.Settings[key] = value
		}
	}
}

func (r *memoryClientRepo) Create(ctx context.Context, client *domain.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[client.ID] = cloneClient(client)
	return nil
}

func (r *memoryClientRepo) GetByID(ctx context.Context, id string) (*domain.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	client := r.clients[id]
	if client == nil {
		return nil, domain.ErrNotFound
	}
	return cloneClient(client), nil
}

func (r *memoryClientRepo) GetBySlug(ctx context.Context, slug string) (*domain.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, client := range r.clients {
		if client.Slug == slug {
			return cloneClient(client), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r *memoryClientRepo) GetByAPIKeyHash(ctx context.Context, hash string) (*domain.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, client := range r.clients {
		if client.APIKeyHash == hash {
			return cloneClient(client), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r *memoryClientRepo) List(ctx context.Context) ([]*domain.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.Client, 0, len(r.clients))
	for _, client := range r.clients {
		out = append(out, cloneClient(client))
	}
	return out, nil
}

func (r *memoryClientRepo) Update(ctx context.Context, client *domain.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.clients[client.ID]; !ok {
		return domain.ErrNotFound
	}
	r.clients[client.ID] = cloneClient(client)
	return nil
}

func (r *memoryClientRepo) UpdateJWTSecret(ctx context.Context, id, newSecret string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	client := r.clients[id]
	if client == nil {
		return domain.ErrNotFound
	}
	client.JWTSecret = newSecret
	client.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *memoryClientRepo) UpdateAPIKeyHash(ctx context.Context, id, newHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	client := r.clients[id]
	if client == nil {
		return domain.ErrNotFound
	}
	client.APIKeyHash = newHash
	client.UpdatedAt = time.Now().UTC()
	return nil
}

type memoryUserRepo struct {
	mu       sync.Mutex
	nextID   int
	users    map[string]*domain.User
	emailIdx map[string]string
}

func newMemoryUserRepo() *memoryUserRepo {
	return &memoryUserRepo{
		users:    map[string]*domain.User{},
		emailIdx: map[string]string{},
	}
}

func (r *memoryUserRepo) Create(ctx context.Context, clientID, email, passwordHash, displayName string) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	normalized := strings.ToLower(strings.TrimSpace(email))
	key := clientID + "|" + normalized
	if _, ok := r.emailIdx[key]; ok {
		return nil, domain.ErrDuplicateEmail
	}
	r.nextID++
	now := time.Now().UTC()
	user := &domain.User{
		ID:           fmt.Sprintf("user-%d", r.nextID),
		ClientID:     clientID,
		Email:        normalized,
		PasswordHash: &passwordHash,
		DisplayName:  displayName,
		Timezone:     "UTC",
		Locale:       "en",
		Role:         "user",
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	r.users[user.ID] = cloneUser(user)
	r.emailIdx[key] = user.ID
	return cloneUser(user), nil
}

func (r *memoryUserRepo) CreateOAuth(ctx context.Context, clientID, email, displayName, avatarURL string) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	normalized := strings.ToLower(strings.TrimSpace(email))
	key := clientID + "|" + normalized
	if normalized != "" {
		if _, ok := r.emailIdx[key]; ok {
			return nil, domain.ErrDuplicateEmail
		}
	}
	r.nextID++
	now := time.Now().UTC()
	user := &domain.User{
		ID:            fmt.Sprintf("user-%d", r.nextID),
		ClientID:      clientID,
		Email:         normalized,
		EmailVerified: true,
		DisplayName:   displayName,
		AvatarURL:     avatarURL,
		Timezone:      "UTC",
		Locale:        "en",
		Role:          "user",
		Status:        "active",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	r.users[user.ID] = cloneUser(user)
	if normalized != "" {
		r.emailIdx[key] = user.ID
	}
	return cloneUser(user), nil
}

func (r *memoryUserRepo) GetByEmail(ctx context.Context, clientID, email string) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.emailIdx[clientID+"|"+strings.ToLower(strings.TrimSpace(email))]
	if id == "" {
		return nil, domain.ErrNotFound
	}
	user := r.users[id]
	if user == nil || user.Status == "deleted" {
		return nil, domain.ErrNotFound
	}
	return cloneUser(user), nil
}

func (r *memoryUserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	user := r.users[id]
	if user == nil || user.Status == "deleted" {
		return nil, domain.ErrNotFound
	}
	return cloneUser(user), nil
}

func (r *memoryUserRepo) mustGet(t *testing.T, id string) *domain.User {
	t.Helper()
	user, err := r.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("get user %s: %v", id, err)
	}
	return user
}

func (r *memoryUserRepo) UpdateLastLogin(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	user := r.users[userID]
	if user == nil {
		return domain.ErrNotFound
	}
	now := time.Now().UTC()
	user.LastLoginAt = &now
	user.UpdatedAt = now
	return nil
}

func (r *memoryUserRepo) VerifyEmail(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	user := r.users[userID]
	if user == nil {
		return domain.ErrNotFound
	}
	user.EmailVerified = true
	user.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *memoryUserRepo) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	user := r.users[userID]
	if user == nil {
		return domain.ErrNotFound
	}
	user.PasswordHash = &passwordHash
	user.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *memoryUserRepo) UpdateProfile(ctx context.Context, userID, displayName, timezone string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	user := r.users[userID]
	if user == nil {
		return domain.ErrNotFound
	}
	user.DisplayName = displayName
	user.Timezone = timezone
	user.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *memoryUserRepo) UpdateStatus(ctx context.Context, userID, status string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	user := r.users[userID]
	if user == nil {
		return domain.ErrNotFound
	}
	user.Status = status
	user.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *memoryUserRepo) SetTOTPSecret(ctx context.Context, userID, secret string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	user := r.users[userID]
	if user == nil {
		return domain.ErrNotFound
	}
	user.TOTPSecret = &secret
	user.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *memoryUserRepo) EnableTOTP(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	user := r.users[userID]
	if user == nil {
		return domain.ErrNotFound
	}
	user.TOTPEnabled = true
	user.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *memoryUserRepo) DisableTOTP(ctx context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	user := r.users[userID]
	if user == nil {
		return domain.ErrNotFound
	}
	user.TOTPEnabled = false
	user.TOTPSecret = nil
	user.UpdatedAt = time.Now().UTC()
	return nil
}

type memorySession struct {
	id        string
	userID    string
	clientID  string
	tokenHash string
	ip        string
	ua        string
	expiresAt time.Time
	revoked   bool
	createdAt time.Time
}

type memorySessionRepo struct {
	mu       sync.Mutex
	nextID   int
	sessions map[string]*memorySession
}

func newMemorySessionRepo() *memorySessionRepo {
	return &memorySessionRepo{sessions: map[string]*memorySession{}}
}

func (r *memorySessionRepo) Create(ctx context.Context, userID, clientID, ip, ua string, ttl time.Duration) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rawToken, err := application.GenerateToken(32)
	if err != nil {
		return "", err
	}
	r.nextID++
	id := fmt.Sprintf("session-%d", r.nextID)
	now := time.Now()
	r.sessions[id] = &memorySession{
		id:        id,
		userID:    userID,
		clientID:  clientID,
		tokenHash: application.HashToken(rawToken),
		ip:        ip,
		ua:        ua,
		expiresAt: now.Add(ttl),
		createdAt: now,
	}
	return rawToken, nil
}

func (r *memorySessionRepo) Validate(ctx context.Context, clientID, rawToken string) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	hash := application.HashToken(rawToken)
	for _, session := range r.sessions {
		if session.clientID == clientID && session.tokenHash == hash && !session.revoked && time.Now().Before(session.expiresAt) {
			return session.userID, session.id, nil
		}
	}
	return "", "", domain.ErrInvalidToken
}

func (r *memorySessionRepo) ListForUser(ctx context.Context, clientID, userID string) ([]*domain.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sessions := []*domain.Session{}
	for _, session := range r.sessions {
		if session.clientID != clientID || session.userID != userID || session.revoked || !time.Now().Before(session.expiresAt) {
			continue
		}
		sessions = append(sessions, &domain.Session{
			ID:        session.id,
			UserID:    session.userID,
			ClientID:  session.clientID,
			UserAgent: session.ua,
			IPAddress: session.ip,
			ExpiresAt: session.expiresAt,
			Revoked:   session.revoked,
			CreatedAt: session.createdAt,
		})
	}
	return sessions, nil
}

func (r *memorySessionRepo) Revoke(ctx context.Context, sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if session := r.sessions[sessionID]; session != nil {
		session.revoked = true
	}
	return nil
}

func (r *memorySessionRepo) RevokeByToken(ctx context.Context, clientID, rawToken string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	hash := application.HashToken(rawToken)
	for _, session := range r.sessions {
		if session.clientID == clientID && session.tokenHash == hash {
			session.revoked = true
		}
	}
	return nil
}

func (r *memorySessionRepo) RevokeForUser(ctx context.Context, clientID, userID, sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	session := r.sessions[sessionID]
	if session == nil || session.clientID != clientID || session.userID != userID || session.revoked {
		return domain.ErrNotFound
	}
	session.revoked = true
	return nil
}

func (r *memorySessionRepo) RevokeAllForUser(ctx context.Context, clientID, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, session := range r.sessions {
		if session.clientID == clientID && session.userID == userID {
			session.revoked = true
		}
	}
	return nil
}

type memoryDeviceRepo struct {
	mu      sync.Mutex
	nextID  int
	devices map[string]*domain.UserDevice
	byFP    map[string]string
}

func newMemoryDeviceRepo() *memoryDeviceRepo {
	return &memoryDeviceRepo{
		devices: map[string]*domain.UserDevice{},
		byFP:    map[string]string{},
	}
}

func (r *memoryDeviceRepo) Upsert(ctx context.Context, device *domain.UserDevice) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := device.ClientID + "|" + device.UserID + "|" + device.Fingerprint
	if id := r.byFP[key]; id != "" {
		existing := r.devices[id]
		existing.UserAgent = device.UserAgent
		existing.IPAddress = device.IPAddress
		existing.LastSeenAt = device.LastSeenAt
		existing.UpdatedAt = time.Now().UTC()
		if device.Name != "" && device.Name != "Device" {
			existing.Name = device.Name
		}
		if device.Trusted {
			existing.Trusted = true
			existing.Remembered = true
			existing.TrustExpiresAt = device.TrustExpiresAt
		}
		if device.Metadata != nil {
			existing.Metadata = cloneMap(device.Metadata)
		}
		return nil
	}
	r.nextID++
	cp := cloneUserDevice(device)
	cp.ID = fmt.Sprintf("device-%d", r.nextID)
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	}
	if cp.UpdatedAt.IsZero() {
		cp.UpdatedAt = cp.CreatedAt
	}
	r.devices[cp.ID] = cp
	r.byFP[key] = cp.ID
	return nil
}

func (r *memoryDeviceRepo) GetByFingerprint(ctx context.Context, clientID, userID, fingerprint string) (*domain.UserDevice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.byFP[clientID+"|"+userID+"|"+fingerprint]
	if id == "" || r.devices[id] == nil {
		return nil, domain.ErrNotFound
	}
	return cloneUserDevice(r.devices[id]), nil
}

func (r *memoryDeviceRepo) GetForUser(ctx context.Context, clientID, userID, deviceID string) (*domain.UserDevice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	device := r.devices[deviceID]
	if device == nil || device.ClientID != clientID || device.UserID != userID {
		return nil, domain.ErrNotFound
	}
	return cloneUserDevice(device), nil
}

func (r *memoryDeviceRepo) ListForUser(ctx context.Context, clientID, userID string) ([]*domain.UserDevice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.UserDevice, 0)
	for _, device := range r.devices {
		if device.ClientID == clientID && device.UserID == userID {
			out = append(out, cloneUserDevice(device))
		}
	}
	return out, nil
}

func (r *memoryDeviceRepo) Trust(ctx context.Context, clientID, userID, deviceID, name string, trusted bool, expiresAt *time.Time) (*domain.UserDevice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	device := r.devices[deviceID]
	if device == nil || device.ClientID != clientID || device.UserID != userID {
		return nil, domain.ErrNotFound
	}
	if strings.TrimSpace(name) != "" {
		device.Name = strings.TrimSpace(name)
	}
	device.Trusted = trusted
	device.Remembered = trusted
	device.TrustExpiresAt = expiresAt
	device.UpdatedAt = time.Now().UTC()
	return cloneUserDevice(device), nil
}

func (r *memoryDeviceRepo) Delete(ctx context.Context, clientID, userID, deviceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	device := r.devices[deviceID]
	if device == nil || device.ClientID != clientID || device.UserID != userID {
		return domain.ErrNotFound
	}
	delete(r.byFP, device.ClientID+"|"+device.UserID+"|"+device.Fingerprint)
	delete(r.devices, deviceID)
	return nil
}

type memoryToken struct {
	id        string
	userID    string
	tokenHash string
	tokenType string
	expiresAt time.Time
	used      bool
	raw       string
}

type memoryTokenRepo struct {
	mu     sync.Mutex
	nextID int
	tokens map[string]*memoryToken
}

func newMemoryTokenRepo() *memoryTokenRepo {
	return &memoryTokenRepo{tokens: map[string]*memoryToken{}}
}

func (r *memoryTokenRepo) Create(ctx context.Context, userID, tokenType string, ttl time.Duration) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, token := range r.tokens {
		if token.userID == userID && token.tokenType == tokenType && !token.used {
			token.used = true
		}
	}
	rawToken, err := application.GenerateToken(32)
	if err != nil {
		return "", err
	}
	r.nextID++
	id := fmt.Sprintf("token-%d", r.nextID)
	r.tokens[id] = &memoryToken{
		id:        id,
		userID:    userID,
		tokenHash: application.HashToken(rawToken),
		tokenType: tokenType,
		expiresAt: time.Now().Add(ttl),
		raw:       rawToken,
	}
	return rawToken, nil
}

func (r *memoryTokenRepo) Validate(ctx context.Context, rawToken, tokenType string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	hash := application.HashToken(rawToken)
	for _, token := range r.tokens {
		if token.tokenHash == hash && token.tokenType == tokenType && !token.used && time.Now().Before(token.expiresAt) {
			token.used = true
			return token.userID, nil
		}
	}
	return "", domain.ErrInvalidToken
}

func (r *memoryTokenRepo) latestFor(t *testing.T, userID, tokenType string) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	var latest *memoryToken
	for _, token := range r.tokens {
		if token.userID == userID && token.tokenType == tokenType {
			if latest == nil || token.id > latest.id {
				latest = token
			}
		}
	}
	if latest == nil || latest.raw == "" {
		t.Fatalf("no token created for user=%s type=%s", userID, tokenType)
	}
	return latest.raw
}

type memoryRecoveryCodeRepo struct {
	mu     sync.Mutex
	hashes map[string]map[string]bool
}

func newMemoryRecoveryCodeRepo() *memoryRecoveryCodeRepo {
	return &memoryRecoveryCodeRepo{hashes: map[string]map[string]bool{}}
}

func (r *memoryRecoveryCodeRepo) ReplaceForUser(ctx context.Context, userID string, codeHashes []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hashes[userID] = map[string]bool{}
	for _, hash := range codeHashes {
		r.hashes[userID][hash] = false
	}
	return nil
}

func (r *memoryRecoveryCodeRepo) CountUnused(ctx context.Context, userID string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, used := range r.hashes[userID] {
		if !used {
			count++
		}
	}
	return count, nil
}

func (r *memoryRecoveryCodeRepo) MarkUsedByHash(ctx context.Context, userID, codeHash string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	used, ok := r.hashes[userID][codeHash]
	if !ok || used {
		return false, nil
	}
	r.hashes[userID][codeHash] = true
	return true, nil
}

type memoryCacheItem struct {
	value     string
	expiresAt time.Time
}

type memoryCache struct {
	mu    sync.Mutex
	items map[string]memoryCacheItem
}

func newMemoryCache() *memoryCache {
	return &memoryCache{items: map[string]memoryCacheItem{}}
}

func (c *memoryCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = memoryCacheItem{value: fmt.Sprint(value), expiresAt: time.Now().Add(ttl)}
	return nil
}

func (c *memoryCache) Get(ctx context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.items[key]
	if !ok || time.Now().After(item.expiresAt) {
		delete(c.items, key)
		return "", domain.ErrNotFound
	}
	return item.value, nil
}

func (c *memoryCache) Del(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
	return nil
}

func (c *memoryCache) Incr(ctx context.Context, key string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item := c.items[key]
	if !item.expiresAt.IsZero() && time.Now().After(item.expiresAt) {
		item = memoryCacheItem{}
	}
	var current int64
	_, _ = fmt.Sscanf(item.value, "%d", &current)
	current++
	item.value = fmt.Sprintf("%d", current)
	c.items[key] = item
	return current, nil
}

func (c *memoryCache) Expire(ctx context.Context, key string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	item := c.items[key]
	item.expiresAt = time.Now().Add(ttl)
	c.items[key] = item
	return nil
}

func (c *memoryCache) Exists(ctx context.Context, key string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.items[key]
	if !ok || time.Now().After(item.expiresAt) {
		delete(c.items, key)
		return false, nil
	}
	return true, nil
}

func (c *memoryCache) Ping(ctx context.Context) error {
	return nil
}

type nilCache struct{}

func (nilCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return domain.ErrRedisRequired
}
func (nilCache) Get(ctx context.Context, key string) (string, error) {
	return "", domain.ErrRedisRequired
}
func (nilCache) Del(ctx context.Context, key string) error { return domain.ErrRedisRequired }
func (nilCache) Incr(ctx context.Context, key string) (int64, error) {
	return 0, domain.ErrRedisRequired
}
func (nilCache) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return domain.ErrRedisRequired
}
func (nilCache) Exists(ctx context.Context, key string) (bool, error) {
	return false, domain.ErrRedisRequired
}
func (nilCache) Ping(ctx context.Context) error { return domain.ErrRedisRequired }

type memoryRateLimiter struct {
	mu     sync.Mutex
	counts map[string]int64
	locks  map[string]bool
}

func newMemoryRateLimiter() *memoryRateLimiter {
	return &memoryRateLimiter{counts: map[string]int64{}, locks: map[string]bool{}}
}

func (r *memoryRateLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[key]++
	remaining := limit - r.counts[key]
	if remaining < 0 {
		remaining = 0
	}
	return r.counts[key] <= limit, remaining, nil
}

func (r *memoryRateLimiter) IsLocked(ctx context.Context, email string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.locks[email]
}

func (r *memoryRateLimiter) RecordFailedLogin(ctx context.Context, email string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := "login_fail:" + email
	r.counts[key]++
	if r.counts[key] >= 5 {
		r.locks[email] = true
		delete(r.counts, key)
	}
}

func (r *memoryRateLimiter) ClearFailedLogins(ctx context.Context, email string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.counts, "login_fail:"+email)
	delete(r.locks, email)
}

type memoryAuditRepo struct {
	mu     sync.Mutex
	events []domain.AuditEvent
}

func (r *memoryAuditRepo) Log(ctx context.Context, clientID string, userID *string, eventType, ip, ua string, metadata map[string]interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	actorID := ""
	if userID != nil {
		actorID = *userID
	}
	r.events = append(r.events, domain.AuditEvent{
		ID:        int64(len(r.events) + 1),
		ClientID:  clientID,
		UserID:    userID,
		EventType: eventType,
		ActorType: "user",
		ActorID:   actorID,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  metadata,
		CreatedAt: time.Now().UTC(),
	})
}

func (r *memoryAuditRepo) LogAdmin(ctx context.Context, event *domain.AuditEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if event.Metadata == nil {
		event.Metadata = map[string]interface{}{}
	}
	if event.BeforeMetadata == nil {
		event.BeforeMetadata = map[string]interface{}{}
	}
	if event.AfterMetadata == nil {
		event.AfterMetadata = map[string]interface{}{}
	}
	cp := *event
	cp.ID = int64(len(r.events) + 1)
	cp.CreatedAt = time.Now().UTC()
	cp.Metadata = cloneAuditMap(event.Metadata)
	cp.BeforeMetadata = cloneAuditMap(event.BeforeMetadata)
	cp.AfterMetadata = cloneAuditMap(event.AfterMetadata)
	r.events = append(r.events, cp)
}

func (r *memoryAuditRepo) List(ctx context.Context, filter domain.AuditEventFilter) ([]*domain.AuditEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	events := make([]*domain.AuditEvent, 0, limit)
	for i := len(r.events) - 1; i >= 0 && len(events) < limit; i-- {
		event := r.events[i]
		if filter.ClientID != "" && event.ClientID != filter.ClientID {
			continue
		}
		if filter.UserID != "" {
			if event.UserID == nil || *event.UserID != filter.UserID {
				continue
			}
		}
		if filter.EventType != "" && event.EventType != filter.EventType {
			continue
		}
		if filter.ActorType != "" && event.ActorType != filter.ActorType {
			continue
		}
		if filter.ActorID != "" && event.ActorID != filter.ActorID {
			continue
		}
		if filter.TargetType != "" && event.TargetType != filter.TargetType {
			continue
		}
		if filter.TargetID != "" && event.TargetID != filter.TargetID {
			continue
		}
		if filter.RequestID != "" && event.RequestID != filter.RequestID {
			continue
		}
		cp := event
		if event.UserID != nil {
			userID := *event.UserID
			cp.UserID = &userID
		}
		cp.Metadata = map[string]interface{}{}
		for key, value := range event.Metadata {
			cp.Metadata[key] = value
		}
		cp.BeforeMetadata = cloneAuditMap(event.BeforeMetadata)
		cp.AfterMetadata = cloneAuditMap(event.AfterMetadata)
		events = append(events, &cp)
	}
	return events, nil
}

type memoryAdminRepo struct {
	mu     sync.Mutex
	admins map[string]*domain.AdminUser
}

func newMemoryAdminRepo() *memoryAdminRepo {
	return &memoryAdminRepo{admins: map[string]*domain.AdminUser{}}
}

func (r *memoryAdminRepo) Create(ctx context.Context, admin *domain.AdminUser) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.admins {
		if strings.EqualFold(existing.Email, admin.Email) {
			return domain.ErrDuplicateEmail
		}
	}
	r.admins[admin.ID] = cloneAdminUser(admin)
	return nil
}

func (r *memoryAdminRepo) GetByID(ctx context.Context, id string) (*domain.AdminUser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	admin := r.admins[id]
	if admin == nil {
		return nil, domain.ErrNotFound
	}
	return cloneAdminUser(admin), nil
}

func (r *memoryAdminRepo) GetByEmail(ctx context.Context, email string) (*domain.AdminUser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, admin := range r.admins {
		if strings.EqualFold(admin.Email, email) {
			return cloneAdminUser(admin), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r *memoryAdminRepo) GetBySSOIdentity(ctx context.Context, provider, subject string) (*domain.AdminUser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, admin := range r.admins {
		if strings.EqualFold(admin.SSOProvider, provider) && admin.SSOSubject == subject {
			return cloneAdminUser(admin), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r *memoryAdminRepo) List(ctx context.Context) ([]*domain.AdminUser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.AdminUser, 0, len(r.admins))
	for _, admin := range r.admins {
		out = append(out, cloneAdminUser(admin))
	}
	return out, nil
}

func (r *memoryAdminRepo) UpdateLastLogin(ctx context.Context, id string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	admin := r.admins[id]
	if admin == nil {
		return domain.ErrNotFound
	}
	admin.LastLoginAt = &at
	admin.UpdatedAt = at
	return nil
}

func cloneAdminUser(admin *domain.AdminUser) *domain.AdminUser {
	if admin == nil {
		return nil
	}
	cp := *admin
	cp.Roles = append([]string(nil), admin.Roles...)
	if admin.LastLoginAt != nil {
		last := *admin.LastLoginAt
		cp.LastLoginAt = &last
	}
	return &cp
}

type recordingMailer struct {
	mu                sync.Mutex
	verifyURLs        []string
	passwordResetURLs []string
	magicURLs         []string
}

func (m *recordingMailer) Send(to, subject, htmlBody string) error { return nil }
func (m *recordingMailer) SendVerifyEmail(to, displayName, verifyURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifyURLs = append(m.verifyURLs, verifyURL)
	return nil
}
func (m *recordingMailer) SendPasswordReset(to, displayName, resetURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.passwordResetURLs = append(m.passwordResetURLs, resetURL)
	return nil
}
func (m *recordingMailer) SendMagicLink(to, magicURL string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.magicURLs = append(m.magicURLs, magicURL)
	return nil
}

func (m *recordingMailer) waitForVerifyURL(t *testing.T) string {
	t.Helper()
	return m.waitForURL(t, func() []string { return m.verifyURLs }, "verification email")
}

func (m *recordingMailer) waitForPasswordResetURL(t *testing.T) string {
	t.Helper()
	return m.waitForURL(t, func() []string { return m.passwordResetURLs }, "password reset email")
}

func (m *recordingMailer) waitForMagicURL(t *testing.T) string {
	t.Helper()
	return m.waitForURL(t, func() []string { return m.magicURLs }, "magic link email")
}

func (m *recordingMailer) waitForURL(t *testing.T, getURLs func() []string, description string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		urls := getURLs()
		if len(urls) > 0 {
			out := urls[len(urls)-1]
			m.mu.Unlock()
			return out
		}
		m.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
	return ""
}

type memoryOAuthRepo struct {
	mu       sync.Mutex
	accounts map[string]*domain.OAuthAccount
}

func newMemoryOAuthRepo() *memoryOAuthRepo {
	return &memoryOAuthRepo{accounts: map[string]*domain.OAuthAccount{}}
}

func (r *memoryOAuthRepo) FindByProvider(ctx context.Context, clientID, provider, providerUserID string) (*domain.OAuthAccount, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	account := r.accounts[clientID+"|"+provider+"|"+providerUserID]
	if account == nil {
		return nil, domain.ErrNotFound
	}
	cp := *account
	return &cp, nil
}

func (r *memoryOAuthRepo) Link(ctx context.Context, userID, clientID, provider, providerUserID, email, accessToken, refreshToken string, rawProfile []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	emailCopy := email
	now := time.Now().UTC()
	r.accounts[clientID+"|"+provider+"|"+providerUserID] = &domain.OAuthAccount{
		ID:             "oauth-" + providerUserID,
		UserID:         userID,
		ClientID:       clientID,
		Provider:       provider,
		ProviderUserID: providerUserID,
		Email:          &emailCopy,
		AccessToken:    accessToken,
		RefreshToken:   refreshToken,
		RawProfile:     rawProfile,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	return nil
}

type memoryOrganizationRepo struct {
	mu            sync.Mutex
	orgs          map[string]*domain.Organization
	memberships   map[string]*domain.OrganizationMembership
	invitations   map[string]*domain.OrganizationInvitation
	inviteByToken map[string]string
	policies      map[string]*domain.OrganizationAuthorizationPolicy
	groupMappings map[string]*domain.OrganizationGroupMapping
}

func newMemoryOrganizationRepo() *memoryOrganizationRepo {
	return &memoryOrganizationRepo{
		orgs:          map[string]*domain.Organization{},
		memberships:   map[string]*domain.OrganizationMembership{},
		invitations:   map[string]*domain.OrganizationInvitation{},
		inviteByToken: map[string]string{},
		policies:      map[string]*domain.OrganizationAuthorizationPolicy{},
		groupMappings: map[string]*domain.OrganizationGroupMapping{},
	}
}

func (r *memoryOrganizationRepo) CreateOrganization(ctx context.Context, org *domain.Organization, owner *domain.OrganizationMembership) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.orgs {
		if existing.ClientID == org.ClientID && strings.EqualFold(existing.Slug, org.Slug) {
			return domain.ErrDuplicateOrganization
		}
	}
	r.orgs[org.ID] = cloneOrganization(org)
	r.memberships[membershipKey(owner.OrganizationID, owner.UserID)] = cloneOrganizationMembership(owner)
	return nil
}

func (r *memoryOrganizationRepo) UpdateOrganization(ctx context.Context, org *domain.Organization) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.orgs[org.ID] == nil || r.orgs[org.ID].ClientID != org.ClientID {
		return domain.ErrNotFound
	}
	for _, existing := range r.orgs {
		if existing.ID != org.ID && existing.ClientID == org.ClientID && strings.EqualFold(existing.Slug, org.Slug) {
			return domain.ErrDuplicateOrganization
		}
	}
	r.orgs[org.ID] = cloneOrganization(org)
	return nil
}

func (r *memoryOrganizationRepo) GetOrganization(ctx context.Context, clientID, organizationID string) (*domain.Organization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	org := r.orgs[organizationID]
	if org == nil || org.ClientID != clientID {
		return nil, domain.ErrNotFound
	}
	return cloneOrganization(org), nil
}

func (r *memoryOrganizationRepo) ListOrganizationsForUser(ctx context.Context, clientID, userID string) ([]domain.OrganizationMembershipDetails, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]domain.OrganizationMembershipDetails, 0)
	for _, membership := range r.memberships {
		if membership.ClientID != clientID || membership.UserID != userID || membership.Status != "active" {
			continue
		}
		org := r.orgs[membership.OrganizationID]
		if org == nil || org.ClientID != clientID {
			continue
		}
		out = append(out, domain.OrganizationMembershipDetails{
			Organization: cloneOrganization(org),
			Membership:   cloneOrganizationMembership(membership),
		})
	}
	return out, nil
}

func (r *memoryOrganizationRepo) GetMembership(ctx context.Context, clientID, organizationID, userID string) (*domain.OrganizationMembership, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	membership := r.memberships[membershipKey(organizationID, userID)]
	if membership == nil || membership.ClientID != clientID || membership.Status != "active" {
		return nil, domain.ErrNotFound
	}
	return cloneOrganizationMembership(membership), nil
}

func (r *memoryOrganizationRepo) ListMemberships(ctx context.Context, clientID, organizationID string) ([]*domain.OrganizationMembership, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.OrganizationMembership, 0)
	for _, membership := range r.memberships {
		if membership.ClientID == clientID && membership.OrganizationID == organizationID && membership.Status == "active" {
			out = append(out, cloneOrganizationMembership(membership))
		}
	}
	return out, nil
}

func (r *memoryOrganizationRepo) UpsertMembership(ctx context.Context, membership *domain.OrganizationMembership) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := membershipKey(membership.OrganizationID, membership.UserID)
	if existing := r.memberships[key]; existing != nil {
		membership.ID = existing.ID
		membership.CreatedAt = existing.CreatedAt
	}
	if membership.ID == "" {
		membership.ID = fmt.Sprintf("membership-%d", len(r.memberships)+1)
	}
	if membership.CreatedAt.IsZero() {
		membership.CreatedAt = time.Now().UTC()
	}
	if membership.UpdatedAt.IsZero() {
		membership.UpdatedAt = time.Now().UTC()
	}
	membership.Status = "active"
	r.memberships[key] = cloneOrganizationMembership(membership)
	return nil
}

func (r *memoryOrganizationRepo) UpdateMembership(ctx context.Context, membership *domain.OrganizationMembership) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := membershipKey(membership.OrganizationID, membership.UserID)
	existing := r.memberships[key]
	if existing == nil || existing.ClientID != membership.ClientID || existing.Status != "active" {
		return domain.ErrNotFound
	}
	cp := cloneOrganizationMembership(membership)
	cp.ID = existing.ID
	cp.CreatedAt = existing.CreatedAt
	cp.Status = "active"
	cp.UpdatedAt = time.Now().UTC()
	r.memberships[key] = cp
	return nil
}

func (r *memoryOrganizationRepo) DeleteMembership(ctx context.Context, clientID, organizationID, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := membershipKey(organizationID, userID)
	membership := r.memberships[key]
	if membership == nil || membership.ClientID != clientID {
		return domain.ErrNotFound
	}
	delete(r.memberships, key)
	return nil
}

func (r *memoryOrganizationRepo) CreateInvitation(ctx context.Context, invitation *domain.OrganizationInvitation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.invitations[invitation.ID] = cloneOrganizationInvitation(invitation)
	r.inviteByToken[invitation.TokenHash] = invitation.ID
	return nil
}

func (r *memoryOrganizationRepo) ListInvitations(ctx context.Context, clientID, organizationID string) ([]*domain.OrganizationInvitation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.OrganizationInvitation, 0)
	for _, invitation := range r.invitations {
		if invitation.ClientID == clientID && invitation.OrganizationID == organizationID {
			out = append(out, cloneOrganizationInvitation(invitation))
		}
	}
	return out, nil
}

func (r *memoryOrganizationRepo) GetInvitation(ctx context.Context, clientID, organizationID, invitationID string) (*domain.OrganizationInvitation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	invitation := r.invitations[invitationID]
	if invitation == nil || invitation.ClientID != clientID || invitation.OrganizationID != organizationID {
		return nil, domain.ErrNotFound
	}
	return cloneOrganizationInvitation(invitation), nil
}

func (r *memoryOrganizationRepo) GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*domain.OrganizationInvitation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.inviteByToken[tokenHash]
	invitation := r.invitations[id]
	if invitation == nil {
		return nil, domain.ErrNotFound
	}
	return cloneOrganizationInvitation(invitation), nil
}

func (r *memoryOrganizationRepo) MarkInvitationAccepted(ctx context.Context, invitationID, userID string) error {
	_ = userID
	r.mu.Lock()
	defer r.mu.Unlock()
	invitation := r.invitations[invitationID]
	if invitation == nil || invitation.Status != "pending" {
		return domain.ErrNotFound
	}
	now := time.Now().UTC()
	invitation.Status = "accepted"
	invitation.AcceptedAt = &now
	invitation.UpdatedAt = now
	return nil
}

func (r *memoryOrganizationRepo) RevokeInvitation(ctx context.Context, clientID, organizationID, invitationID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	invitation := r.invitations[invitationID]
	if invitation == nil || invitation.ClientID != clientID || invitation.OrganizationID != organizationID || invitation.Status != "pending" {
		return domain.ErrNotFound
	}
	now := time.Now().UTC()
	invitation.Status = "revoked"
	invitation.RevokedAt = &now
	invitation.UpdatedAt = now
	return nil
}

func (r *memoryOrganizationRepo) GetAuthorizationPolicy(ctx context.Context, clientID, organizationID string) (*domain.OrganizationAuthorizationPolicy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	policy := r.policies[organizationID]
	if policy == nil || policy.ClientID != clientID {
		return nil, domain.ErrNotFound
	}
	return cloneAuthorizationPolicy(policy), nil
}

func (r *memoryOrganizationRepo) UpsertAuthorizationPolicy(ctx context.Context, policy *domain.OrganizationAuthorizationPolicy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.orgs[policy.OrganizationID] == nil || r.orgs[policy.OrganizationID].ClientID != policy.ClientID {
		return domain.ErrNotFound
	}
	now := time.Now().UTC()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	if policy.UpdatedAt.IsZero() {
		policy.UpdatedAt = now
	}
	r.policies[policy.OrganizationID] = cloneAuthorizationPolicy(policy)
	return nil
}

func (r *memoryOrganizationRepo) ListGroupMappings(ctx context.Context, clientID, organizationID string) ([]*domain.OrganizationGroupMapping, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.OrganizationGroupMapping, 0)
	for _, mapping := range r.groupMappings {
		if mapping.ClientID == clientID && mapping.OrganizationID == organizationID {
			out = append(out, cloneGroupMapping(mapping))
		}
	}
	return out, nil
}

func (r *memoryOrganizationRepo) GetGroupMapping(ctx context.Context, clientID, organizationID, mappingID string) (*domain.OrganizationGroupMapping, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	mapping := r.groupMappings[mappingID]
	if mapping == nil || mapping.ClientID != clientID || mapping.OrganizationID != organizationID {
		return nil, domain.ErrNotFound
	}
	return cloneGroupMapping(mapping), nil
}

func (r *memoryOrganizationRepo) UpsertGroupMapping(ctx context.Context, mapping *domain.OrganizationGroupMapping) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if mapping.ID == "" {
		mapping.ID = fmt.Sprintf("group-mapping-%d", len(r.groupMappings)+1)
	}
	now := time.Now().UTC()
	for id, existing := range r.groupMappings {
		if existing.OrganizationID == mapping.OrganizationID &&
			existing.Source == mapping.Source &&
			existing.SourceID == mapping.SourceID &&
			existing.Group == mapping.Group {
			mapping.ID = id
			mapping.CreatedAt = existing.CreatedAt
			break
		}
	}
	if mapping.CreatedAt.IsZero() {
		mapping.CreatedAt = now
	}
	if mapping.UpdatedAt.IsZero() {
		mapping.UpdatedAt = now
	}
	r.groupMappings[mapping.ID] = cloneGroupMapping(mapping)
	return nil
}

func (r *memoryOrganizationRepo) DeleteGroupMapping(ctx context.Context, clientID, organizationID, mappingID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	mapping := r.groupMappings[mappingID]
	if mapping == nil || mapping.ClientID != clientID || mapping.OrganizationID != organizationID {
		return domain.ErrNotFound
	}
	delete(r.groupMappings, mappingID)
	return nil
}

func (r *memoryOrganizationRepo) ListGroupMappingsForSource(ctx context.Context, clientID, source, sourceID string, groups []string) ([]*domain.OrganizationGroupMapping, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	groupSet := map[string]struct{}{}
	for _, group := range groups {
		groupSet[domain.NormalizeGroupName(group)] = struct{}{}
	}
	out := make([]*domain.OrganizationGroupMapping, 0)
	for _, mapping := range r.groupMappings {
		if mapping.ClientID != clientID || mapping.Source != source {
			continue
		}
		if mapping.SourceID != "" && mapping.SourceID != sourceID {
			continue
		}
		if _, ok := groupSet[domain.NormalizeGroupName(mapping.Group)]; !ok {
			continue
		}
		out = append(out, cloneGroupMapping(mapping))
	}
	return out, nil
}

type memoryServiceAccountRepo struct {
	mu            sync.Mutex
	accounts      map[string]*domain.ServiceAccount
	keys          map[string]*domain.ServiceAccountKey
	keyBySecret   map[string]string
	keysByAccount map[string][]string
}

func newMemoryServiceAccountRepo() *memoryServiceAccountRepo {
	return &memoryServiceAccountRepo{
		accounts:      map[string]*domain.ServiceAccount{},
		keys:          map[string]*domain.ServiceAccountKey{},
		keyBySecret:   map[string]string{},
		keysByAccount: map[string][]string{},
	}
}

func (r *memoryServiceAccountRepo) CreateServiceAccount(ctx context.Context, account *domain.ServiceAccount) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.accounts[account.ID] = cloneServiceAccount(account)
	return nil
}

func (r *memoryServiceAccountRepo) ListServiceAccounts(ctx context.Context, clientID string) ([]*domain.ServiceAccount, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.ServiceAccount, 0)
	for _, account := range r.accounts {
		if account.ClientID == clientID {
			out = append(out, cloneServiceAccount(account))
		}
	}
	return out, nil
}

func (r *memoryServiceAccountRepo) GetServiceAccount(ctx context.Context, clientID, serviceAccountID string) (*domain.ServiceAccount, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	account := r.accounts[serviceAccountID]
	if account == nil || account.ClientID != clientID {
		return nil, domain.ErrNotFound
	}
	return cloneServiceAccount(account), nil
}

func (r *memoryServiceAccountRepo) UpdateServiceAccount(ctx context.Context, account *domain.ServiceAccount) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.accounts[account.ID] == nil || r.accounts[account.ID].ClientID != account.ClientID {
		return domain.ErrNotFound
	}
	r.accounts[account.ID] = cloneServiceAccount(account)
	return nil
}

func (r *memoryServiceAccountRepo) UpdateServiceAccountLastUsed(ctx context.Context, serviceAccountID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	account := r.accounts[serviceAccountID]
	if account == nil {
		return domain.ErrNotFound
	}
	now := time.Now().UTC()
	account.LastUsedAt = &now
	account.UpdatedAt = now
	return nil
}

func (r *memoryServiceAccountRepo) CreateServiceAccountKey(ctx context.Context, key *domain.ServiceAccountKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[key.ID] = cloneServiceAccountKey(key)
	r.keyBySecret[key.SecretHash] = key.ID
	r.keysByAccount[key.ServiceAccountID] = append(r.keysByAccount[key.ServiceAccountID], key.ID)
	return nil
}

func (r *memoryServiceAccountRepo) ListServiceAccountKeys(ctx context.Context, clientID, serviceAccountID string) ([]*domain.ServiceAccountKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.ServiceAccountKey, 0)
	for _, keyID := range r.keysByAccount[serviceAccountID] {
		key := r.keys[keyID]
		if key != nil && key.ClientID == clientID {
			out = append(out, cloneServiceAccountKey(key))
		}
	}
	return out, nil
}

func (r *memoryServiceAccountRepo) GetServiceAccountKey(ctx context.Context, clientID, serviceAccountID, keyID string) (*domain.ServiceAccountKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.keys[keyID]
	if key == nil || key.ClientID != clientID || key.ServiceAccountID != serviceAccountID {
		return nil, domain.ErrNotFound
	}
	return cloneServiceAccountKey(key), nil
}

func (r *memoryServiceAccountRepo) GetServiceAccountKeyBySecretHash(ctx context.Context, serviceAccountID, secretHash string) (*domain.ServiceAccountKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.keys[r.keyBySecret[secretHash]]
	if key == nil || key.ServiceAccountID != serviceAccountID {
		return nil, domain.ErrNotFound
	}
	return cloneServiceAccountKey(key), nil
}

func (r *memoryServiceAccountRepo) UpdateServiceAccountKeyLastUsed(ctx context.Context, keyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.keys[keyID]
	if key == nil {
		return domain.ErrNotFound
	}
	now := time.Now().UTC()
	key.LastUsedAt = &now
	key.UpdatedAt = now
	return nil
}

func (r *memoryServiceAccountRepo) RevokeServiceAccountKey(ctx context.Context, clientID, serviceAccountID, keyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := r.keys[keyID]
	if key == nil || key.ClientID != clientID || key.ServiceAccountID != serviceAccountID || key.Status == "revoked" {
		return domain.ErrNotFound
	}
	now := time.Now().UTC()
	key.Status = "revoked"
	key.RevokedAt = &now
	key.UpdatedAt = now
	return nil
}

type memoryEnterpriseSSORepo struct {
	mu          sync.Mutex
	connections map[string]*domain.EnterpriseSSOConnection
	identities  map[string]*domain.EnterpriseSSOIdentity
}

func newMemoryEnterpriseSSORepo() *memoryEnterpriseSSORepo {
	return &memoryEnterpriseSSORepo{
		connections: map[string]*domain.EnterpriseSSOConnection{},
		identities:  map[string]*domain.EnterpriseSSOIdentity{},
	}
}

func (r *memoryEnterpriseSSORepo) CreateConnection(ctx context.Context, connection *domain.EnterpriseSSOConnection) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connections[connection.ID] = cloneEnterpriseSSOConnection(connection)
	return nil
}

func (r *memoryEnterpriseSSORepo) ListConnections(ctx context.Context, clientID string) ([]*domain.EnterpriseSSOConnection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.EnterpriseSSOConnection, 0)
	for _, connection := range r.connections {
		if connection.ClientID == clientID {
			out = append(out, cloneEnterpriseSSOConnection(connection))
		}
	}
	return out, nil
}

func (r *memoryEnterpriseSSORepo) ListConnectionsForOrganization(ctx context.Context, clientID, organizationID string) ([]*domain.EnterpriseSSOConnection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.EnterpriseSSOConnection, 0)
	for _, connection := range r.connections {
		if connection.ClientID == clientID && connection.OrganizationID == organizationID {
			out = append(out, cloneEnterpriseSSOConnection(connection))
		}
	}
	return out, nil
}

func (r *memoryEnterpriseSSORepo) GetConnection(ctx context.Context, clientID, connectionID string) (*domain.EnterpriseSSOConnection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	connection := r.connections[connectionID]
	if connection == nil || connection.ClientID != clientID {
		return nil, domain.ErrNotFound
	}
	return cloneEnterpriseSSOConnection(connection), nil
}

func (r *memoryEnterpriseSSORepo) GetConnectionByID(ctx context.Context, connectionID string) (*domain.EnterpriseSSOConnection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	connection := r.connections[connectionID]
	if connection == nil {
		return nil, domain.ErrNotFound
	}
	return cloneEnterpriseSSOConnection(connection), nil
}

func (r *memoryEnterpriseSSORepo) GetConnectionBySlug(ctx context.Context, clientID, slug string) (*domain.EnterpriseSSOConnection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, connection := range r.connections {
		if connection.ClientID == clientID && connection.Slug == slug {
			return cloneEnterpriseSSOConnection(connection), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r *memoryEnterpriseSSORepo) GetActiveConnectionByDomain(ctx context.Context, clientID, domainName string) (*domain.EnterpriseSSOConnection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, connection := range r.connections {
		if connection.ClientID != clientID || connection.Status != domain.SSOConnectionStatusActive {
			continue
		}
		for _, allowed := range connection.Domains {
			if allowed == domainName {
				return cloneEnterpriseSSOConnection(connection), nil
			}
		}
	}
	return nil, domain.ErrNotFound
}

func (r *memoryEnterpriseSSORepo) UpdateConnection(ctx context.Context, connection *domain.EnterpriseSSOConnection) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing := r.connections[connection.ID]; existing == nil || existing.ClientID != connection.ClientID {
		return domain.ErrNotFound
	}
	r.connections[connection.ID] = cloneEnterpriseSSOConnection(connection)
	return nil
}

func (r *memoryEnterpriseSSORepo) DeactivateConnection(ctx context.Context, clientID, connectionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	connection := r.connections[connectionID]
	if connection == nil || connection.ClientID != clientID {
		return domain.ErrNotFound
	}
	connection.Status = domain.SSOConnectionStatusInactive
	connection.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *memoryEnterpriseSSORepo) MarkConnectionLogin(ctx context.Context, clientID, connectionID string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	connection := r.connections[connectionID]
	if connection == nil || connection.ClientID != clientID {
		return domain.ErrNotFound
	}
	connection.LastLoginAt = &at
	connection.UpdatedAt = at
	return nil
}

func (r *memoryEnterpriseSSORepo) MarkConnectionError(ctx context.Context, clientID, connectionID, message string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	connection := r.connections[connectionID]
	if connection == nil || connection.ClientID != clientID {
		return domain.ErrNotFound
	}
	connection.LastError = message
	connection.LastErrorAt = &at
	connection.UpdatedAt = at
	return nil
}

func (r *memoryEnterpriseSSORepo) FindIdentity(ctx context.Context, clientID, connectionID, externalID string) (*domain.EnterpriseSSOIdentity, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	identity := r.identities[ssoIdentityKey(connectionID, externalID)]
	if identity == nil || identity.ClientID != clientID {
		return nil, domain.ErrNotFound
	}
	return cloneEnterpriseSSOIdentity(identity), nil
}

func (r *memoryEnterpriseSSORepo) UpsertIdentity(ctx context.Context, identity *domain.EnterpriseSSOIdentity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := ssoIdentityKey(identity.ConnectionID, identity.ExternalID)
	existing := r.identities[key]
	cp := cloneEnterpriseSSOIdentity(identity)
	now := time.Now().UTC()
	if existing != nil {
		cp.ID = existing.ID
		cp.CreatedAt = existing.CreatedAt
	} else if cp.ID == "" {
		cp.ID = fmt.Sprintf("sso-identity-%d", len(r.identities)+1)
		cp.CreatedAt = now
	}
	cp.LastLoginAt = now
	cp.UpdatedAt = now
	r.identities[key] = cp
	return nil
}

type memorySCIMRepo struct {
	mu          sync.Mutex
	directories map[string]*domain.SCIMDirectory
	users       map[string]*domain.SCIMUser
	groups      map[string]*domain.SCIMGroup
}

func newMemorySCIMRepo() *memorySCIMRepo {
	return &memorySCIMRepo{
		directories: map[string]*domain.SCIMDirectory{},
		users:       map[string]*domain.SCIMUser{},
		groups:      map[string]*domain.SCIMGroup{},
	}
}

func (r *memorySCIMRepo) CreateDirectory(ctx context.Context, directory *domain.SCIMDirectory) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.directories[directory.ID] = cloneSCIMDirectory(directory)
	return nil
}

func (r *memorySCIMRepo) ListDirectories(ctx context.Context, clientID string) ([]*domain.SCIMDirectory, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*domain.SCIMDirectory{}
	for _, directory := range r.directories {
		if directory.ClientID == clientID {
			out = append(out, cloneSCIMDirectory(directory))
		}
	}
	return out, nil
}

func (r *memorySCIMRepo) ListDirectoriesForOrganization(ctx context.Context, clientID, organizationID string) ([]*domain.SCIMDirectory, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*domain.SCIMDirectory{}
	for _, directory := range r.directories {
		if directory.ClientID == clientID && directory.OrganizationID == organizationID {
			out = append(out, cloneSCIMDirectory(directory))
		}
	}
	return out, nil
}

func (r *memorySCIMRepo) GetDirectory(ctx context.Context, clientID, directoryID string) (*domain.SCIMDirectory, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	directory := r.directories[directoryID]
	if directory == nil || directory.ClientID != clientID {
		return nil, domain.ErrNotFound
	}
	return cloneSCIMDirectory(directory), nil
}

func (r *memorySCIMRepo) GetDirectoryByID(ctx context.Context, directoryID string) (*domain.SCIMDirectory, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	directory := r.directories[directoryID]
	if directory == nil {
		return nil, domain.ErrNotFound
	}
	return cloneSCIMDirectory(directory), nil
}

func (r *memorySCIMRepo) GetDirectoryByTokenHash(ctx context.Context, tokenHash string) (*domain.SCIMDirectory, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, directory := range r.directories {
		if directory.TokenHash == tokenHash {
			return cloneSCIMDirectory(directory), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r *memorySCIMRepo) UpdateDirectory(ctx context.Context, directory *domain.SCIMDirectory) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.directories[directory.ID] == nil || r.directories[directory.ID].ClientID != directory.ClientID {
		return domain.ErrNotFound
	}
	r.directories[directory.ID] = cloneSCIMDirectory(directory)
	return nil
}

func (r *memorySCIMRepo) MarkDirectorySync(ctx context.Context, clientID, directoryID string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	directory := r.directories[directoryID]
	if directory == nil || directory.ClientID != clientID {
		return domain.ErrNotFound
	}
	directory.LastSyncAt = &at
	directory.UpdatedAt = at
	return nil
}

func (r *memorySCIMRepo) MarkDirectoryError(ctx context.Context, clientID, directoryID, message string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	directory := r.directories[directoryID]
	if directory == nil || directory.ClientID != clientID {
		return domain.ErrNotFound
	}
	directory.LastError = message
	directory.LastErrorAt = &at
	directory.UpdatedAt = at
	return nil
}

func (r *memorySCIMRepo) UpsertUser(ctx context.Context, user *domain.SCIMUser) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := scimUserKey(user.DirectoryID, user.ID)
	r.users[key] = cloneSCIMUser(user)
	return nil
}

func (r *memorySCIMRepo) ListUsers(ctx context.Context, clientID, directoryID string) ([]*domain.SCIMUser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*domain.SCIMUser{}
	for _, user := range r.users {
		if user.ClientID == clientID && user.DirectoryID == directoryID {
			out = append(out, cloneSCIMUser(user))
		}
	}
	return out, nil
}

func (r *memorySCIMRepo) GetUser(ctx context.Context, clientID, directoryID, scimUserID string) (*domain.SCIMUser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	user := r.users[scimUserKey(directoryID, scimUserID)]
	if user == nil || user.ClientID != clientID {
		return nil, domain.ErrNotFound
	}
	return cloneSCIMUser(user), nil
}

func (r *memorySCIMRepo) GetUserByExternalID(ctx context.Context, clientID, directoryID, externalID string) (*domain.SCIMUser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, user := range r.users {
		if user.ClientID == clientID && user.DirectoryID == directoryID && user.ExternalID == externalID {
			return cloneSCIMUser(user), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r *memorySCIMRepo) DeleteUser(ctx context.Context, clientID, directoryID, scimUserID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := scimUserKey(directoryID, scimUserID)
	user := r.users[key]
	if user == nil || user.ClientID != clientID {
		return domain.ErrNotFound
	}
	delete(r.users, key)
	return nil
}

func (r *memorySCIMRepo) UpsertGroup(ctx context.Context, group *domain.SCIMGroup) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.groups[scimGroupKey(group.DirectoryID, group.ID)] = cloneSCIMGroup(group)
	return nil
}

func (r *memorySCIMRepo) ListGroups(ctx context.Context, clientID, directoryID string) ([]*domain.SCIMGroup, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []*domain.SCIMGroup{}
	for _, group := range r.groups {
		if group.ClientID == clientID && group.DirectoryID == directoryID {
			out = append(out, cloneSCIMGroup(group))
		}
	}
	return out, nil
}

func (r *memorySCIMRepo) GetGroup(ctx context.Context, clientID, directoryID, scimGroupID string) (*domain.SCIMGroup, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	group := r.groups[scimGroupKey(directoryID, scimGroupID)]
	if group == nil || group.ClientID != clientID {
		return nil, domain.ErrNotFound
	}
	return cloneSCIMGroup(group), nil
}

func (r *memorySCIMRepo) GetGroupByExternalID(ctx context.Context, clientID, directoryID, externalID string) (*domain.SCIMGroup, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, group := range r.groups {
		if group.ClientID == clientID && group.DirectoryID == directoryID && group.ExternalID == externalID {
			return cloneSCIMGroup(group), nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r *memorySCIMRepo) DeleteGroup(ctx context.Context, clientID, directoryID, scimGroupID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := scimGroupKey(directoryID, scimGroupID)
	group := r.groups[key]
	if group == nil || group.ClientID != clientID {
		return domain.ErrNotFound
	}
	delete(r.groups, key)
	return nil
}

type memoryWebAuthnRepo struct {
	mu               sync.Mutex
	byUser           map[string][]webauthn.Credential
	domainByUser     map[string][]domain.WebAuthnCredential
	credentialToUser map[string]string
}

func newMemoryWebAuthnRepo() *memoryWebAuthnRepo {
	return &memoryWebAuthnRepo{
		byUser:           map[string][]webauthn.Credential{},
		domainByUser:     map[string][]domain.WebAuthnCredential{},
		credentialToUser: map[string]string{},
	}
}

func (r *memoryWebAuthnRepo) Save(ctx context.Context, userID string, cred *webauthn.Credential, friendlyName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byUser[userID] = append(r.byUser[userID], *cred)
	id := fmt.Sprintf("passkey-%d", len(r.domainByUser[userID])+1)
	r.domainByUser[userID] = append(r.domainByUser[userID], domain.WebAuthnCredential{
		ID:           id,
		UserID:       userID,
		CredentialID: cred.ID,
		FriendlyName: friendlyName,
		SignCount:    cred.Authenticator.SignCount,
		CreatedAt:    time.Now().UTC(),
	})
	r.credentialToUser[string(cred.ID)] = userID
	return nil
}

func (r *memoryWebAuthnRepo) GetByUser(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	creds := append([]webauthn.Credential(nil), r.byUser[userID]...)
	return creds, nil
}

func (r *memoryWebAuthnRepo) UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	return nil
}

func (r *memoryWebAuthnRepo) ListByUser(ctx context.Context, userID string) ([]domain.WebAuthnCredential, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	creds := append([]domain.WebAuthnCredential(nil), r.domainByUser[userID]...)
	return creds, nil
}

func (r *memoryWebAuthnRepo) GetUserIDByCredentialID(ctx context.Context, credentialID []byte) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	userID := r.credentialToUser[string(credentialID)]
	if userID == "" {
		return "", domain.ErrNotFound
	}
	return userID, nil
}

func (r *memoryWebAuthnRepo) DeleteByID(ctx context.Context, id, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	creds := r.domainByUser[userID]
	for idx, cred := range creds {
		if cred.ID == id {
			r.domainByUser[userID] = append(creds[:idx], creds[idx+1:]...)
			return nil
		}
	}
	return domain.ErrNotFound
}

func cloneClient(client *domain.Client) *domain.Client {
	if client == nil {
		return nil
	}
	cp := *client
	cp.AllowedOrigins = append([]string(nil), client.AllowedOrigins...)
	cp.Settings = map[string]interface{}{}
	for key, value := range client.Settings {
		cp.Settings[key] = value
	}
	return &cp
}

func cloneUser(user *domain.User) *domain.User {
	if user == nil {
		return nil
	}
	cp := *user
	if user.PasswordHash != nil {
		v := *user.PasswordHash
		cp.PasswordHash = &v
	}
	if user.TOTPSecret != nil {
		v := *user.TOTPSecret
		cp.TOTPSecret = &v
	}
	if user.LastLoginAt != nil {
		v := *user.LastLoginAt
		cp.LastLoginAt = &v
	}
	return &cp
}

func cloneUserDevice(device *domain.UserDevice) *domain.UserDevice {
	if device == nil {
		return nil
	}
	cp := *device
	if device.TrustExpiresAt != nil {
		v := *device.TrustExpiresAt
		cp.TrustExpiresAt = &v
	}
	cp.Metadata = cloneMap(device.Metadata)
	return &cp
}

func cloneMap(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return map[string]interface{}{}
	}
	out := make(map[string]interface{}, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneOrganization(org *domain.Organization) *domain.Organization {
	if org == nil {
		return nil
	}
	cp := *org
	if org.CreatedByUserID != nil {
		v := *org.CreatedByUserID
		cp.CreatedByUserID = &v
	}
	cp.Metadata = map[string]interface{}{}
	for key, value := range org.Metadata {
		cp.Metadata[key] = value
	}
	return &cp
}

func cloneOrganizationMembership(membership *domain.OrganizationMembership) *domain.OrganizationMembership {
	if membership == nil {
		return nil
	}
	cp := *membership
	cp.Permissions = append([]string(nil), membership.Permissions...)
	return &cp
}

func cloneOrganizationInvitation(invitation *domain.OrganizationInvitation) *domain.OrganizationInvitation {
	if invitation == nil {
		return nil
	}
	cp := *invitation
	cp.Permissions = append([]string(nil), invitation.Permissions...)
	if invitation.InvitedByUserID != nil {
		v := *invitation.InvitedByUserID
		cp.InvitedByUserID = &v
	}
	if invitation.AcceptedAt != nil {
		v := *invitation.AcceptedAt
		cp.AcceptedAt = &v
	}
	if invitation.RevokedAt != nil {
		v := *invitation.RevokedAt
		cp.RevokedAt = &v
	}
	return &cp
}

func cloneAuthorizationPolicy(policy *domain.OrganizationAuthorizationPolicy) *domain.OrganizationAuthorizationPolicy {
	if policy == nil {
		return nil
	}
	cp := *policy
	cp.Resources = append([]domain.AuthorizationResource(nil), policy.Resources...)
	for i := range cp.Resources {
		cp.Resources[i].Actions = append([]domain.AuthorizationAction(nil), policy.Resources[i].Actions...)
	}
	cp.Permissions = append([]domain.AuthorizationPermission(nil), policy.Permissions...)
	cp.Roles = append([]domain.AuthorizationRoleTemplate(nil), policy.Roles...)
	for i := range cp.Roles {
		cp.Roles[i].Permissions = append([]string(nil), policy.Roles[i].Permissions...)
	}
	return &cp
}

func cloneGroupMapping(mapping *domain.OrganizationGroupMapping) *domain.OrganizationGroupMapping {
	if mapping == nil {
		return nil
	}
	cp := *mapping
	cp.Permissions = append([]string(nil), mapping.Permissions...)
	return &cp
}

func cloneServiceAccount(account *domain.ServiceAccount) *domain.ServiceAccount {
	if account == nil {
		return nil
	}
	cp := *account
	cp.Scopes = append([]string(nil), account.Scopes...)
	if account.LastUsedAt != nil {
		v := *account.LastUsedAt
		cp.LastUsedAt = &v
	}
	return &cp
}

func cloneServiceAccountKey(key *domain.ServiceAccountKey) *domain.ServiceAccountKey {
	if key == nil {
		return nil
	}
	cp := *key
	cp.Scopes = append([]string(nil), key.Scopes...)
	if key.LastUsedAt != nil {
		v := *key.LastUsedAt
		cp.LastUsedAt = &v
	}
	if key.ExpiresAt != nil {
		v := *key.ExpiresAt
		cp.ExpiresAt = &v
	}
	if key.RevokedAt != nil {
		v := *key.RevokedAt
		cp.RevokedAt = &v
	}
	return &cp
}

func cloneEnterpriseSSOConnection(connection *domain.EnterpriseSSOConnection) *domain.EnterpriseSSOConnection {
	if connection == nil {
		return nil
	}
	cp := *connection
	cp.Domains = append([]string(nil), connection.Domains...)
	cp.OIDC.Scopes = append([]string(nil), connection.OIDC.Scopes...)
	cp.AttributeMapping = map[string]string{}
	for key, value := range connection.AttributeMapping {
		cp.AttributeMapping[key] = value
	}
	return &cp
}

func cloneEnterpriseSSOIdentity(identity *domain.EnterpriseSSOIdentity) *domain.EnterpriseSSOIdentity {
	if identity == nil {
		return nil
	}
	cp := *identity
	cp.RawProfile = append([]byte(nil), identity.RawProfile...)
	return &cp
}

func ssoIdentityKey(connectionID, externalID string) string {
	return connectionID + "|" + externalID
}

func cloneSCIMDirectory(directory *domain.SCIMDirectory) *domain.SCIMDirectory {
	if directory == nil {
		return nil
	}
	cp := *directory
	cp.Domains = append([]string(nil), directory.Domains...)
	return &cp
}

func cloneSCIMUser(user *domain.SCIMUser) *domain.SCIMUser {
	if user == nil {
		return nil
	}
	cp := *user
	cp.RawResource = append([]byte(nil), user.RawResource...)
	return &cp
}

func cloneSCIMGroup(group *domain.SCIMGroup) *domain.SCIMGroup {
	if group == nil {
		return nil
	}
	cp := *group
	cp.Members = append([]string(nil), group.Members...)
	cp.RawResource = append([]byte(nil), group.RawResource...)
	return &cp
}

func scimUserKey(directoryID, userID string) string {
	return directoryID + "|user|" + userID
}

func scimGroupKey(directoryID, groupID string) string {
	return directoryID + "|group|" + groupID
}

func membershipKey(organizationID, userID string) string {
	return organizationID + "|" + userID
}

func hashE2EKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}
