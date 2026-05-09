package rest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/pquerna/otp/totp"
	"golang.org/x/oauth2"
)

const (
	e2eAdminKey = "admin-e2e-key"
	e2eAPIKey   = "client-e2e-api-key"
	e2ePassword = "password123"
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
	mailer   *recordingMailer
	rl       *memoryRateLimiter
	oauth    *memoryOAuthRepo
	webauthn *memoryWebAuthnRepo

	client *domain.Client
	apiKey string
}

type e2eOptions struct {
	oauthProviders map[string]*application.OAuthProviderConfig
	cache          application.CacheClient
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
	audit := &memoryAuditRepo{}
	mailer := &recordingMailer{}
	rl := newMemoryRateLimiter()
	oauthRepo := newMemoryOAuthRepo()
	webauthnRepo := newMemoryWebAuthnRepo()

	clientSvc := application.NewClientService(clients)
	authSvc := application.NewAuthService(users, sessions, cache, audit, rl)
	verifySvc := application.NewEmailVerifyService(users, tokens, mailer)
	resetSvc := application.NewPasswordResetService(users, tokens, sessions, mailer)
	magicSvc := application.NewMagicLinkService(clients, users, sessions, cache, mailer, audit, rl)
	totpSvc := application.NewTOTPService(users, sessions, cache, audit)
	oauthSvc := application.NewOAuthService(users, clients, oauthRepo, sessions, cache, audit)
	auditSvc := application.NewAuditService(audit)
	passkeySvc, err := application.NewPasskeyService(users, webauthnRepo, sessions, cache, audit, "E2E Auth", "example.com", "https://example.com")
	if err != nil {
		t.Fatalf("new passkey service: %v", err)
	}

	verifySvc.WireSignupHook("https://auth.example.com")
	application.SetSigningKeyRepository(&signingKeyRepoRouteStub{})
	t.Cleanup(func() {
		application.OnSignup = nil
		application.SetSigningKeyRepository(nil)
	})

	cfg := &HandlerConfig{
		AllowOrigin:    "*",
		BaseURL:        "https://auth.example.com",
		BcryptCost:     10,
		AccessTTL:      15 * time.Minute,
		RefreshTTL:     24 * time.Hour,
		CookieSameSite: "lax",
	}
	router := NewRouter(
		authSvc, verifySvc, resetSvc, magicSvc, totpSvc,
		oauthSvc, passkeySvc, clientSvc, auditSvc,
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
		mailer:   mailer,
		rl:       rl,
		oauth:    oauthRepo,
		webauthn: webauthnRepo,
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

	challengeRec := env.request(t, http.MethodPost, "/api/auth/login", map[string]string{
		"email":        "bob@example.com",
		"password":     "resetpassword123",
		"session_mode": "token",
	}, env.apiHeaders())
	assertStatus(t, challengeRec, http.StatusOK)
	var challenge application.AuthResponse
	decodeBody(t, challengeRec, &challenge)
	if !challenge.Requires2FA || challenge.TwoFAToken == "" || len(challenge.TwoFAMethods) != 1 {
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
		"session_mode":     "token",
	}, env.apiHeaders())
	assertStatus(t, verifyTOTPRec, http.StatusOK)
	var twoFALogin application.AuthResponse
	decodeBody(t, verifyTOTPRec, &twoFALogin)
	if twoFALogin.AccessToken == "" || twoFALogin.RefreshToken == "" {
		t.Fatalf("2FA verify should issue tokens: %+v", twoFALogin)
	}

	disableCode, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	disableRec := env.request(t, http.MethodPost, "/api/auth/totp/disable", map[string]string{
		"code": disableCode,
	}, env.bearerHeaders(twoFALogin.AccessToken))
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

	badAuditLimitRec := env.request(t, http.MethodGet, "/api/admin/audit-events?limit=not-a-number", nil, map[string]string{"X-Admin-Key": e2eAdminKey})
	assertStatus(t, badAuditLimitRec, http.StatusBadRequest)
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
	if !strings.HasPrefix(callbackLocation, "https://auth.example.com/login.html?access_token=") {
		t.Fatalf("unexpected oauth callback redirect: %s", callbackLocation)
	}
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

	passkeyRegisterBeginRec := env.request(t, http.MethodPost, "/api/auth/passkey/register/begin", nil, env.bearerHeaders(user.AccessToken))
	assertStatus(t, passkeyRegisterBeginRec, http.StatusOK)

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
	expiresAt time.Time
	revoked   bool
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
	r.sessions[id] = &memorySession{
		id:        id,
		userID:    userID,
		clientID:  clientID,
		tokenHash: application.HashToken(rawToken),
		expiresAt: time.Now().Add(ttl),
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
	r.events = append(r.events, domain.AuditEvent{
		ID:        int64(len(r.events) + 1),
		ClientID:  clientID,
		UserID:    userID,
		EventType: eventType,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  metadata,
		CreatedAt: time.Now().UTC(),
	})
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
		cp := event
		if event.UserID != nil {
			userID := *event.UserID
			cp.UserID = &userID
		}
		cp.Metadata = map[string]interface{}{}
		for key, value := range event.Metadata {
			cp.Metadata[key] = value
		}
		events = append(events, &cp)
	}
	return events, nil
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

func hashE2EKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}
