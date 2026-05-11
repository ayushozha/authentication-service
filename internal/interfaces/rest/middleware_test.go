package rest

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ayush10/authentication-service/internal/domain"
)

func TestResolveAllowedOrigin(t *testing.T) {
	client := &domain.Client{
		ID:             "client-1",
		AllowedOrigins: []string{"https://a.example.com", "https://b.example.com"},
	}

	origin, creds, ok := resolveAllowedOrigin("https://b.example.com", "*", client)
	if !ok || origin != "https://b.example.com" || !creds {
		t.Fatalf("expected client origin to be allowed")
	}

	_, _, ok = resolveAllowedOrigin("https://evil.example.com", "*", client)
	if ok {
		t.Fatalf("expected disallowed origin")
	}

	origin, creds, ok = resolveAllowedOrigin("https://any.example.com", "*", nil)
	if !ok || origin != "*" || creds {
		t.Fatalf("expected wildcard without credentials")
	}

	origin, creds, ok = resolveAllowedOrigin("https://app.example.com", "https://app.example.com,https://admin.example.com", nil)
	if !ok || origin != "https://app.example.com" || !creds {
		t.Fatalf("expected configured origin with credentials")
	}
}

func TestTokenSessionMode(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/auth/login?session_mode=token", nil)
	if !isTokenSessionMode(req, "") {
		t.Fatalf("expected token mode from query")
	}

	req = httptest.NewRequest("POST", "/api/auth/login", nil)
	if !isTokenSessionMode(req, "token") {
		t.Fatalf("expected token mode from payload")
	}

	if isTokenSessionMode(req, "cookie") {
		t.Fatalf("unexpected token mode")
	}
}

func TestWriteErrorIncludesCanonicalAuthMetadata(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	req.Header.Set("X-Request-ID", "req-user@example.com-123456")
	rec := httptest.NewRecorder()

	writeError(rec, req, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password.")

	assertStatus(t, rec, http.StatusUnauthorized)
	var payload errorPayload
	decodeBody(t, rec, &payload)
	if payload.Code != "invalid_credentials" || payload.AuthCode != "AUTH_INVALID_CREDENTIALS" {
		t.Fatalf("unexpected payload codes: %+v", payload)
	}
	if payload.UserMessage != "Invalid email or password." || payload.Retryable {
		t.Fatalf("unexpected normalized payload: %+v", payload)
	}
	if payload.RequestID != "[REDACTED_EMAIL]-[REDACTED_CODE]" {
		t.Fatalf("request id should be redacted in error payload: %+v", payload)
	}
}

func TestWriteErrorMarksRateLimitRetryable(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", nil)
	rec := httptest.NewRecorder()

	writeError(rec, req, http.StatusTooManyRequests, "rate_limited", "too many requests, try again later")

	assertStatus(t, rec, http.StatusTooManyRequests)
	var payload errorPayload
	decodeBody(t, rec, &payload)
	if payload.AuthCode != "AUTH_RATE_LIMITED" || !payload.Retryable {
		t.Fatalf("expected retryable rate-limit payload, got %+v", payload)
	}
}

func TestWriteErrorLogsStructuredRedactedAuthEvent(t *testing.T) {
	var buf bytes.Buffer
	oldOutput := log.Writer()
	oldFlags := log.Flags()
	oldPrefix := log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(oldOutput)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
	}()

	req := httptest.NewRequest(http.MethodPost, "/api/auth/oauth/google/callback", nil)
	req.Header.Set("X-Request-ID", "req-user@example.com-123456")
	req.Header.Set("User-Agent", "Mozilla/5.0 secret@example.com 654321")
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature")
	rec := httptest.NewRecorder()

	writeError(rec, req, http.StatusBadRequest, "invalid_state", "OAuth state mismatch.")

	logLine := strings.TrimSpace(buf.String())
	if logLine == "" {
		t.Fatal("expected auth error log line")
	}
	for _, secret := range []string{
		"user@example.com",
		"secret@example.com",
		"123456",
		"654321",
		"Mozilla/5.0",
		"eyJhbGciOiJIUzI1NiJ9",
	} {
		if strings.Contains(logLine, secret) {
			t.Fatalf("auth error log leaked %q: %s", secret, logLine)
		}
	}

	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(logLine), &entry); err != nil {
		t.Fatalf("auth error log should be JSON: %v\n%s", err, logLine)
	}
	if entry["event"] != "auth.error" ||
		entry["platform"] != "auth-service" ||
		entry["app"] != "auth-service" ||
		entry["component"] != "/api/auth/oauth/google/callback" ||
		entry["operation"] != "oauth" ||
		entry["code"] != "AUTH_OAUTH_STATE_MISMATCH" ||
		entry["provider_code"] != "invalid_state" ||
		entry["method"] != http.MethodPost {
		t.Fatalf("unexpected structured auth log fields: %+v", entry)
	}
	if entry["status"] != float64(http.StatusBadRequest) || entry["retryable"] != false {
		t.Fatalf("unexpected status/retryable fields: %+v", entry)
	}
	if entry["request_id"] != "[REDACTED_EMAIL]-[REDACTED_CODE]" {
		t.Fatalf("request id should be redacted in auth log: %+v", entry)
	}
	device, ok := entry["device"].(map[string]interface{})
	if !ok || device["user_agent"] != "[REDACTED_USER_AGENT]" {
		t.Fatalf("user agent should be structurally redacted in auth log: %+v", entry)
	}
}

func TestAuthOperationForPathCoversAuthSurfaces(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/auth/login", "login"},
		{"/api/auth/signup", "signup"},
		{"/api/auth/refresh", "refresh"},
		{"/api/auth/logout", "logout"},
		{"/api/auth/change-password", "password_change"},
		{"/api/auth/forgot-password", "password_reset"},
		{"/api/auth/reset-password", "password_reset"},
		{"/api/auth/verify-email", "email_verification"},
		{"/api/auth/resend-verification", "email_verification"},
		{"/api/auth/magic-link/send", "magic_link"},
		{"/api/auth/redirect/exchange", "redirect_exchange"},
		{"/api/auth/oauth/google/callback", "oauth"},
		{"/api/auth/sso/callback/connection-id", "sso"},
		{"/api/auth/totp/verify", "mfa"},
		{"/api/auth/recovery-codes/verify", "mfa"},
		{"/api/auth/step-up/verify", "mfa"},
		{"/api/auth/passkey/login/finish", "passkey"},
		{"/api/auth/me", "session"},
		{"/api/auth/sessions/session-id", "session"},
		{"/api/auth/devices/device-id", "device"},
		{"/api/auth/ui/config", "ui_config"},
		{"/api/auth/organizations/org-id/invitations", "organization"},
		{"/api/auth/organization-invitations/accept", "organization"},
		{"/api/auth/enterprise-onboarding/organizations/org-id/audit-events", "enterprise_onboarding"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodPost, tt.path, nil)
		if got := authOperationForPath(req); got != tt.want {
			t.Fatalf("authOperationForPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}
