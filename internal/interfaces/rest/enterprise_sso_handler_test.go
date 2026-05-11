package rest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Ayush10/authentication-service/internal/domain"
)

func TestEnterpriseSSOErrorsUseCanonicalAuthEnvelope(t *testing.T) {
	handler := NewEnterpriseSSOHandler(nil, &HandlerConfig{BaseURL: "https://auth.example.com"})
	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso?domain=acme.com", nil)
	req.Header.Set("X-Request-ID", "req-sso-user@example.com-123456")

	rec := httptest.NewRecorder()
	handler.writeSSOError(rec, req, domain.ErrInvalidSSOConnection)

	assertStatus(t, rec, http.StatusBadRequest)
	var payload errorPayload
	decodeBody(t, rec, &payload)
	if payload.Code != "sso_failed" || payload.AuthCode != "AUTH_SSO_FAILED" {
		t.Fatalf("expected canonical SSO failure, got %+v", payload)
	}
	if payload.UserMessage != "We could not complete single sign-on. Try again." || !payload.Retryable {
		t.Fatalf("expected retryable user-safe SSO message, got %+v", payload)
	}
	if payload.Message != "Could not complete SSO." {
		t.Fatalf("expected generic legacy message, got %+v", payload)
	}
	if payload.RequestID != "[REDACTED_EMAIL]-[REDACTED_CODE]" {
		t.Fatalf("request id should be redacted, got %+v", payload)
	}

	rec = httptest.NewRecorder()
	handler.writeSSOError(rec, req, domain.ErrRedisRequired)
	assertStatus(t, rec, http.StatusServiceUnavailable)
	decodeBody(t, rec, &payload)
	if payload.Code != "redis_required" || payload.AuthCode != "AUTH_SERVICE_UNAVAILABLE" || !payload.Retryable {
		t.Fatalf("expected service-unavailable Redis SSO error, got %+v", payload)
	}

	rec = httptest.NewRecorder()
	handler.writeSSOError(rec, req, domain.ErrAccountSuspended)
	assertStatus(t, rec, http.StatusForbidden)
	decodeBody(t, rec, &payload)
	if payload.Code != "account_suspended" || payload.AuthCode != "AUTH_ACCOUNT_DISABLED" || payload.Retryable {
		t.Fatalf("expected account-disabled SSO error, got %+v", payload)
	}
}

func TestEnterpriseSSOCallbackRedirectsCanonicalAuthErrors(t *testing.T) {
	handler := NewEnterpriseSSOHandler(nil, &HandlerConfig{BaseURL: "https://auth.example.com"})
	req := httptest.NewRequest(http.MethodGet, "https://auth.example.com/api/auth/sso/callback/", nil)
	rec := httptest.NewRecorder()

	handler.handleCallback(rec, req)

	assertStatus(t, rec, http.StatusFound)
	location := rec.Header().Get("Location")
	if location != "https://auth.example.com/login.html?error=AUTH_SSO_FAILED" {
		t.Fatalf("expected canonical SSO redirect, got %q", location)
	}
	if strings.Contains(location, "missing_sso_connection") || strings.Contains(location, "invalid enterprise sso") {
		t.Fatalf("redirect leaked raw SSO error: %q", location)
	}
}
