package rest

import (
	"net/http"
	"net/http/httptest"
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

	writeError(rec, req, http.StatusUnauthorized, "invalid_credentials", "The email or password is incorrect.")

	assertStatus(t, rec, http.StatusUnauthorized)
	var payload errorPayload
	decodeBody(t, rec, &payload)
	if payload.Code != "invalid_credentials" || payload.AuthCode != "AUTH_INVALID_CREDENTIALS" {
		t.Fatalf("unexpected payload codes: %+v", payload)
	}
	if payload.UserMessage != "The email or password is incorrect." || payload.Retryable {
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
