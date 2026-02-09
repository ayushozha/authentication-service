package rest

import (
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
