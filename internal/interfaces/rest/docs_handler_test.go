package rest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDocsUIIncludesIntegrationShell(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rec := httptest.NewRecorder()

	DocsUIHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Build login, MFA, passkeys, OAuth, JWT validation, and audit trails",
		"Integration path",
		"Production login request",
		"data-url=\"/docs/openapi.yaml\"",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("docs UI missing %q", want)
		}
	}
}

func TestDocsSpecIncludesIntegrationGuide(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/docs/openapi.yaml", nil)
	rec := httptest.NewRecorder()

	DocsSpecHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"Integration Quickstart",
		"Recommended Integration Patterns",
		"Production Checklist",
		"x-codeSamples",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("docs spec missing %q", want)
		}
	}
}
