package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Ayush10/authentication-service/internal/domain"
)

func TestEnterpriseOnboardingAuditLimitUsesCanonicalError(t *testing.T) {
	handler := &EnterpriseOnboardingHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/enterprise-onboarding/organizations/org-1/audit-events?limit=abc", nil)
	rec := httptest.NewRecorder()

	handler.handleAuditEvents(rec, req, context.Background(), "client-1", "org-1", "user-1", []string{"org-1", "audit-events"})

	assertStatus(t, rec, http.StatusBadRequest)
	assertAuthError(t, rec, "invalid_request", "AUTH_INVALID_REQUEST", false)
}

func TestEnterpriseOnboardingErrorsUseCanonicalEnvelope(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/auth/enterprise-onboarding/organizations/missing", nil)
	rec := httptest.NewRecorder()

	writeEnterpriseOnboardingError(rec, req, domain.ErrNotFound)

	assertStatus(t, rec, http.StatusNotFound)
	assertAuthError(t, rec, "not_found", "AUTH_INVALID_REQUEST", false)
}
