package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteAdaptiveActionDecisionNilUsesCanonicalError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/organizations/org-1/token", nil)
	rec := httptest.NewRecorder()

	writeAdaptiveActionDecision(rec, req, nil)

	assertStatus(t, rec, http.StatusForbidden)
	assertAuthError(t, rec, "forbidden", "AUTH_INVALID_REQUEST", false)
}
