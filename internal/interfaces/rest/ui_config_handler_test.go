package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUIConfigMissingClientUsesCanonicalAuthEnvelope(t *testing.T) {
	handler := NewUIConfigHandler(&HandlerConfig{})
	req := httptest.NewRequest(http.MethodGet, "/api/auth/ui/config", nil)
	rec := httptest.NewRecorder()

	handler.config(rec, req)

	assertStatus(t, rec, http.StatusUnauthorized)
	var payload errorPayload
	decodeBody(t, rec, &payload)
	if payload.Code != "missing_client" || payload.AuthCode != "AUTH_SERVICE_UNAVAILABLE" {
		t.Fatalf("expected canonical missing-client payload, got %+v", payload)
	}
	if payload.UserMessage != "We could not sign you in right now. Try again later." || !payload.Retryable {
		t.Fatalf("expected retryable service-unavailable message, got %+v", payload)
	}
}
