package application

import (
	"testing"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/go-webauthn/webauthn/protocol"
)

func TestPasskeyAttestationPolicyFromClientSettings(t *testing.T) {
	client := &domain.Client{Settings: map[string]interface{}{
		"webauthn_attestation":                 "enterprise",
		"webauthn_require_attestation":         "true",
		"webauthn_allowed_attestation_formats": []interface{}{"packed", "tpm"},
	}}

	policy := passkeyAttestationPolicyForClient(client)
	if policy.Conveyance != protocol.PreferEnterpriseAttestation {
		t.Fatalf("unexpected conveyance: %s", policy.Conveyance)
	}
	if !policy.RequireAttestation {
		t.Fatal("expected attestation to be required")
	}
	if len(policy.AllowedFormats) != 2 || policy.AllowedFormats[0] != "packed" || policy.AllowedFormats[1] != "tpm" {
		t.Fatalf("unexpected allowed formats: %+v", policy.AllowedFormats)
	}
}

func TestValidatePasskeyAttestationPolicyRejectsNoneWhenRequired(t *testing.T) {
	policy := PasskeyAttestationPolicy{
		Conveyance:         protocol.PreferDirectAttestation,
		RequireAttestation: true,
		AllowedFormats:     []string{"packed"},
	}

	if err := validatePasskeyAttestationPolicy(policy, "none"); err != domain.ErrPasskeyAttestation {
		t.Fatalf("expected none attestation to be rejected, got %v", err)
	}
	if err := validatePasskeyAttestationPolicy(policy, "apple"); err != domain.ErrPasskeyAttestation {
		t.Fatalf("expected disallowed attestation format to be rejected, got %v", err)
	}
	if err := validatePasskeyAttestationPolicy(policy, "packed"); err != nil {
		t.Fatalf("expected allowed attestation format, got %v", err)
	}
}
