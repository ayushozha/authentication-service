package application

import (
	"context"
	"testing"

	"github.com/Ayush10/authentication-service/internal/domain"
)

func TestVerifyBotTokenRequiresConfiguredVerifier(t *testing.T) {
	SetBotProtection(BotProtectionConfig{SignupRequired: true})
	defer SetBotProtection(BotProtectionConfig{})

	if err := verifyBotToken(context.Background(), true, "token", "203.0.113.10"); err != domain.ErrBotVerification {
		t.Fatalf("expected missing verifier to fail, got %v", err)
	}
}

func TestVerifyBotTokenUsesVerifierWhenRequired(t *testing.T) {
	verifier := &recordingBotVerifier{}
	SetBotProtection(BotProtectionConfig{SignupRequired: true, Verifier: verifier})
	defer SetBotProtection(BotProtectionConfig{})

	if err := verifyBotToken(context.Background(), true, "token", "203.0.113.10"); err != nil {
		t.Fatalf("expected verifier success, got %v", err)
	}
	if verifier.token != "token" || verifier.remoteIP != "203.0.113.10" {
		t.Fatalf("verifier saw wrong inputs: %+v", verifier)
	}
}

type recordingBotVerifier struct {
	token    string
	remoteIP string
}

func (v *recordingBotVerifier) Verify(ctx context.Context, token, remoteIP string) error {
	v.token = token
	v.remoteIP = remoteIP
	return nil
}
