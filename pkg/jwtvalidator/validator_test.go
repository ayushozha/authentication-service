package jwtvalidator

import (
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestValidateEnforcesClaims(t *testing.T) {
	token := signedTestToken(t, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			Issuer:    "https://auth.example.com",
			Audience:  jwt.ClaimStrings{"api://billing"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		ClientID:                "client-1",
		TokenUse:                "access",
		Scope:                   "invoices:read",
		Scopes:                  []string{"reports:*"},
		OrganizationRole:        "member",
		OrganizationPermissions: []string{"billing:write"},
	})

	validator := New(Config{
		Secret:                          "secret",
		Issuer:                          "https://auth.example.com",
		Audience:                        []string{"api://billing"},
		ClientID:                        "client-1",
		TokenUse:                        "access",
		RequiredScopes:                  []string{"invoices:read", "reports:export"},
		RequiredOrganizationPermissions: []string{"billing:write"},
	})

	claims, err := validator.Validate(token)
	if err != nil {
		t.Fatalf("validate token: %v", err)
	}
	if claims.UserID() != "user-1" {
		t.Fatalf("unexpected subject %q", claims.UserID())
	}
}

func TestValidateRejectsMissingScope(t *testing.T) {
	token := signedTestToken(t, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		ClientID: "client-1",
		Scope:    "profile:read",
	})

	validator := New(Config{
		Secret:         "secret",
		ClientID:       "client-1",
		RequiredScopes: []string{"profile:write"},
	})

	if _, err := validator.Validate(token); err == nil {
		t.Fatal("expected missing scope error")
	}
}

func TestWebhookSignatureVerification(t *testing.T) {
	timestamp := time.Now().Format("20060102150405")
	if VerifyWebhookSignature("secret", timestamp, "bad", []byte(`{"ok":true}`), time.Minute) {
		t.Fatal("bad signature verified")
	}

	unixTimestamp := strconv.FormatInt(time.Now().Unix(), 10)
	payload := []byte(`{"ok":true}`)
	signature := SignWebhookPayload("secret", unixTimestamp, payload)
	if !VerifyWebhookSignature("secret", unixTimestamp, signature, payload, time.Minute) {
		t.Fatal("valid signature did not verify")
	}
}

func signedTestToken(t *testing.T, claims Claims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}
