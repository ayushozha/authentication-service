package rest

import (
	"net/http"
	"testing"
)

// Signup errors used to be flattened into AUTH_UNKNOWN with a generic
// "Something went wrong. Try again." user message. These cases lock in the
// specific, user-actionable classification.
func TestSignupErrorClassification(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		code        string
		message     string
		wantAuth    string
		wantUserMsg string
	}{
		{
			name:        "duplicate email by code",
			status:      http.StatusConflict,
			code:        "duplicate_email",
			message:     "email already registered",
			wantAuth:    "AUTH_EMAIL_EXISTS",
			wantUserMsg: "That email is already registered. Try signing in instead.",
		},
		{
			name:        "compromised password surfaces reason",
			status:      http.StatusBadRequest,
			code:        "invalid_signup",
			message:     "password appears in a known compromised password list",
			wantAuth:    "AUTH_PASSWORD_REQUIREMENTS",
			wantUserMsg: "password appears in a known compromised password list",
		},
		{
			name:        "password unique chars surfaces reason",
			status:      http.StatusBadRequest,
			code:        "invalid_signup",
			message:     "password must contain at least 4 unique characters",
			wantAuth:    "AUTH_PASSWORD_REQUIREMENTS",
			wantUserMsg: "password must contain at least 4 unique characters",
		},
		{
			name:        "password contains name surfaces reason",
			status:      http.StatusBadRequest,
			code:        "invalid_signup",
			message:     "password must not contain your name",
			wantAuth:    "AUTH_PASSWORD_REQUIREMENTS",
			wantUserMsg: "password must not contain your name",
		},
		{
			name:        "blocked email domain",
			status:      http.StatusBadRequest,
			code:        "invalid_signup",
			message:     "email domain is not allowed",
			wantAuth:    "AUTH_EMAIL_DOMAIN_BLOCKED",
			wantUserMsg: "Sign-ups from that email domain aren't allowed.",
		},
		{
			name:        "internal error never leaks verbatim",
			status:      http.StatusBadRequest,
			code:        "invalid_signup",
			message:     "internal error",
			wantAuth:    "AUTH_SERVICE_UNAVAILABLE",
			wantUserMsg: "We could not sign you in right now. Try again later.",
		},
		{
			name:        "could not create account is treated as internal",
			status:      http.StatusBadRequest,
			code:        "invalid_signup",
			message:     "could not create account",
			wantAuth:    "AUTH_SERVICE_UNAVAILABLE",
			wantUserMsg: "We could not sign you in right now. Try again later.",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authCode, def := normalizeAuthError(tc.status, tc.code, tc.message)
			if authCode != tc.wantAuth {
				t.Fatalf("auth code: got %q want %q", authCode, tc.wantAuth)
			}
			userMsg := def.UserMessage
			if def.UseUpstreamMessage && tc.message != "" {
				userMsg = tc.message
			}
			if userMsg != tc.wantUserMsg {
				t.Fatalf("user message: got %q want %q", userMsg, tc.wantUserMsg)
			}
		})
	}
}
