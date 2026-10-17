package application

import (
	"encoding/base64"
	"errors"

	"github.com/Ayush10/authentication-service/internal/domain"
)

var ErrInvalidAppOAuthBinding = errors.New("invalid app OAuth binding")

// AppOAuthOptions opts one Google transaction into browser-held S256 binding
// and provider-subject identity. Empty options preserve the legacy contract.
type AppOAuthOptions struct {
	CodeChallenge       string
	CodeChallengeMethod string
	IdentityPolicy      string
}

func (o AppOAuthOptions) Validate(provider string) error {
	if o == (AppOAuthOptions{}) {
		return nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(o.CodeChallenge)
	if provider != "google" || o.CodeChallengeMethod != "S256" || o.IdentityPolicy != "provider_subject" ||
		err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != o.CodeChallenge {
		return ErrInvalidAppOAuthBinding
	}
	return nil
}

type OAuthCallbackResult struct {
	Client           *domain.Client
	AccessToken      string
	RefreshToken     string
	SessionMode      string
	AppCodeChallenge string
	IdentityPolicy   string
	Provider         string
	ProviderSubject  string
}
