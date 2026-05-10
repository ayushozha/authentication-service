package authservice

import (
	"net/http"

	"github.com/Ayush10/authentication-service/pkg/jwtvalidator"
)

type Claims = jwtvalidator.Claims
type JwtVerifier = jwtvalidator.Validator
type JwtVerifierConfig = jwtvalidator.Config

func NewJwtVerifier(cfg JwtVerifierConfig) *JwtVerifier {
	return jwtvalidator.New(cfg)
}

func VerifyWebhookSignature(secret, timestamp, signature string, payload []byte) bool {
	return jwtvalidator.VerifyWebhookSignature(secret, timestamp, signature, payload)
}

func ClaimsFromRequest(r *http.Request) *Claims {
	return jwtvalidator.GetClaims(r.Context())
}
