package jwtvalidator

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Config holds the configuration for the JWT validator.
type Config struct {
	Secret string // The JWT signing secret (per-client, from the auth service)
}

// Validator validates JWTs issued by the authentication service.
type Validator struct {
	secret []byte
}

// New creates a new JWT validator.
func New(cfg Config) *Validator {
	return &Validator{secret: []byte(cfg.Secret)}
}

// Validate parses and validates a JWT token string.
func (v *Validator) Validate(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.secret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

// ValidateFromRequest extracts and validates a JWT from the Authorization header.
func (v *Validator) ValidateFromRequest(r *http.Request) (*Claims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return nil, fmt.Errorf("invalid authorization format")
	}

	return v.Validate(parts[1])
}

// Middleware returns an HTTP middleware that validates JWTs and rejects unauthorized requests.
func (v *Validator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := v.ValidateFromRequest(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"error":"unauthorized: %s"}`, err.Error())
			return
		}

		// Store claims in request context
		ctx := r.Context()
		ctx = WithClaims(ctx, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
