package jwtvalidator

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config holds the configuration for the JWT validator.
type Config struct {
	Secret string // Optional HS256 secret.

	// Optional JWKS settings for RS256 validation.
	JWKSURL         string
	ClientID        string
	RefreshInterval time.Duration
	HTTPClient      *http.Client
}

// Validator validates JWTs issued by the authentication service.
type Validator struct {
	secret []byte

	jwksURL         string
	clientID        string
	refreshInterval time.Duration
	httpClient      *http.Client

	mu        sync.RWMutex
	publicKey map[string]*rsa.PublicKey
	lastFetch time.Time
}

// New creates a new JWT validator.
func New(cfg Config) *Validator {
	interval := cfg.RefreshInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}

	return &Validator{
		secret:          []byte(cfg.Secret),
		jwksURL:         strings.TrimSpace(cfg.JWKSURL),
		clientID:        strings.TrimSpace(cfg.ClientID),
		refreshInterval: interval,
		httpClient:      httpClient,
		publicKey:       map[string]*rsa.PublicKey{},
	}
}

// Validate parses and validates a JWT token string.
func (v *Validator) Validate(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		switch t.Method.Alg() {
		case jwt.SigningMethodHS256.Alg():
			if len(v.secret) == 0 {
				return nil, fmt.Errorf("no HS256 secret configured")
			}
			return v.secret, nil
		case jwt.SigningMethodRS256.Alg():
			if v.jwksURL == "" {
				return nil, fmt.Errorf("no JWKS URL configured")
			}
			kid, _ := t.Header["kid"].(string)
			if strings.TrimSpace(kid) == "" {
				return nil, fmt.Errorf("missing key id")
			}
			return v.lookupPublicKey(kid)
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}
	if v.clientID != "" && claims.ClientID != v.clientID {
		return nil, fmt.Errorf("token client mismatch")
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

		ctx := WithClaims(r.Context(), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (v *Validator) lookupPublicKey(kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key := v.publicKey[kid]
	needsRefresh := key == nil || time.Since(v.lastFetch) > v.refreshInterval
	v.mu.RUnlock()

	if needsRefresh {
		if err := v.refreshJWKS(); err != nil {
			return nil, err
		}
		v.mu.RLock()
		key = v.publicKey[kid]
		v.mu.RUnlock()
	}
	if key == nil {
		return nil, fmt.Errorf("signing key not found")
	}
	return key, nil
}

func (v *Validator) refreshJWKS() error {
	req, err := http.NewRequest(http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("jwks request failed with status %d", resp.StatusCode)
	}

	var payload struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}

	nextKeys := make(map[string]*rsa.PublicKey, len(payload.Keys))
	for _, key := range payload.Keys {
		if key.Kty != "RSA" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return err
		}
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		if e == 0 {
			return fmt.Errorf("invalid jwks exponent")
		}
		nextKeys[key.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: e,
		}
	}

	v.mu.Lock()
	v.publicKey = nextKeys
	v.lastFetch = time.Now()
	v.mu.Unlock()
	return nil
}
