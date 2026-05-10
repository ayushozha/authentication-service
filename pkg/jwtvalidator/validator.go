package jwtvalidator

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
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

	// Optional claim enforcement.
	Issuer                          string
	Audience                        []string
	TokenUse                        string
	RequiredScopes                  []string
	RequiredOrganizationPermissions []string
	ClockSkew                       time.Duration
}

// Validator validates JWTs issued by the authentication service.
type Validator struct {
	secret []byte

	jwksURL         string
	clientID        string
	refreshInterval time.Duration
	httpClient      *http.Client

	issuer                          string
	audience                        []string
	tokenUse                        string
	requiredScopes                  []string
	requiredOrganizationPermissions []string
	clockSkew                       time.Duration

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
	clockSkew := cfg.ClockSkew
	if clockSkew <= 0 {
		clockSkew = time.Minute
	}

	return &Validator{
		secret:                          []byte(cfg.Secret),
		jwksURL:                         strings.TrimSpace(cfg.JWKSURL),
		clientID:                        strings.TrimSpace(cfg.ClientID),
		refreshInterval:                 interval,
		httpClient:                      httpClient,
		issuer:                          strings.TrimSpace(cfg.Issuer),
		audience:                        trimStrings(cfg.Audience),
		tokenUse:                        strings.TrimSpace(cfg.TokenUse),
		requiredScopes:                  trimStrings(cfg.RequiredScopes),
		requiredOrganizationPermissions: trimStrings(cfg.RequiredOrganizationPermissions),
		clockSkew:                       clockSkew,
		publicKey:                       map[string]*rsa.PublicKey{},
	}
}

// Validate parses and validates a JWT token string.
func (v *Validator) Validate(tokenStr string) (*Claims, error) {
	parserOptions := []jwt.ParserOption{jwt.WithLeeway(v.clockSkew)}
	if v.issuer != "" {
		parserOptions = append(parserOptions, jwt.WithIssuer(v.issuer))
	}
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
	}, parserOptions...)
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
	if len(v.audience) > 0 && !audienceMatches(claims.Audience, v.audience) {
		return nil, fmt.Errorf("token audience mismatch")
	}
	if v.tokenUse != "" && claims.TokenUse != v.tokenUse {
		return nil, fmt.Errorf("token_use mismatch")
	}
	for _, required := range v.requiredScopes {
		if !claims.HasScope(required) {
			return nil, fmt.Errorf("missing required scope: %s", required)
		}
	}
	for _, required := range v.requiredOrganizationPermissions {
		if !claims.HasOrganizationPermission(required) {
			return nil, fmt.Errorf("missing required organization permission: %s", required)
		}
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

func (v *Validator) RequireOrganizationPermission(permission string, next http.Handler) http.Handler {
	return v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil || !claims.HasOrganizationPermission(permission) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"error":"forbidden"}`)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func (v *Validator) RequireAuthorization(resource, action string, next http.Handler) http.Handler {
	return v.RequireOrganizationPermission(PermissionFor(resource, action), next)
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

// SignWebhookPayload computes the AuthService webhook signature for a raw payload.
func SignWebhookPayload(secret, timestamp string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(payload)
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature verifies an AuthService webhook signature and timestamp.
func VerifyWebhookSignature(secret, timestamp, signature string, payload []byte, tolerances ...time.Duration) bool {
	tolerance := 5 * time.Minute
	if len(tolerances) > 0 && tolerances[0] > 0 {
		tolerance = tolerances[0]
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(timestamp), 10, 64)
	if err != nil {
		return false
	}
	if tolerance > 0 && time.Since(time.Unix(ts, 0).UTC()).Abs() > tolerance {
		return false
	}
	expected := SignWebhookPayload(secret, timestamp, payload)
	return hmac.Equal([]byte(expected), []byte(signature))
}

func trimStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func audienceMatches(actual []string, expected []string) bool {
	for _, want := range expected {
		for _, got := range actual {
			if got == want {
				return true
			}
		}
	}
	return false
}

func splitScopeString(raw string) []string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func scopeMatches(granted, required string) bool {
	granted = strings.TrimSpace(granted)
	required = strings.TrimSpace(required)
	if granted == required || granted == "*" {
		return true
	}
	if strings.HasSuffix(granted, ":*") {
		return strings.HasPrefix(required, strings.TrimSuffix(granted, "*"))
	}
	return false
}
