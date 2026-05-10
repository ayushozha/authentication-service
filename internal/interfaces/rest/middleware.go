package rest

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type contextKey string

const (
	clientContextKey contextKey = "client"
	userContextKey   contextKey = "user_claims"
)

func LogRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		elapsed := time.Since(start)
		application.Metrics().ObserveHTTP(r.Method, r.URL.Path, rec.status, elapsed)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.status, elapsed)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// RequireAPIKey validates the X-API-Key header and injects the client into context.
// OPTIONS requests are passed through for CORS preflight support.
func RequireAPIKey(clientSvc *application.ClientService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing X-API-Key header"})
				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()

			client, err := clientSvc.GetClientByAPIKey(ctx, apiKey)
			if err != nil {
				if err == domain.ErrInvalidClient {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid API key"})
				} else if err == domain.ErrClientSuspended {
					writeJSON(w, http.StatusForbidden, map[string]string{"error": "client suspended"})
				} else {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				}
				return
			}

			ctx2 := context.WithValue(r.Context(), clientContextKey, client)
			next.ServeHTTP(w, r.WithContext(ctx2))
		})
	}
}

// RequireAdminKey validates the master admin API key.
// OPTIONS requests are passed through for CORS preflight support.
func RequireAdminKey(adminAPIKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			key := r.Header.Get("X-Admin-Key")
			if key == "" || key != adminAPIKey {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid admin key"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireUserAuth validates JWT Bearer token.
func RequireUserAuth(clientSvc *application.ClientService) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			client := GetClient(r)
			if client == nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing client context"})
				return
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing authorization header"})
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid authorization format"})
				return
			}

			claims, err := application.ValidateAccessToken(r.Context(), client, parts[1])
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
				return
			}
			if claims.ClientID != client.ID {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token does not belong to this client"})
				return
			}

			ctx := context.WithValue(r.Context(), userContextKey, claims)
			next(w, r.WithContext(ctx))
		}
	}
}

func GetClient(r *http.Request) *domain.Client {
	client, _ := r.Context().Value(clientContextKey).(*domain.Client)
	return client
}

func GetUserClaims(r *http.Request) *application.AccessClaims {
	claims, _ := r.Context().Value(userContextKey).(*application.AccessClaims)
	return claims
}

func SetRefreshCookie(w http.ResponseWriter, token string, ttl time.Duration, cfg *HandlerConfig) {
	if cfg == nil {
		cfg = &HandlerConfig{}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_refresh",
		Value:    token,
		Path:     "/",
		Domain:   cfg.CookieDomain,
		Secure:   cfg.CookieSecure,
		HttpOnly: true,
		SameSite: parseSameSite(cfg.CookieSameSite),
		MaxAge:   int(ttl.Seconds()),
	})
}

func ClearRefreshCookie(w http.ResponseWriter, cfg *HandlerConfig) {
	if cfg == nil {
		cfg = &HandlerConfig{}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_refresh",
		Value:    "",
		Path:     "/",
		Domain:   cfg.CookieDomain,
		Secure:   cfg.CookieSecure,
		HttpOnly: true,
		SameSite: parseSameSite(cfg.CookieSameSite),
		MaxAge:   -1,
	})
}

// CORSHandler wraps a HandlerFunc with CORS support.
func CORSHandler(origin string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client := GetClient(r)
		requestOrigin := strings.TrimSpace(r.Header.Get("Origin"))
		corsOrigin, allowCredentials, allowed := resolveAllowedOrigin(requestOrigin, origin, client)
		if requestOrigin != "" && !allowed {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin is not allowed"})
			return
		}
		if requestOrigin != "" || corsOrigin != "" {
			setCorsHeaders(w, corsOrigin, allowCredentials)
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func MethodCheck(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			return // already handled by CORSHandler
		}
		if r.Method != method {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": fmt.Sprintf("method not allowed, expected %s", method)})
			return
		}
		next(w, r)
	}
}

func parseSameSite(value string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func resolveAllowedOrigin(requestOrigin, defaultOrigin string, client *domain.Client) (corsOrigin string, allowCredentials bool, allowed bool) {
	if client != nil && len(client.AllowedOrigins) > 0 {
		if requestOrigin == "" {
			return client.AllowedOrigins[0], true, true
		}
		for _, allowedOrigin := range client.AllowedOrigins {
			if strings.EqualFold(strings.TrimSpace(allowedOrigin), requestOrigin) {
				return requestOrigin, true, true
			}
		}
		return "", false, false
	}

	rawDefault := strings.TrimSpace(defaultOrigin)
	if rawDefault == "" {
		return "", false, requestOrigin == ""
	}
	if rawDefault == "*" {
		return "*", false, true
	}

	origins := splitOrigins(rawDefault)
	if requestOrigin == "" {
		return origins[0], true, true
	}
	for _, allowedOrigin := range origins {
		if strings.EqualFold(allowedOrigin, requestOrigin) {
			return requestOrigin, true, true
		}
	}
	return "", false, false
}

func splitOrigins(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		o := strings.TrimSpace(part)
		if o != "" {
			result = append(result, o)
		}
	}
	if len(result) == 0 {
		return []string{raw}
	}
	return result
}
