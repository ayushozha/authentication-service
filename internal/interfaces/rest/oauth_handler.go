package rest

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type OAuthHandler struct {
	svc       *application.OAuthService
	providers map[string]*application.OAuthProviderConfig
	cfg       *HandlerConfig
}

func NewOAuthHandler(svc *application.OAuthService, providers map[string]*application.OAuthProviderConfig, cfg *HandlerConfig) *OAuthHandler {
	return &OAuthHandler{svc: svc, providers: providers, cfg: cfg}
}

func (h *OAuthHandler) RegisterRoutes(mux *http.ServeMux) {
	h.RegisterBeginRoutes(mux)
	h.RegisterCallbackRoutes(mux)
}

func (h *OAuthHandler) RegisterBeginRoutes(mux *http.ServeMux) {
	for name, prov := range h.providers {
		provName := name
		provCfg := prov

		mux.HandleFunc("/api/auth/oauth/"+provName, CORSHandler(h.cfg.AllowOrigin, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
				return
			}
			client := GetClient(r)
			if client == nil {
				writeError(w, r, http.StatusUnauthorized, "missing_client", "Missing client.")
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()

			redirectURL, err := h.svc.BeginOAuth(ctx, client, provCfg, provName, r.URL.Query().Get("session_mode"))
			if err != nil {
				if err == domain.ErrRedisRequired {
					writeError(w, r, http.StatusServiceUnavailable, "oauth_provider_unavailable", "OAuth requires Redis.")
					return
				}
				writeError(w, r, http.StatusInternalServerError, "oauth_failed", "OAuth failed.")
				return
			}
			http.Redirect(w, r, redirectURL, http.StatusFound)
		}))
	}
}

func (h *OAuthHandler) RegisterCallbackRoutes(mux *http.ServeMux) {
	for name, prov := range h.providers {
		provName := name
		provCfg := prov

		mux.HandleFunc("/api/auth/oauth/"+provName+"/callback", CORSHandler(h.cfg.AllowOrigin, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodPost {
				writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
				return
			}
			if r.Method == http.MethodPost {
				_ = r.ParseForm()
			}

			code := r.FormValue("code")
			state := r.FormValue("state")
			if code == "" || state == "" {
				redirectWithLoginAuthError(w, r, h.cfg, authCodeForOAuthCallbackError(r.FormValue("error")))
				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()

			_, accessToken, refreshToken, sessionMode, err := h.svc.HandleCallback(ctx, provCfg, provName, code, state, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
			if err != nil {
				redirectWithLoginAuthError(w, r, h.cfg, authCodeForOAuthCallbackError(err.Error()))
				return
			}

			tokenMode := isTokenSessionMode(r, sessionMode)
			if !tokenMode {
				SetRefreshCookie(w, refreshToken, h.cfg.RefreshTTL, h.cfg)
			}
			resp := &application.AuthResponse{
				AccessToken: accessToken,
				TokenType:   "Bearer",
				ExpiresIn:   int(h.cfg.AccessTTL.Seconds()),
			}
			redirectWithAuthCode(w, r, h.cfg, resp, refreshToken, tokenMode)
		}))
	}
}

func authCodeForOAuthCallbackError(value string) string {
	switch normalizeLegacyErrorCode(value) {
	case "access_denied", "cancelled", "canceled", "oauth_cancelled":
		return "AUTH_OAUTH_CANCELLED"
	case "invalid_state", "state_mismatch", "missing_code_or_state":
		return "AUTH_OAUTH_STATE_MISMATCH"
	case "redis_required", "oauth_requires_redis", "provider_unavailable", "temporarily_unavailable":
		return "AUTH_OAUTH_PROVIDER_UNAVAILABLE"
	case "sso_required":
		return "AUTH_SSO_FAILED"
	case "account_suspended", "account_disabled":
		return "AUTH_ACCOUNT_DISABLED"
	}
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return "AUTH_OAUTH_STATE_MISMATCH"
	}
	if strings.Contains(lower, "redis") || strings.Contains(lower, "temporarily unavailable") {
		return "AUTH_OAUTH_PROVIDER_UNAVAILABLE"
	}
	if strings.Contains(lower, "sso") {
		return "AUTH_SSO_FAILED"
	}
	return "AUTH_OAUTH_FAILED"
}
