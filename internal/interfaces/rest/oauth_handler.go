package rest

import (
	"context"
	"net/http"
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
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
				return
			}
			client := GetClient(r)
			if client == nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing client"})
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()

			redirectURL, err := h.svc.BeginOAuth(ctx, client, provCfg, provName, r.URL.Query().Get("session_mode"))
			if err != nil {
				if err == domain.ErrRedisRequired {
					writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "oauth requires Redis"})
					return
				}
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
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
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
				return
			}
			if r.Method == http.MethodPost {
				_ = r.ParseForm()
			}

			code := r.FormValue("code")
			state := r.FormValue("state")
			if code == "" || state == "" {
				errorMsg := r.FormValue("error")
				if errorMsg == "" {
					errorMsg = "missing code or state"
				}
				http.Redirect(w, r, h.cfg.BaseURL+"/login.html?error="+errorMsg, http.StatusFound)
				return
			}

			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()

			_, accessToken, refreshToken, sessionMode, err := h.svc.HandleCallback(ctx, provCfg, provName, code, state, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
			if err != nil {
				http.Redirect(w, r, h.cfg.BaseURL+"/login.html?error="+err.Error(), http.StatusFound)
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
