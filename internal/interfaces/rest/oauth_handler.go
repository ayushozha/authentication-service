package rest

import (
	"context"
	"net/http"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
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
	for name, prov := range h.providers {
		provName := name
		provCfg := prov

		mux.HandleFunc("/api/auth/oauth/"+provName, CORSHandler(h.cfg.AllowOrigin, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()

			redirectURL, err := h.svc.BeginOAuth(ctx, provCfg)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			http.Redirect(w, r, redirectURL, http.StatusFound)
		}))

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
				http.Redirect(w, r, h.cfg.BaseURL+"/login?error="+errorMsg, http.StatusFound)
				return
			}

			client := GetClient(r)
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()

			accessToken, refreshToken, err := h.svc.HandleCallback(ctx, client, provCfg, provName, code, state, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
			if err != nil {
				http.Redirect(w, r, h.cfg.BaseURL+"/login?error="+err.Error(), http.StatusFound)
				return
			}

			SetRefreshCookie(w, refreshToken, h.cfg.RefreshTTL)
			http.Redirect(w, r, h.cfg.BaseURL+"/login?access_token="+accessToken, http.StatusFound)
		}))
	}
}
