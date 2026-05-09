package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type MagicLinkHandler struct {
	svc *application.MagicLinkService
	cfg *HandlerConfig
}

func NewMagicLinkHandler(svc *application.MagicLinkService, cfg *HandlerConfig) *MagicLinkHandler {
	return &MagicLinkHandler{svc: svc, cfg: cfg}
}

func (h *MagicLinkHandler) RegisterRoutes(mux *http.ServeMux) {
	h.RegisterSendRoute(mux)
	h.RegisterVerifyPublicRoute(mux)
}

func (h *MagicLinkHandler) RegisterSendRoute(mux *http.ServeMux) {
	mux.HandleFunc("/api/auth/magic-link/send", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.send)))
}

func (h *MagicLinkHandler) RegisterVerifyPublicRoute(mux *http.ServeMux) {
	mux.HandleFunc("/api/auth/magic-link/verify", CORSHandler(h.cfg.AllowOrigin, h.verify))
}

func (h *MagicLinkHandler) send(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.svc.SendMagicLink(ctx, client, req.Email, h.cfg.BaseURL, clientIP(r), r.UserAgent()); err != nil {
		if err == domain.ErrEmailNotConfigured {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		if err == domain.ErrRedisRequired {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "magic links require Redis"})
			return
		}
		if err == domain.ErrRateLimit {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *MagicLinkHandler) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, refreshToken, err := h.svc.VerifyMagicLinkPublic(ctx, token, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
	if err != nil {
		if err == domain.ErrInvalidToken {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired magic link"})
		} else if err == domain.ErrRedisRequired {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "magic links require Redis"})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}

	if isTokenSessionMode(r, "") {
		resp.RefreshToken = refreshToken
	} else {
		SetRefreshCookie(w, refreshToken, h.cfg.RefreshTTL, h.cfg)
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	http.Redirect(w, r, h.cfg.BaseURL+"/login.html?access_token="+resp.AccessToken, http.StatusFound)
}
