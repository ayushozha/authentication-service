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
		writeError(w, r, http.StatusBadRequest, "email_required", "Email is required.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.svc.SendMagicLink(ctx, client, req.Email, h.cfg.BaseURL, clientIP(r), r.UserAgent()); err != nil {
		if err == domain.ErrInvalidEmail {
			writeError(w, r, http.StatusBadRequest, "invalid_email", err.Error())
			return
		}
		if err == domain.ErrEmailNotConfigured {
			writeError(w, r, http.StatusServiceUnavailable, "email_not_configured", err.Error())
			return
		}
		if err == domain.ErrRedisRequired {
			writeError(w, r, http.StatusServiceUnavailable, "redis_required", "Magic links require Redis.")
			return
		}
		if err == domain.ErrRateLimit {
			w.Header().Set("Retry-After", "3600")
			writeError(w, r, http.StatusTooManyRequests, "rate_limited", err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *MagicLinkHandler) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, r, http.StatusBadRequest, "token_is_required", "Token is required.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, refreshToken, err := h.svc.VerifyMagicLinkPublic(ctx, token, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
	if err != nil {
		if err == domain.ErrInvalidToken {
			writeError(w, r, http.StatusBadRequest, "invalid_or_expired_token", "Invalid or expired magic link.")
		} else if err == domain.ErrRedisRequired {
			writeError(w, r, http.StatusServiceUnavailable, "redis_required", "Magic links require Redis.")
		} else {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
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
	redirectWithAuthCode(w, r, h.cfg, resp, refreshToken, isTokenSessionMode(r, ""))
}
