package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type TOTPHandler struct {
	svc *application.TOTPService
	cfg *HandlerConfig
}

func NewTOTPHandler(svc *application.TOTPService, cfg *HandlerConfig) *TOTPHandler {
	return &TOTPHandler{svc: svc, cfg: cfg}
}

func (h *TOTPHandler) RegisterRoutes(mux *http.ServeMux, authMw func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/auth/totp/setup", CORSHandler(h.cfg.AllowOrigin, authMw(MethodCheck(http.MethodPost, h.setup))))
	mux.HandleFunc("/api/auth/totp/enable", CORSHandler(h.cfg.AllowOrigin, authMw(MethodCheck(http.MethodPost, h.enable))))
	mux.HandleFunc("/api/auth/totp/verify", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.verify)))
	mux.HandleFunc("/api/auth/totp/disable", CORSHandler(h.cfg.AllowOrigin, authMw(MethodCheck(http.MethodPost, h.disable))))
}

func (h *TOTPHandler) setup(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	issuerName := "AuthService"
	if client != nil {
		issuerName = client.Name
	}

	resp, err := h.svc.Setup(ctx, client, claims.Subject, issuerName)
	if err != nil {
		if err == domain.ErrTOTPAlreadyOn {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *TOTPHandler) enable(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code is required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := h.svc.Enable(ctx, client, claims.Subject, req.Code, clientIP(r), r.UserAgent()); err != nil {
		switch err {
		case domain.ErrTOTPInvalid:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid code"})
		case domain.ErrTOTPNoPending:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *TOTPHandler) verify(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	var req struct {
		TwoFAToken string `json:"two_factor_token"`
		Code       string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.TwoFAToken == "" || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "two_factor_token and code are required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, refreshToken, err := h.svc.Verify(ctx, client, req.TwoFAToken, req.Code, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
	if err != nil {
		switch err {
		case domain.ErrInvalidToken:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired 2FA token"})
		case domain.ErrTOTPInvalid:
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
		case domain.ErrRedisRequired:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "2FA requires Redis"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}

	SetRefreshCookie(w, refreshToken, h.cfg.RefreshTTL)
	writeJSON(w, http.StatusOK, resp)
}

func (h *TOTPHandler) disable(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code is required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := h.svc.Disable(ctx, client, claims.Subject, req.Code, clientIP(r), r.UserAgent()); err != nil {
		switch err {
		case domain.ErrTOTPInvalid:
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
		case domain.ErrTOTPNotEnabled:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
