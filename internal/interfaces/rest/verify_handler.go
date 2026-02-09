package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type VerifyHandler struct {
	verifySvc *application.EmailVerifyService
	resetSvc  *application.PasswordResetService
	cfg       *HandlerConfig
}

func NewVerifyHandler(verifySvc *application.EmailVerifyService, resetSvc *application.PasswordResetService, cfg *HandlerConfig) *VerifyHandler {
	return &VerifyHandler{verifySvc: verifySvc, resetSvc: resetSvc, cfg: cfg}
}

func (h *VerifyHandler) RegisterRoutes(mux *http.ServeMux, authMw func(http.HandlerFunc) http.HandlerFunc) {
	h.RegisterPublicRoutes(mux)
	h.RegisterAPIKeyRoutes(mux)
	h.RegisterProtectedRoutes(mux, authMw)
}

func (h *VerifyHandler) RegisterPublicRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/auth/verify-email", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.verifyEmail)))
	mux.HandleFunc("/api/auth/reset-password", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.resetPassword)))
}

func (h *VerifyHandler) RegisterAPIKeyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/auth/forgot-password", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.forgotPassword)))
}

func (h *VerifyHandler) RegisterProtectedRoutes(mux *http.ServeMux, authMw func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/auth/resend-verification", CORSHandler(h.cfg.AllowOrigin, authMw(MethodCheck(http.MethodPost, h.resendVerification))))
}

func (h *VerifyHandler) verifyEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token is required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.verifySvc.VerifyEmail(ctx, req.Token); err != nil {
		if err == domain.ErrInvalidToken {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired token"})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *VerifyHandler) resendVerification(w http.ResponseWriter, r *http.Request) {
	claims := GetUserClaims(r)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.verifySvc.ResendVerification(ctx, claims.Subject, h.cfg.BaseURL); err != nil {
		switch err {
		case domain.ErrEmailNotConfigured:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		case domain.ErrEmailAlreadyVerified:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *VerifyHandler) forgotPassword(w http.ResponseWriter, r *http.Request) {
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

	_ = h.resetSvc.ForgotPassword(ctx, client.ID, req.Email, h.cfg.BaseURL)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *VerifyHandler) resetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Token == "" || req.NewPassword == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token and new_password are required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.resetSvc.ResetPassword(ctx, req.Token, req.NewPassword, h.cfg.BcryptCost); err != nil {
		if err == domain.ErrInvalidToken {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired token"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
