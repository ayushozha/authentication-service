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
		writeError(w, r, http.StatusBadRequest, "token_is_required", "Token is required.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.verifySvc.VerifyEmail(ctx, req.Token); err != nil {
		if err == domain.ErrInvalidToken {
			writeError(w, r, http.StatusBadRequest, "invalid_or_expired_token", "Invalid or expired token.")
		} else {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
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
			writeError(w, r, http.StatusServiceUnavailable, "email_not_configured", err.Error())
		case domain.ErrEmailAlreadyVerified:
			writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		default:
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *VerifyHandler) forgotPassword(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	if client == nil {
		writeError(w, r, http.StatusUnauthorized, "missing_client", "Missing client.")
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.Email == "" {
		writeError(w, r, http.StatusBadRequest, "email_required", "Email is required.")
		return
	}
	email, err := application.NormalizeEmailAddress(req.Email)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_email", err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.resetSvc.ForgotPassword(ctx, client.ID, email, h.cfg.BaseURL); err != nil {
		switch err {
		case domain.ErrRateLimit:
			w.Header().Set("Retry-After", "3600")
			writeError(w, r, http.StatusTooManyRequests, "rate_limited", err.Error())
		case domain.ErrEmailNotConfigured:
			writeError(w, r, http.StatusServiceUnavailable, "email_not_configured", err.Error())
		default:
			// Preserve password-reset enumeration safety for lookup/provider errors.
			writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *VerifyHandler) resetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request_body", "Invalid request body.")
		return
	}
	if req.Token == "" || req.NewPassword == "" {
		writeError(w, r, http.StatusBadRequest, "token_and_new_password_are_required", "Token and new password are required.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.resetSvc.ResetPassword(ctx, req.Token, req.NewPassword, h.cfg.BcryptCost); err != nil {
		if err == domain.ErrInvalidToken {
			writeError(w, r, http.StatusBadRequest, "invalid_or_expired_token", "Invalid or expired token.")
		} else {
			writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
