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
	mux.HandleFunc("/api/auth/recovery-codes", CORSHandler(h.cfg.AllowOrigin, authMw(h.recoveryCodes)))
	mux.HandleFunc("/api/auth/recovery-codes/verify", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.verifyRecoveryCode)))
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
			writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		} else if err == domain.ErrRedisRequired {
			writeError(w, r, http.StatusServiceUnavailable, "redis_required", "2FA requires Redis.")
		} else if err == domain.ErrNotFound {
			writeError(w, r, http.StatusNotFound, "user_not_found", "User not found.")
		} else {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
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
		writeError(w, r, http.StatusBadRequest, "code_is_required", "Code is required.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := h.svc.Enable(ctx, client, claims.Subject, req.Code, clientIP(r), r.UserAgent()); err != nil {
		switch err {
		case domain.ErrTOTPInvalid:
			writeError(w, r, http.StatusBadRequest, "invalid_totp", "Invalid code.")
		case domain.ErrTOTPNoPending:
			writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		case domain.ErrRedisRequired:
			writeError(w, r, http.StatusServiceUnavailable, "redis_required", "2FA requires Redis.")
		default:
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *TOTPHandler) verify(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	var req struct {
		TwoFAToken     string `json:"two_factor_token"`
		Code           string `json:"code"`
		SessionMode    string `json:"session_mode"`
		TokenTransport string `json:"token_transport"`
		RememberDevice bool   `json:"remember_device"`
		DeviceName     string `json:"device_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request_body", "Invalid request body.")
		return
	}
	if req.TwoFAToken == "" || req.Code == "" {
		writeError(w, r, http.StatusBadRequest, "token_and_code_are_required", "Two-factor token and code are required.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, refreshToken, err := h.svc.Verify(ctx, client, req.TwoFAToken, req.Code, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL, req.RememberDevice, req.DeviceName)
	if err != nil {
		switch err {
		case domain.ErrInvalidToken:
			writeError(w, r, http.StatusBadRequest, "invalid_or_expired_2fa_token", "Invalid or expired 2FA token.")
		case domain.ErrTOTPInvalid:
			writeError(w, r, http.StatusUnauthorized, "invalid_totp", "Invalid code.")
		case domain.ErrRedisRequired:
			writeError(w, r, http.StatusServiceUnavailable, "redis_required", "2FA requires Redis.")
		default:
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		}
		return
	}

	applyRefreshTransport(w, h.cfg, resp, refreshToken, tokenTransport(r, req.TokenTransport, req.SessionMode))
	writeJSON(w, http.StatusOK, resp)
}

func (h *TOTPHandler) recoveryCodes(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	switch r.Method {
	case http.MethodGet:
		resp, err := h.svc.CountRecoveryCodes(ctx, client, claims.Subject)
		if err != nil {
			writeRecoveryCodeError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		resp, err := h.svc.GenerateRecoveryCodes(ctx, client, claims.Subject, clientIP(r), r.UserAgent())
		if err != nil {
			writeRecoveryCodeError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
	}
}

func (h *TOTPHandler) verifyRecoveryCode(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	var req struct {
		TwoFAToken     string `json:"two_factor_token"`
		Code           string `json:"code"`
		SessionMode    string `json:"session_mode"`
		TokenTransport string `json:"token_transport"`
		RememberDevice bool   `json:"remember_device"`
		DeviceName     string `json:"device_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request_body", "Invalid request body.")
		return
	}
	if req.TwoFAToken == "" || req.Code == "" {
		writeError(w, r, http.StatusBadRequest, "token_and_code_are_required", "Two-factor token and code are required.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, refreshToken, err := h.svc.VerifyRecoveryCode(ctx, client, req.TwoFAToken, req.Code, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL, req.RememberDevice, req.DeviceName)
	if err != nil {
		switch err {
		case domain.ErrInvalidToken:
			writeError(w, r, http.StatusBadRequest, "invalid_or_expired_2fa_token", "Invalid or expired 2FA token.")
		case domain.ErrTOTPInvalid:
			writeError(w, r, http.StatusUnauthorized, "invalid_recovery_code", "Invalid recovery code.")
		case domain.ErrRedisRequired:
			writeError(w, r, http.StatusServiceUnavailable, "redis_required", "2FA requires Redis.")
		default:
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		}
		return
	}

	applyRefreshTransport(w, h.cfg, resp, refreshToken, tokenTransport(r, req.TokenTransport, req.SessionMode))
	writeJSON(w, http.StatusOK, resp)
}

func (h *TOTPHandler) disable(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.Code == "" {
		writeError(w, r, http.StatusBadRequest, "code_is_required", "Code is required.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := h.svc.Disable(ctx, client, claims.Subject, req.Code, clientIP(r), r.UserAgent()); err != nil {
		switch err {
		case domain.ErrTOTPInvalid:
			writeError(w, r, http.StatusUnauthorized, "invalid_totp", "Invalid code.")
		case domain.ErrTOTPNotEnabled:
			writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		default:
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func writeRecoveryCodeError(w http.ResponseWriter, r *http.Request, err error) {
	switch err {
	case domain.ErrTOTPNotEnabled:
		writeError(w, r, http.StatusBadRequest, "invalid_request", "TOTP must be enabled before generating recovery codes.")
	case domain.ErrNotFound:
		writeError(w, r, http.StatusNotFound, "user_not_found", "User not found.")
	case domain.ErrInvalidToken:
		writeError(w, r, http.StatusUnauthorized, "invalid_access_token", "Unauthorized.")
	default:
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
	}
}
