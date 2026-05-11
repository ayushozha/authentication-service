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
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		} else if err == domain.ErrRedisRequired {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "2FA requires Redis"})
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
		case domain.ErrRedisRequired:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "2FA requires Redis"})
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
		TwoFAToken     string `json:"two_factor_token"`
		Code           string `json:"code"`
		SessionMode    string `json:"session_mode"`
		TokenTransport string `json:"token_transport"`
		RememberDevice bool   `json:"remember_device"`
		DeviceName     string `json:"device_name"`
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

	resp, refreshToken, err := h.svc.Verify(ctx, client, req.TwoFAToken, req.Code, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL, req.RememberDevice, req.DeviceName)
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
			writeRecoveryCodeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		resp, err := h.svc.GenerateRecoveryCodes(ctx, client, claims.Subject, clientIP(r), r.UserAgent())
		if err != nil {
			writeRecoveryCodeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.TwoFAToken == "" || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "two_factor_token and code are required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, refreshToken, err := h.svc.VerifyRecoveryCode(ctx, client, req.TwoFAToken, req.Code, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL, req.RememberDevice, req.DeviceName)
	if err != nil {
		switch err {
		case domain.ErrInvalidToken:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired 2FA token"})
		case domain.ErrTOTPInvalid:
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid recovery code"})
		case domain.ErrRedisRequired:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "2FA requires Redis"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
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

func writeRecoveryCodeError(w http.ResponseWriter, err error) {
	switch err {
	case domain.ErrTOTPNotEnabled:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "TOTP must be enabled before generating recovery codes"})
	case domain.ErrNotFound:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
	case domain.ErrInvalidToken:
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
}
