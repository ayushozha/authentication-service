package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type AdaptiveSecurityHandler struct {
	svc *application.AdaptiveSecurityService
	cfg *HandlerConfig
}

func NewAdaptiveSecurityHandler(svc *application.AdaptiveSecurityService, cfg *HandlerConfig) *AdaptiveSecurityHandler {
	return &AdaptiveSecurityHandler{svc: svc, cfg: cfg}
}

func (h *AdaptiveSecurityHandler) RegisterRoutes(mux *http.ServeMux, authMw func(http.HandlerFunc) http.HandlerFunc) {
	if h == nil || h.svc == nil {
		return
	}
	mux.HandleFunc("/api/auth/step-up/verify", CORSHandler(h.cfg.AllowOrigin, authMw(MethodCheck(http.MethodPost, h.verifyStepUp))))
	mux.HandleFunc("/api/auth/devices", CORSHandler(h.cfg.AllowOrigin, authMw(h.devices)))
	mux.HandleFunc("/api/auth/devices/", CORSHandler(h.cfg.AllowOrigin, authMw(h.deviceByID)))
}

func (h *AdaptiveSecurityHandler) RegisterAdminRoutes(mux *http.ServeMux, adminMw func(http.Handler) http.Handler) {
	if h == nil || h.svc == nil {
		return
	}
	mux.Handle("/api/admin/step-up/verify", adminMw(http.HandlerFunc(h.verifyAdminStepUp)))
}

func (h *AdaptiveSecurityHandler) verifyStepUp(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized.")
		return
	}
	var req struct {
		ChallengeToken string `json:"challenge_token"`
		Factor         string `json:"factor"`
		Code           string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request_body", "Invalid request body.")
		return
	}
	if strings.TrimSpace(req.ChallengeToken) == "" || strings.TrimSpace(req.Code) == "" {
		writeError(w, r, http.StatusBadRequest, "token_and_code_are_required", "Challenge token and code are required.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	resp, err := h.svc.VerifyStepUp(ctx, client, claims.Subject, req.ChallengeToken, req.Factor, req.Code, clientIP(r), r.UserAgent())
	if err != nil {
		writeAdaptiveSecurityError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AdaptiveSecurityHandler) verifyAdminStepUp(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w, "*", false)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	actor := GetAdminActor(r)
	if actor == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized.")
		return
	}
	var req struct {
		ChallengeToken string `json:"challenge_token"`
		Factor         string `json:"factor"`
		Code           string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request_body", "Invalid request body.")
		return
	}
	if strings.TrimSpace(req.ChallengeToken) == "" || strings.TrimSpace(req.Code) == "" {
		writeError(w, r, http.StatusBadRequest, "token_and_code_are_required", "Challenge token and code are required.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	resp, err := h.svc.VerifyAdminStepUp(ctx, actor, req.ChallengeToken, req.Factor, req.Code, clientIP(r), r.UserAgent())
	if err != nil {
		writeAdaptiveSecurityError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AdaptiveSecurityHandler) devices(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized.")
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	devices, err := h.svc.ListDevices(ctx, client, claims.Subject)
	if err != nil {
		writeAdaptiveSecurityError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"devices": devices})
}

func (h *AdaptiveSecurityHandler) deviceByID(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized.")
		return
	}
	deviceID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auth/devices/"), "/")
	if deviceID == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Device ID required.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	switch r.Method {
	case http.MethodPatch:
		var req struct {
			Name    string `json:"name"`
			Trusted *bool  `json:"trusted"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request_body", "Invalid request body.")
			return
		}
		trusted := false
		if req.Trusted != nil {
			trusted = *req.Trusted
		}
		device, err := h.svc.TrustDevice(ctx, client, claims.Subject, deviceID, req.Name, trusted)
		if err != nil {
			writeAdaptiveSecurityError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, device)
	case http.MethodDelete:
		if err := h.svc.DeleteDevice(ctx, client, claims.Subject, deviceID); err != nil {
			writeAdaptiveSecurityError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
	}
}

func stepUpTokenFromRequest(r *http.Request) string {
	token := strings.TrimSpace(r.Header.Get("X-Step-Up-Token"))
	if token != "" {
		return token
	}
	return strings.TrimSpace(r.URL.Query().Get("step_up_token"))
}

func writeAdaptiveActionDecision(w http.ResponseWriter, r *http.Request, decision *application.ActionSecurityDecision) {
	if decision == nil {
		writeError(w, r, http.StatusForbidden, "forbidden", "Forbidden.")
		return
	}
	status := http.StatusForbidden
	errorCode := "step_up_required"
	authCode := "AUTH_MFA_REQUIRED"
	if decision.Blocked {
		errorCode = "blocked_by_security_policy"
		authCode = "AUTH_ACCOUNT_DISABLED"
	}
	definition := authErrorDefinitions[authCode]
	writeJSON(w, status, map[string]interface{}{
		"error":            errorCode,
		"code":             errorCode,
		"message":          definition.UserMessage,
		"auth_code":        authCode,
		"user_message":     definition.UserMessage,
		"retryable":        definition.Retryable,
		"action":           decision.Action,
		"step_up_required": decision.StepUpRequired,
		"challenge_token":  decision.ChallengeToken,
		"factors":          decision.Factors,
		"expires_in":       decision.ExpiresIn,
		"risk":             decision.Risk,
	})
}

func writeAdaptiveSecurityError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domain.ErrRedisRequired):
		writeError(w, r, http.StatusServiceUnavailable, "redis_required", "Adaptive security requires Redis.")
	case errors.Is(err, domain.ErrInvalidToken):
		writeError(w, r, http.StatusBadRequest, "invalid_or_expired_2fa_token", "Invalid or expired security token.")
	case errors.Is(err, domain.ErrTOTPInvalid):
		writeError(w, r, http.StatusUnauthorized, "invalid_totp", "Invalid code.")
	case errors.Is(err, domain.ErrStepUpEnrollmentRequired):
		writeError(w, r, http.StatusForbidden, "mfa_required", "Step-up factor enrollment required.")
	case errors.Is(err, domain.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "user_not_found", "Not found.")
	default:
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
	}
}
