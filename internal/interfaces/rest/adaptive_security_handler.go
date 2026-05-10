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
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req struct {
		ChallengeToken string `json:"challenge_token"`
		Factor         string `json:"factor"`
		Code           string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(req.ChallengeToken) == "" || strings.TrimSpace(req.Code) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge_token and code are required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	resp, err := h.svc.VerifyStepUp(ctx, client, claims.Subject, req.ChallengeToken, req.Factor, req.Code, clientIP(r), r.UserAgent())
	if err != nil {
		writeAdaptiveSecurityError(w, err)
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
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	actor := GetAdminActor(r)
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req struct {
		ChallengeToken string `json:"challenge_token"`
		Factor         string `json:"factor"`
		Code           string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(req.ChallengeToken) == "" || strings.TrimSpace(req.Code) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge_token and code are required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	resp, err := h.svc.VerifyAdminStepUp(ctx, actor, req.ChallengeToken, req.Factor, req.Code, clientIP(r), r.UserAgent())
	if err != nil {
		writeAdaptiveSecurityError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AdaptiveSecurityHandler) devices(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	devices, err := h.svc.ListDevices(ctx, client, claims.Subject)
	if err != nil {
		writeAdaptiveSecurityError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"devices": devices})
}

func (h *AdaptiveSecurityHandler) deviceByID(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	deviceID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auth/devices/"), "/")
	if deviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "device_id required"})
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
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		trusted := false
		if req.Trusted != nil {
			trusted = *req.Trusted
		}
		device, err := h.svc.TrustDevice(ctx, client, claims.Subject, deviceID, req.Name, trusted)
		if err != nil {
			writeAdaptiveSecurityError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, device)
	case http.MethodDelete:
		if err := h.svc.DeleteDevice(ctx, client, claims.Subject, deviceID); err != nil {
			writeAdaptiveSecurityError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func stepUpTokenFromRequest(r *http.Request) string {
	token := strings.TrimSpace(r.Header.Get("X-Step-Up-Token"))
	if token != "" {
		return token
	}
	return strings.TrimSpace(r.URL.Query().Get("step_up_token"))
}

func writeAdaptiveActionDecision(w http.ResponseWriter, decision *application.ActionSecurityDecision) {
	if decision == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	status := http.StatusForbidden
	errorCode := "step_up_required"
	if decision.Blocked {
		errorCode = "blocked_by_security_policy"
	}
	writeJSON(w, status, map[string]interface{}{
		"error":            errorCode,
		"action":           decision.Action,
		"step_up_required": decision.StepUpRequired,
		"challenge_token":  decision.ChallengeToken,
		"factors":          decision.Factors,
		"expires_in":       decision.ExpiresIn,
		"risk":             decision.Risk,
	})
}

func writeAdaptiveSecurityError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrRedisRequired):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "adaptive security requires Redis"})
	case errors.Is(err, domain.ErrInvalidToken):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired security token"})
	case errors.Is(err, domain.ErrTOTPInvalid):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
	case errors.Is(err, domain.ErrStepUpEnrollmentRequired):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "step-up factor enrollment required"})
	case errors.Is(err, domain.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
}
