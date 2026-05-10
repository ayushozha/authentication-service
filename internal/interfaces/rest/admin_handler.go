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
	"github.com/google/uuid"
)

type AdminHandler struct {
	svc *application.AdminService
	cfg *HandlerConfig
}

func NewAdminHandler(svc *application.AdminService, cfg *HandlerConfig) *AdminHandler {
	return &AdminHandler{svc: svc, cfg: cfg}
}

func (h *AdminHandler) RegisterAuthRoutes(mux *http.ServeMux) {
	if h == nil || h.svc == nil {
		return
	}
	mux.HandleFunc("/api/admin/auth/login", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.login)))
	mux.HandleFunc("/api/admin/auth/sso", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.ssoLogin)))
}

func (h *AdminHandler) RegisterUserRoutes(mux *http.ServeMux, adminMw func(http.Handler) http.Handler) {
	if h == nil || h.svc == nil {
		return
	}
	mux.Handle("/api/admin/users", adminMw(http.HandlerFunc(h.users)))
}

func (h *AdminHandler) login(w http.ResponseWriter, r *http.Request) {
	var req application.AdminLoginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	resp, err := h.svc.Login(ctx, req, clientIP(r), r.UserAgent(), adminAuthRequestID(w, r))
	if err != nil {
		writeAdminAuthError(w, resp, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) ssoLogin(w http.ResponseWriter, r *http.Request) {
	var req application.AdminSSOLoginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	resp, err := h.svc.LoginWithSSO(ctx, req, clientIP(r), r.UserAgent(), adminAuthRequestID(w, r))
	if err != nil {
		writeAdminAuthError(w, resp, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *AdminHandler) users(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w, "*", false)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	switch r.Method {
	case http.MethodGet:
		admins, err := h.svc.ListAdminUsers(ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		SetAdminAuditAfter(r, map[string]interface{}{"count": len(admins)})
		writeJSON(w, http.StatusOK, map[string]interface{}{"admins": admins})
	case http.MethodPost:
		var req application.CreateAdminUserRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		resp, err := h.svc.CreateAdminUser(ctx, req)
		if err != nil {
			writeAdminManagementError(w, err)
			return
		}
		SetAdminAuditTarget(r, "admin_user", resp.ID, "")
		SetAdminAuditAfter(r, map[string]interface{}{
			"id":                    resp.ID,
			"email":                 resp.Email,
			"roles":                 resp.Roles,
			"scope_type":            resp.ScopeType,
			"scope_client_id":       resp.ScopeClientID,
			"scope_organization_id": resp.ScopeOrganizationID,
			"mfa_required":          resp.MFARequired,
			"totp_enabled":          resp.TOTPEnabled,
			"sso_provider":          resp.SSOProvider,
			"status":                resp.Status,
		})
		writeJSON(w, http.StatusCreated, resp)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func writeAdminAuthError(w http.ResponseWriter, resp *application.AdminAuthResponse, err error) {
	switch {
	case errors.Is(err, domain.ErrMFARequired):
		if resp == nil {
			resp = &application.AdminAuthResponse{MFARequired: true, Error: "mfa_required"}
		}
		writeJSON(w, http.StatusUnauthorized, resp)
	case errors.Is(err, domain.ErrMFAEnrollmentRequired):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "mfa enrollment required"})
	case errors.Is(err, domain.ErrTOTPInvalid):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid TOTP code"})
	case errors.Is(err, domain.ErrAccountSuspended):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account suspended"})
	case errors.Is(err, domain.ErrInvalidPassword):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid email or password"})
	default:
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "required") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
}

func writeAdminManagementError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidAdminRole):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid admin role"})
	case errors.Is(err, domain.ErrInvalidAdminScope):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid admin scope"})
	default:
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "required") || strings.Contains(msg, "invalid") || strings.Contains(msg, "must") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
}

func adminAuthRequestID(w http.ResponseWriter, r *http.Request) string {
	requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if requestID == "" {
		requestID = uuid.NewString()
	}
	w.Header().Set("X-Request-ID", requestID)
	return requestID
}
