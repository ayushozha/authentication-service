package rest

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type PasskeyHandler struct {
	svc *application.PasskeyService
	cfg *HandlerConfig
}

func NewPasskeyHandler(svc *application.PasskeyService, cfg *HandlerConfig) *PasskeyHandler {
	return &PasskeyHandler{svc: svc, cfg: cfg}
}

func (h *PasskeyHandler) RegisterRoutes(mux *http.ServeMux, authMw func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/auth/passkey/register/begin", CORSHandler(h.cfg.AllowOrigin, authMw(MethodCheck(http.MethodPost, h.registerBegin))))
	mux.HandleFunc("/api/auth/passkey/register/finish", CORSHandler(h.cfg.AllowOrigin, authMw(MethodCheck(http.MethodPost, h.registerFinish))))
	mux.HandleFunc("/api/auth/passkey/login/begin", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.loginBegin)))
	mux.HandleFunc("/api/auth/passkey/login/finish", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.loginFinish)))
	mux.HandleFunc("/api/auth/passkeys", CORSHandler(h.cfg.AllowOrigin, authMw(h.listOrDeleteRoot)))
	mux.HandleFunc("/api/auth/passkeys/", CORSHandler(h.cfg.AllowOrigin, authMw(MethodCheck(http.MethodDelete, h.deletePasskeyByPath))))
}

func (h *PasskeyHandler) registerBegin(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	options, err := h.svc.BeginRegistration(ctx, client, claims.Subject)
	if err != nil {
		if err == domain.ErrRedisRequired {
			writeError(w, r, http.StatusServiceUnavailable, "redis_required", "Passkeys require Redis.")
			return
		}
		if err == domain.ErrNotFound {
			writeError(w, r, http.StatusNotFound, "user_not_found", "User not found.")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	writeJSON(w, http.StatusOK, options)
}

func (h *PasskeyHandler) registerFinish(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized.")
		return
	}

	friendlyName := strings.TrimSpace(r.URL.Query().Get("name"))
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.svc.FinishRegistration(ctx, client, claims.Subject, friendlyName, r, clientIP(r), r.UserAgent()); err != nil {
		switch err {
		case domain.ErrRedisRequired:
			writeError(w, r, http.StatusServiceUnavailable, "redis_required", "Passkeys require Redis.")
		case domain.ErrInvalidToken:
			writeError(w, r, http.StatusBadRequest, "no_registration_in_progress", "No registration in progress.")
		case domain.ErrNotFound:
			writeError(w, r, http.StatusNotFound, "user_not_found", "User not found.")
		case domain.ErrPasskeyAttestation:
			writeError(w, r, http.StatusBadRequest, "passkey_attestation_rejected", "Passkey attestation rejected.")
		default:
			writeError(w, r, http.StatusBadRequest, "registration_failed", "Registration failed.")
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"ok": "true"})
}

func (h *PasskeyHandler) loginBegin(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	if client == nil {
		writeError(w, r, http.StatusUnauthorized, "missing_client", "Missing client.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	options, _, err := h.svc.BeginLogin(ctx, client)
	if err != nil {
		if err == domain.ErrRedisRequired {
			writeError(w, r, http.StatusServiceUnavailable, "redis_required", "Passkeys require Redis.")
		} else {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		}
		return
	}
	writeJSON(w, http.StatusOK, options)
}

func (h *PasskeyHandler) loginFinish(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	if client == nil {
		writeError(w, r, http.StatusUnauthorized, "missing_client", "Missing client.")
		return
	}

	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if sessionID == "" {
		writeError(w, r, http.StatusBadRequest, "session_id_required", "Session ID required.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, refreshToken, err := h.svc.FinishLogin(ctx, client, sessionID, r, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
	if err != nil {
		switch err {
		case domain.ErrRedisRequired:
			writeError(w, r, http.StatusServiceUnavailable, "redis_required", "Passkeys require Redis.")
		case domain.ErrInvalidToken:
			writeError(w, r, http.StatusBadRequest, "no_login_in_progress", "No login in progress.")
		case domain.ErrNotFound:
			writeError(w, r, http.StatusUnauthorized, "user_not_found", "User not found.")
		case domain.ErrAccountSuspended:
			writeError(w, r, http.StatusForbidden, "account_suspended", "Account is suspended.")
		default:
			writeError(w, r, http.StatusUnauthorized, "authentication_failed", "Authentication failed.")
		}
		return
	}

	applyRefreshTransport(w, h.cfg, resp, refreshToken, tokenTransport(r, "", ""))
	writeJSON(w, http.StatusOK, resp)
}

func (h *PasskeyHandler) listOrDeleteRoot(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	switch r.Method {
	case http.MethodGet:
		creds, err := h.svc.ListPasskeys(ctx, claims.Subject)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
			return
		}
		writeJSON(w, http.StatusOK, creds)
	case http.MethodDelete:
		// Backward compatible delete style: DELETE /api/auth/passkeys?id=<passkey-id>
		passkeyID := strings.TrimSpace(r.URL.Query().Get("id"))
		if passkeyID == "" {
			writeError(w, r, http.StatusBadRequest, "passkey_id_required", "Passkey ID required.")
			return
		}
		if err := h.svc.DeletePasskey(ctx, client, passkeyID, claims.Subject, clientIP(r), r.UserAgent()); err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
	}
}

func (h *PasskeyHandler) deletePasskeyByPath(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeError(w, r, http.StatusUnauthorized, "unauthorized", "Unauthorized.")
		return
	}

	passkeyID := strings.TrimPrefix(r.URL.Path, "/api/auth/passkeys/")
	passkeyID = strings.TrimSpace(passkeyID)
	if passkeyID == "" {
		writeError(w, r, http.StatusBadRequest, "passkey_id_required", "Passkey ID required.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := h.svc.DeletePasskey(ctx, client, passkeyID, claims.Subject, clientIP(r), r.UserAgent()); err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
