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
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	options, err := h.svc.BeginRegistration(ctx, client, claims.Subject)
	if err != nil {
		if err == domain.ErrRedisRequired {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "passkeys require Redis"})
			return
		}
		if err == domain.ErrNotFound {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, options)
}

func (h *PasskeyHandler) registerFinish(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	friendlyName := strings.TrimSpace(r.URL.Query().Get("name"))
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.svc.FinishRegistration(ctx, client, claims.Subject, friendlyName, r, clientIP(r), r.UserAgent()); err != nil {
		switch err {
		case domain.ErrRedisRequired:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "passkeys require Redis"})
		case domain.ErrInvalidToken:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no registration in progress"})
		case domain.ErrNotFound:
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		case domain.ErrPasskeyAttestation:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey attestation rejected"})
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "registration failed"})
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"ok": "true"})
}

func (h *PasskeyHandler) loginBegin(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	if client == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing client"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	options, _, err := h.svc.BeginLogin(ctx, client)
	if err != nil {
		if err == domain.ErrRedisRequired {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "passkeys require Redis"})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		}
		return
	}
	writeJSON(w, http.StatusOK, options)
}

func (h *PasskeyHandler) loginFinish(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	if client == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing client"})
		return
	}

	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, refreshToken, err := h.svc.FinishLogin(ctx, client, sessionID, r, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
	if err != nil {
		switch err {
		case domain.ErrRedisRequired:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "passkeys require Redis"})
		case domain.ErrInvalidToken:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no login in progress"})
		case domain.ErrNotFound:
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		case domain.ErrAccountSuspended:
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "account is suspended"})
		default:
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
		}
		return
	}

	if isTokenSessionMode(r, "") {
		resp.RefreshToken = refreshToken
	} else {
		SetRefreshCookie(w, refreshToken, h.cfg.RefreshTTL, h.cfg)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *PasskeyHandler) listOrDeleteRoot(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	switch r.Method {
	case http.MethodGet:
		creds, err := h.svc.ListPasskeys(ctx, claims.Subject)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		writeJSON(w, http.StatusOK, creds)
	case http.MethodDelete:
		// Backward compatible delete style: DELETE /api/auth/passkeys?id=<passkey-id>
		passkeyID := strings.TrimSpace(r.URL.Query().Get("id"))
		if passkeyID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey ID required"})
			return
		}
		if err := h.svc.DeletePasskey(ctx, client, passkeyID, claims.Subject, clientIP(r), r.UserAgent()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not delete passkey"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *PasskeyHandler) deletePasskeyByPath(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	passkeyID := strings.TrimPrefix(r.URL.Path, "/api/auth/passkeys/")
	passkeyID = strings.TrimSpace(passkeyID)
	if passkeyID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey ID required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := h.svc.DeletePasskey(ctx, client, passkeyID, claims.Subject, clientIP(r), r.UserAgent()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not delete passkey"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
