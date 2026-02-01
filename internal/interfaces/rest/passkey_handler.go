package rest

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/go-webauthn/webauthn/webauthn"
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
	mux.HandleFunc("/api/auth/passkeys", CORSHandler(h.cfg.AllowOrigin, authMw(h.listOrDelete)))
}

func (h *PasskeyHandler) registerBegin(w http.ResponseWriter, r *http.Request) {
	claims := GetUserClaims(r)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	options, err := h.svc.BeginRegistration(ctx, claims.Subject)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, http.StatusOK, options)
}

func (h *PasskeyHandler) registerFinish(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	cache := h.svc.GetCache()
	if cache == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "passkeys require Redis"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	user, err := h.svc.GetUserRepo().GetByID(ctx, claims.Subject)
	if err != nil || user == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	sessionJSON, err := cache.Get(ctx, "webauthn:reg:"+user.ID)
	if err != nil || sessionJSON == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no registration in progress"})
		return
	}
	_ = cache.Del(ctx, "webauthn:reg:"+user.ID)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	existingCreds, _ := h.svc.GetWebAuthnRepo().GetByUser(ctx, user.ID)
	waUser := &passkeyUser{id: []byte(user.ID), name: user.Email, displayName: user.DisplayName, credentials: existingCreds}

	credential, err := h.svc.GetWA().FinishRegistration(waUser, sessionData, r)
	if err != nil {
		log.Printf("webauthn finish registration error: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "registration failed"})
		return
	}

	friendlyName := r.URL.Query().Get("name")
	if friendlyName == "" {
		friendlyName = "Passkey"
	}

	if err := h.svc.GetWebAuthnRepo().Save(ctx, user.ID, credential, friendlyName); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save credential"})
		return
	}

	uid := user.ID
	h.svc.GetAudit().Log(ctx, client.ID, &uid, "passkey_registered", clientIP(r), r.UserAgent(), nil)
	writeJSON(w, http.StatusCreated, map[string]string{"ok": "true"})
}

func (h *PasskeyHandler) loginBegin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	options, _, err := h.svc.BeginLogin(ctx)
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
	cache := h.svc.GetCache()
	if cache == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "passkeys require Redis"})
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	sessionJSON, err := cache.Get(ctx, "webauthn:login:"+sessionID)
	if err != nil || sessionJSON == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no login in progress"})
		return
	}
	_ = cache.Del(ctx, "webauthn:login:"+sessionID)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	userRepo := h.svc.GetUserRepo()
	waRepo := h.svc.GetWebAuthnRepo()

	userHandler := func(rawID, userHandle []byte) (webauthn.User, error) {
		uid := string(userHandle)
		u, err := userRepo.GetByID(ctx, uid)
		if err != nil || u == nil {
			return nil, err
		}
		creds, _ := waRepo.GetByUser(ctx, uid)
		return &passkeyUser{id: []byte(u.ID), name: u.Email, displayName: u.DisplayName, credentials: creds}, nil
	}

	credential, err := h.svc.GetWA().FinishDiscoverableLogin(userHandler, sessionData, r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
		return
	}

	_ = waRepo.UpdateSignCount(ctx, credential.ID, credential.Authenticator.SignCount)

	userIDStr, err := waRepo.GetUserIDByCredentialID(ctx, credential.ID)
	if err != nil || userIDStr == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}

	user, err := userRepo.GetByID(ctx, userIDStr)
	if err != nil || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return
	}
	if user.Status != "active" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account is suspended"})
		return
	}

	ip := clientIP(r)
	_ = userRepo.UpdateLastLogin(ctx, user.ID)
	uid := user.ID
	h.svc.GetAudit().Log(ctx, client.ID, &uid, "login_success", ip, r.UserAgent(), map[string]interface{}{"method": "passkey"})

	accessToken, err := application.CreateAccessToken(client.JWTSecret, h.cfg.AccessTTL, user)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	refreshToken, err := h.svc.GetSessionRepo().Create(ctx, user.ID, client.ID, ip, r.UserAgent(), h.cfg.RefreshTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	SetRefreshCookie(w, refreshToken, h.cfg.RefreshTTL)
	writeJSON(w, http.StatusOK, application.AuthResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(h.cfg.AccessTTL.Seconds()),
		User:        user,
	})
}

func (h *PasskeyHandler) listOrDelete(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if r.Method == http.MethodGet {
		creds, err := h.svc.ListPasskeys(ctx, claims.Subject)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		writeJSON(w, http.StatusOK, creds)
		return
	}

	if r.Method == http.MethodDelete {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 5 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey ID required"})
			return
		}
		passkeyID := parts[len(parts)-1]
		if err := h.svc.DeletePasskey(ctx, client, passkeyID, claims.Subject, clientIP(r), r.UserAgent()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not delete passkey"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
		return
	}

	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

// passkeyUser implements webauthn.User
type passkeyUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return u.id }
func (u *passkeyUser) WebAuthnName() string                       { return u.name }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }
