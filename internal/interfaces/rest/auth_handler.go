package rest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type AuthHandler struct {
	authSvc *application.AuthService
	cfg     *HandlerConfig
}

type HandlerConfig struct {
	AllowOrigin    string
	BaseURL        string
	Cache          application.CacheClient
	BcryptCost     int
	AccessTTL      time.Duration
	RefreshTTL     time.Duration
	CookieSecure   bool
	CookieSameSite string
	CookieDomain   string
}

func NewAuthHandler(authSvc *application.AuthService, cfg *HandlerConfig) *AuthHandler {
	return &AuthHandler{authSvc: authSvc, cfg: cfg}
}

func (h *AuthHandler) RegisterRoutes(mux *http.ServeMux, authMw func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("/api/auth/signup", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.signup)))
	mux.HandleFunc("/api/auth/login", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.login)))
	mux.HandleFunc("/api/auth/refresh", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.refresh)))
	mux.HandleFunc("/api/auth/logout", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.logout)))
	mux.HandleFunc("/api/auth/me", CORSHandler(h.cfg.AllowOrigin, authMw(h.me)))
	mux.HandleFunc("/api/auth/sessions", CORSHandler(h.cfg.AllowOrigin, authMw(h.sessions)))
	mux.HandleFunc("/api/auth/sessions/", CORSHandler(h.cfg.AllowOrigin, authMw(h.sessionByID)))
	mux.HandleFunc("/api/auth/change-password", CORSHandler(h.cfg.AllowOrigin, authMw(MethodCheck(http.MethodPost, h.changePassword))))
}

func (h *AuthHandler) signup(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	if client == nil {
		writeError(w, r, http.StatusUnauthorized, "missing_client", "Missing client.")
		return
	}

	var req application.SignupRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request_body", "Invalid request body.")
		return
	}
	transport := tokenTransport(r, req.TokenTransport, req.SessionMode)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, refreshToken, err := h.authSvc.Signup(ctx, client, req, clientIP(r), r.UserAgent(), h.cfg.BcryptCost, h.cfg.AccessTTL, h.cfg.RefreshTTL)
	if err != nil {
		switch err {
		case domain.ErrDuplicateEmail:
			writeError(w, r, http.StatusConflict, "duplicate_email", err.Error())
		case domain.ErrRateLimit:
			w.Header().Set("Retry-After", "3600")
			writeError(w, r, http.StatusTooManyRequests, "rate_limited", err.Error())
		case domain.ErrBotVerification:
			writeError(w, r, http.StatusBadRequest, "bot_verification_failed", err.Error())
		case domain.ErrSSORequired:
			writeError(w, r, http.StatusForbidden, "sso_required", err.Error())
		default:
			writeError(w, r, http.StatusBadRequest, "invalid_signup", err.Error())
		}
		return
	}

	h.applyRefreshTransport(w, resp, refreshToken, transport)

	writeJSON(w, http.StatusCreated, resp)
}

func (h *AuthHandler) login(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	if client == nil {
		writeError(w, r, http.StatusUnauthorized, "missing_client", "Missing client.")
		return
	}

	var req struct {
		Email          string `json:"email"`
		Password       string `json:"password"`
		SessionMode    string `json:"session_mode"`
		TokenTransport string `json:"token_transport"`
		CaptchaToken   string `json:"captcha_token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request_body", "Invalid request body.")
		return
	}
	transport := tokenTransport(r, req.TokenTransport, req.SessionMode)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, refreshToken, err := h.authSvc.Login(ctx, client, application.LoginRequest{
		Email:        req.Email,
		Password:     req.Password,
		CaptchaToken: req.CaptchaToken,
	}, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
	if err != nil {
		switch err {
		case domain.ErrBotVerification:
			writeError(w, r, http.StatusBadRequest, "bot_verification_failed", err.Error())
		case domain.ErrInvalidEmail:
			writeError(w, r, http.StatusBadRequest, "invalid_email", err.Error())
		case domain.ErrInvalidPassword:
			writeError(w, r, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password.")
		case domain.ErrAccountSuspended:
			writeError(w, r, http.StatusForbidden, "account_suspended", err.Error())
		case domain.ErrSSORequired:
			writeError(w, r, http.StatusForbidden, "sso_required", err.Error())
		case domain.ErrSecurityPolicyBlocked:
			writeError(w, r, http.StatusForbidden, "security_policy_blocked", err.Error())
		case domain.ErrStepUpEnrollmentRequired:
			writeError(w, r, http.StatusForbidden, "step_up_enrollment_required", err.Error())
		case domain.ErrAccountLocked:
			w.Header().Set("Retry-After", "1800")
			writeError(w, r, http.StatusTooManyRequests, "account_locked", "Account temporarily locked, try again in 30 minutes.")
		case domain.ErrRateLimit:
			w.Header().Set("Retry-After", "900")
			writeError(w, r, http.StatusTooManyRequests, "rate_limited", err.Error())
		case domain.ErrRedisRequired:
			writeError(w, r, http.StatusServiceUnavailable, "redis_required", "2FA requires Redis.")
		default:
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		}
		return
	}

	h.applyRefreshTransport(w, resp, refreshToken, transport)

	writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) applyRefreshTransport(w http.ResponseWriter, resp *application.AuthResponse, refreshToken, transport string) {
	applyRefreshTransport(w, h.cfg, resp, refreshToken, transport)
}

func (h *AuthHandler) refresh(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	if client == nil {
		writeError(w, r, http.StatusUnauthorized, "missing_client", "Missing client.")
		return
	}

	var body struct {
		RefreshToken      string `json:"refresh_token"`
		RefreshTokenCamel string `json:"refreshToken"`
		SessionMode       string `json:"session_mode"`
		TokenTransport    string `json:"token_transport"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil && err != io.EOF {
		writeError(w, r, http.StatusBadRequest, "invalid_request_body", "Invalid request body.")
		return
	}
	transport := tokenTransport(r, body.TokenTransport, body.SessionMode)

	rawRefreshToken := strings.TrimSpace(body.RefreshToken)
	if rawRefreshToken == "" {
		rawRefreshToken = strings.TrimSpace(body.RefreshTokenCamel)
	}
	usedCookie := false
	if rawRefreshToken == "" {
		cookie, err := r.Cookie(refreshCookieName)
		if err == nil {
			rawRefreshToken = strings.TrimSpace(cookie.Value)
			usedCookie = rawRefreshToken != ""
		}
	}

	if rawRefreshToken == "" {
		writeError(w, r, http.StatusBadRequest, "refresh_token_missing", "Refresh token missing. Send refresh_token in JSON mode or include the auth_refresh cookie in cookie mode.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, newRefreshToken, err := h.authSvc.Refresh(ctx, client, rawRefreshToken, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
	if err != nil {
		if usedCookie {
			ClearRefreshCookie(w, h.cfg)
		}
		if err == domain.ErrInvalidToken {
			writeError(w, r, http.StatusUnauthorized, "invalid_refresh_token", "Invalid or expired refresh token.")
		} else {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
		}
		return
	}

	h.applyRefreshTransport(w, resp, newRefreshToken, transport)
	writeJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) logout(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	if client == nil {
		writeError(w, r, http.StatusUnauthorized, "missing_client", "Missing client.")
		return
	}
	var body struct {
		RefreshToken      string `json:"refresh_token"`
		RefreshTokenCamel string `json:"refreshToken"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)

	rawRefreshToken := strings.TrimSpace(body.RefreshToken)
	if rawRefreshToken == "" {
		rawRefreshToken = strings.TrimSpace(body.RefreshTokenCamel)
	}
	cookie, err := r.Cookie(refreshCookieName)
	if err == nil {
		rawRefreshToken = cookie.Value
	}
	if rawRefreshToken != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		_ = h.authSvc.Logout(ctx, client.ID, rawRefreshToken)
	}
	ClearRefreshCookie(w, h.cfg)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *AuthHandler) me(w http.ResponseWriter, r *http.Request) {
	claims := GetUserClaims(r)
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if r.Method == http.MethodGet {
		user, err := h.authSvc.GetUser(ctx, claims.Subject)
		if err != nil || user == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, http.StatusOK, user)
		return
	}

	if r.Method == http.MethodPatch {
		var req application.UpdateProfileRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		user, err := h.authSvc.UpdateProfile(ctx, claims.Subject, req)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update profile"})
			return
		}
		writeJSON(w, http.StatusOK, user)
		return
	}

	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func (h *AuthHandler) sessions(w http.ResponseWriter, r *http.Request) {
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
		sessions, err := h.authSvc.ListSessions(ctx, client, claims.Subject)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not list sessions"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"sessions": sessions})
	case http.MethodDelete:
		if err := h.authSvc.RevokeAllSessions(ctx, client, claims.Subject, clientIP(r), r.UserAgent()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke sessions"})
			return
		}
		ClearRefreshCookie(w, h.cfg)
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *AuthHandler) sessionByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	sessionID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auth/sessions/"), "/")
	if sessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.authSvc.RevokeSession(ctx, client, claims.Subject, sessionID, clientIP(r), r.UserAgent()); err != nil {
		if err == domain.ErrNotFound {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not revoke session"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *AuthHandler) changePassword(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)

	var req application.ChangePasswordRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := h.authSvc.ChangePassword(ctx, client, claims.Subject, req, clientIP(r), r.UserAgent(), h.cfg.BcryptCost); err != nil {
		if err == domain.ErrNotFound {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		} else if err == domain.ErrSSORequired {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}
