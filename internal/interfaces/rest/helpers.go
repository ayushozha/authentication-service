package rest

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/Ayush10/authentication-service/internal/application"
)

const refreshCookieName = "auth_refresh"

type errorPayload struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(payload)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	if message == "" {
		message = code
	}
	payload := errorPayload{
		Error:   message,
		Code:    code,
		Message: message,
	}
	if r != nil {
		payload.RequestID = strings.TrimSpace(r.Header.Get("X-Request-ID"))
	}
	writeJSON(w, status, payload)
}

func clientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func setCorsHeaders(w http.ResponseWriter, origin string, allowCredentials bool) {
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Admin-Key, X-Request-ID, X-Step-Up-Token")
	if allowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
}

func isTokenSessionMode(r *http.Request, requestedMode string) bool {
	mode := strings.ToLower(strings.TrimSpace(requestedMode))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("session_mode")))
	}
	return mode == "token"
}

func tokenTransport(r *http.Request, requestedTransport, requestedSessionMode string) string {
	transport := strings.ToLower(strings.TrimSpace(requestedTransport))
	if transport == "" && r != nil {
		transport = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("token_transport")))
	}
	switch transport {
	case "json", "cookie":
		return transport
	}
	if isTokenSessionMode(r, requestedSessionMode) {
		return "json"
	}
	return "cookie"
}

func isJSONTokenTransport(r *http.Request, requestedTransport, requestedSessionMode string) bool {
	return tokenTransport(r, requestedTransport, requestedSessionMode) == "json"
}

func applyRefreshTransport(w http.ResponseWriter, cfg *HandlerConfig, resp *application.AuthResponse, refreshToken, transport string) {
	if cfg == nil || resp == nil || refreshToken == "" {
		return
	}
	expiresIn := int(cfg.RefreshTTL.Seconds())
	if transport == "json" {
		resp.RefreshToken = refreshToken
		resp.Refresh = &application.RefreshInfo{Transport: "json", ExpiresIn: expiresIn}
		return
	}
	SetRefreshCookie(w, refreshToken, cfg.RefreshTTL, cfg)
	resp.Refresh = &application.RefreshInfo{Transport: "cookie", CookieName: refreshCookieName, ExpiresIn: expiresIn}
}
