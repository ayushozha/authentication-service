package rest

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(payload)
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
