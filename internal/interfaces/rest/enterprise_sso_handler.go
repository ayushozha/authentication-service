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

type EnterpriseSSOHandler struct {
	svc *application.EnterpriseSSOService
	cfg *HandlerConfig
}

func NewEnterpriseSSOHandler(svc *application.EnterpriseSSOService, cfg *HandlerConfig) *EnterpriseSSOHandler {
	return &EnterpriseSSOHandler{svc: svc, cfg: cfg}
}

func (h *EnterpriseSSOHandler) RegisterAuthRoutes(authMux, publicMux *http.ServeMux) {
	authMux.HandleFunc("/api/auth/sso", CORSHandler(h.cfg.AllowOrigin, h.beginLoginByDomain))
	authMux.HandleFunc("/api/auth/sso/", CORSHandler(h.cfg.AllowOrigin, h.beginLoginByConnection))
	publicMux.HandleFunc("/api/auth/sso/callback/", CORSHandler(h.cfg.AllowOrigin, h.handleCallback))
	publicMux.HandleFunc("/api/auth/sso/metadata/", CORSHandler(h.cfg.AllowOrigin, h.handleMetadata))
}

func (h *EnterpriseSSOHandler) beginLoginByDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	client := GetClient(r)
	if client == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing client"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	redirectURL, err := h.svc.BeginLogin(ctx, client, application.BeginEnterpriseSSOLoginRequest{
		Domain:      r.URL.Query().Get("domain"),
		SessionMode: r.URL.Query().Get("session_mode"),
	}, h.externalBaseURL(r))
	if err != nil {
		h.writeSSOError(w, err)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *EnterpriseSSOHandler) beginLoginByConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	client := GetClient(r)
	if client == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing client"})
		return
	}
	connectionID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auth/sso/"), "/")
	if connectionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "connection ID required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	redirectURL, err := h.svc.BeginLogin(ctx, client, application.BeginEnterpriseSSOLoginRequest{
		ConnectionID: connectionID,
		SessionMode:  r.URL.Query().Get("session_mode"),
	}, h.externalBaseURL(r))
	if err != nil {
		h.writeSSOError(w, err)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *EnterpriseSSOHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	connectionID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auth/sso/callback/"), "/")
	if connectionID == "" {
		http.Redirect(w, r, h.cfg.BaseURL+"/login.html?error=missing_sso_connection", http.StatusFound)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	var (
		resp         *application.AuthResponse
		refreshToken string
		err          error
	)
	if r.FormValue("SAMLResponse") != "" || r.Method == http.MethodPost {
		resp, refreshToken, err = h.svc.HandleSAMLCallback(ctx, r, connectionID, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
	} else {
		resp, refreshToken, err = h.svc.HandleOIDCCallback(ctx, connectionID, r.URL.Query().Get("code"), r.URL.Query().Get("state"), clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
	}
	if err != nil {
		http.Redirect(w, r, h.cfg.BaseURL+"/login.html?error="+err.Error(), http.StatusFound)
		return
	}
	if isTokenSessionMode(r, "") {
		resp.RefreshToken = refreshToken
		writeJSON(w, http.StatusOK, resp)
		return
	}
	SetRefreshCookie(w, refreshToken, h.cfg.RefreshTTL, h.cfg)
	http.Redirect(w, r, h.cfg.BaseURL+"/login.html?access_token="+resp.AccessToken, http.StatusFound)
}

func (h *EnterpriseSSOHandler) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	connectionID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auth/sso/metadata/"), "/")
	if connectionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "connection ID required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	metadata, err := h.svc.SAMLMetadata(ctx, connectionID)
	if err != nil {
		h.writeSSOError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(metadata)
}

func (h *EnterpriseSSOHandler) handleAdminConnections(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID string, parts []string) {
	if h.svc == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	switch len(parts) {
	case 6:
		switch r.Method {
		case http.MethodGet:
			connections, err := h.svc.ListConnections(ctx, clientID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			writeJSON(w, http.StatusOK, sanitizeSSOConnections(connections))
		case http.MethodPost:
			var req application.CreateEnterpriseSSOConnectionRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
				return
			}
			connection, err := h.svc.CreateConnection(ctx, clientID, req, h.externalBaseURL(r))
			if err != nil {
				h.writeSSOError(w, err)
				return
			}
			writeJSON(w, http.StatusCreated, sanitizeSSOConnection(connection))
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	case 7:
		connectionID := parts[6]
		switch r.Method {
		case http.MethodGet:
			connection, err := h.svc.GetConnection(ctx, clientID, connectionID)
			if err != nil {
				h.writeSSOError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, sanitizeSSOConnection(connection))
		case http.MethodPatch:
			var req application.UpdateEnterpriseSSOConnectionRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
				return
			}
			connection, err := h.svc.UpdateConnection(ctx, clientID, connectionID, req, h.externalBaseURL(r))
			if err != nil {
				h.writeSSOError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, sanitizeSSOConnection(connection))
		case http.MethodDelete:
			if err := h.svc.DeactivateConnection(ctx, clientID, connectionID); err != nil {
				h.writeSSOError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (h *EnterpriseSSOHandler) externalBaseURL(r *http.Request) string {
	if h.cfg != nil && strings.TrimSpace(h.cfg.BaseURL) != "" {
		return strings.TrimRight(h.cfg.BaseURL, "/")
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = forwarded
	}
	return scheme + "://" + r.Host
}

func (h *EnterpriseSSOHandler) writeSSOError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, domain.ErrRedisRequired):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "enterprise sso requires Redis"})
	case errors.Is(err, domain.ErrInvalidClient), errors.Is(err, domain.ErrInvalidToken), errors.Is(err, domain.ErrInvalidSSOConnection):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, domain.ErrSSODomainNotAllowed), errors.Is(err, domain.ErrAccountSuspended):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}

func sanitizeSSOConnections(connections []*domain.EnterpriseSSOConnection) []*domain.EnterpriseSSOConnection {
	out := make([]*domain.EnterpriseSSOConnection, 0, len(connections))
	for _, connection := range connections {
		out = append(out, sanitizeSSOConnection(connection))
	}
	return out
}

func sanitizeSSOConnection(connection *domain.EnterpriseSSOConnection) *domain.EnterpriseSSOConnection {
	if connection == nil {
		return nil
	}
	clone := *connection
	clone.Domains = append([]string(nil), connection.Domains...)
	clone.AttributeMapping = map[string]string{}
	for key, value := range connection.AttributeMapping {
		clone.AttributeMapping[key] = value
	}
	clone.OIDC.ClientSecret = ""
	clone.SAML.SPPrivateKeyPEM = ""
	return &clone
}
