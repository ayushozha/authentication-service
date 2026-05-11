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
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	client := GetClient(r)
	if client == nil {
		writeError(w, r, http.StatusUnauthorized, "missing_client", "Missing client.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	redirectURL, err := h.svc.BeginLogin(ctx, client, application.BeginEnterpriseSSOLoginRequest{
		Domain:      r.URL.Query().Get("domain"),
		SessionMode: r.URL.Query().Get("session_mode"),
	}, h.externalBaseURL(r))
	if err != nil {
		application.Metrics().ObserveSSOError("begin_domain", err)
		h.writeSSOError(w, r, err)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *EnterpriseSSOHandler) beginLoginByConnection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	client := GetClient(r)
	if client == nil {
		writeError(w, r, http.StatusUnauthorized, "missing_client", "Missing client.")
		return
	}
	connectionID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auth/sso/"), "/")
	if connectionID == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Connection ID required.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	redirectURL, err := h.svc.BeginLogin(ctx, client, application.BeginEnterpriseSSOLoginRequest{
		ConnectionID: connectionID,
		SessionMode:  r.URL.Query().Get("session_mode"),
	}, h.externalBaseURL(r))
	if err != nil {
		application.Metrics().ObserveSSOError("begin_connection", err)
		h.writeSSOError(w, r, err)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *EnterpriseSSOHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	connectionID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auth/sso/callback/"), "/")
	if connectionID == "" {
		redirectWithLoginAuthError(w, r, h.cfg, "AUTH_SSO_FAILED")
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
		application.Metrics().ObserveSSOError("callback", err)
		redirectWithLoginAuthError(w, r, h.cfg, authCodeForSSOError(err))
		return
	}
	tokenMode := isTokenSessionMode(r, resp.SessionMode)
	if tokenMode && strings.Contains(r.Header.Get("Accept"), "application/json") {
		resp.RefreshToken = refreshToken
		writeJSON(w, http.StatusOK, resp)
		return
	}
	if !tokenMode {
		SetRefreshCookie(w, refreshToken, h.cfg.RefreshTTL, h.cfg)
	}
	redirectWithAuthCode(w, r, h.cfg, resp, refreshToken, tokenMode)
}

func (h *EnterpriseSSOHandler) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	connectionID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auth/sso/metadata/"), "/")
	if connectionID == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "Connection ID required.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	metadata, err := h.svc.SAMLMetadata(ctx, connectionID)
	if err != nil {
		application.Metrics().ObserveSSOError("metadata", err)
		h.writeSSOError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(metadata)
}

func (h *EnterpriseSSOHandler) handleAdminConnections(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID string, parts []string) {
	if h.svc == nil {
		writeError(w, r, http.StatusNotFound, "invalid_sso_connection", "SSO connection not found.")
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
			SetAdminAuditAfter(r, map[string]interface{}{"count": len(connections)})
			writeJSON(w, http.StatusOK, sanitizeSSOConnections(connections))
		case http.MethodPost:
			var req application.CreateEnterpriseSSOConnectionRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
				writeError(w, r, http.StatusBadRequest, "invalid_request_body", "Invalid request body.")
				return
			}
			connection, err := h.svc.CreateConnection(ctx, clientID, req, h.externalBaseURL(r))
			if err != nil {
				h.writeSSOError(w, r, err)
				return
			}
			SetAdminAuditTarget(r, "sso_connection", connection.ID, clientID)
			SetAdminAuditAfter(r, safeSSOConnectionMetadata(connection))
			writeJSON(w, http.StatusCreated, sanitizeSSOConnection(connection))
		default:
			writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		}
	case 7:
		connectionID := parts[6]
		switch r.Method {
		case http.MethodGet:
			connection, err := h.svc.GetConnection(ctx, clientID, connectionID)
			if err != nil {
				h.writeSSOError(w, r, err)
				return
			}
			SetAdminAuditAfter(r, safeSSOConnectionMetadata(connection))
			writeJSON(w, http.StatusOK, sanitizeSSOConnection(connection))
		case http.MethodPatch:
			before, _ := h.svc.GetConnection(ctx, clientID, connectionID)
			SetAdminAuditBefore(r, safeSSOConnectionMetadata(before))
			var req application.UpdateEnterpriseSSOConnectionRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
				writeError(w, r, http.StatusBadRequest, "invalid_request_body", "Invalid request body.")
				return
			}
			connection, err := h.svc.UpdateConnection(ctx, clientID, connectionID, req, h.externalBaseURL(r))
			if err != nil {
				h.writeSSOError(w, r, err)
				return
			}
			SetAdminAuditAfter(r, safeSSOConnectionMetadata(connection))
			writeJSON(w, http.StatusOK, sanitizeSSOConnection(connection))
		case http.MethodDelete:
			before, _ := h.svc.GetConnection(ctx, clientID, connectionID)
			SetAdminAuditBefore(r, safeSSOConnectionMetadata(before))
			if err := h.svc.DeactivateConnection(ctx, clientID, connectionID); err != nil {
				h.writeSSOError(w, r, err)
				return
			}
			SetAdminAuditAfter(r, map[string]interface{}{"connection_id": connectionID, "status": domain.SSOConnectionStatusInactive})
			w.WriteHeader(http.StatusNoContent)
		default:
			writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		}
	default:
		writeError(w, r, http.StatusNotFound, "invalid_sso_connection", "SSO connection not found.")
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

func (h *EnterpriseSSOHandler) writeSSOError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "invalid_sso_connection", "SSO connection not found.")
	case errors.Is(err, domain.ErrRedisRequired):
		writeError(w, r, http.StatusServiceUnavailable, "redis_required", "Enterprise SSO requires Redis.")
	case errors.Is(err, domain.ErrInvalidClient):
		writeError(w, r, http.StatusBadRequest, "invalid_client", "Invalid SSO client.")
	case errors.Is(err, domain.ErrInvalidToken), errors.Is(err, domain.ErrInvalidSSOConnection):
		writeError(w, r, http.StatusBadRequest, "sso_failed", "Could not complete SSO.")
	case errors.Is(err, domain.ErrSSODomainNotAllowed):
		writeError(w, r, http.StatusForbidden, "sso_failed", "Could not complete SSO.")
	case errors.Is(err, domain.ErrAccountSuspended):
		writeError(w, r, http.StatusForbidden, "account_suspended", "Account is suspended.")
	default:
		writeError(w, r, http.StatusInternalServerError, "internal_error", "Internal error.")
	}
}

func authCodeForSSOError(err error) string {
	switch {
	case errors.Is(err, domain.ErrAccountSuspended):
		return "AUTH_ACCOUNT_DISABLED"
	case errors.Is(err, domain.ErrRedisRequired):
		return "AUTH_SERVICE_UNAVAILABLE"
	case errors.Is(err, domain.ErrInvalidClient):
		return "AUTH_SERVICE_UNAVAILABLE"
	default:
		return "AUTH_SSO_FAILED"
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

func safeSSOConnectionMetadata(connection *domain.EnterpriseSSOConnection) map[string]interface{} {
	if connection == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"id":              connection.ID,
		"client_id":       connection.ClientID,
		"organization_id": connection.OrganizationID,
		"name":            connection.Name,
		"slug":            connection.Slug,
		"provider":        connection.Provider,
		"protocol":        connection.Protocol,
		"status":          connection.Status,
		"domains":         connection.Domains,
	}
}
