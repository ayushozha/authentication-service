package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type EnterpriseOnboardingHandler struct {
	svc *application.EnterpriseOnboardingService
	cfg *HandlerConfig
}

func NewEnterpriseOnboardingHandler(svc *application.EnterpriseOnboardingService, cfg *HandlerConfig) *EnterpriseOnboardingHandler {
	return &EnterpriseOnboardingHandler{svc: svc, cfg: cfg}
}

func (h *EnterpriseOnboardingHandler) RegisterRoutes(mux *http.ServeMux, authMw func(http.HandlerFunc) http.HandlerFunc) {
	if h == nil || h.svc == nil {
		return
	}
	mux.HandleFunc("/api/auth/enterprise-onboarding/providers", CORSHandler(h.cfg.AllowOrigin, authMw(h.handleProviders)))
	mux.HandleFunc("/api/auth/enterprise-onboarding/organizations/", CORSHandler(h.cfg.AllowOrigin, authMw(h.handleOrganizationPath)))
}

func (h *EnterpriseOnboardingHandler) handleProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"providers": application.EnterpriseProviderGuides()})
}

func (h *EnterpriseOnboardingHandler) handleOrganizationPath(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	parts := splitEnterpriseOnboardingPath(r.URL.Path)
	if len(parts) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	organizationID := parts[0]
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		summary, err := h.svc.Summary(ctx, client.ID, organizationID, claims.Subject, h.externalBaseURL(r))
		h.writeResult(w, http.StatusOK, summary, err)
		return
	}

	switch parts[1] {
	case "domains":
		h.handleDomains(w, r, ctx, client.ID, organizationID, claims.Subject, parts)
	case "sso-connections":
		h.handleSSOConnections(w, r, ctx, client, organizationID, claims.Subject, parts)
	case "scim-directories":
		h.handleSCIMDirectories(w, r, ctx, client.ID, organizationID, claims.Subject, parts)
	case "audit-events":
		h.handleAuditEvents(w, r, ctx, client.ID, organizationID, claims.Subject, parts)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (h *EnterpriseOnboardingHandler) handleDomains(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID, organizationID, actorUserID string, parts []string) {
	if len(parts) == 2 {
		switch r.Method {
		case http.MethodGet:
			summary, err := h.svc.Summary(ctx, clientID, organizationID, actorUserID, h.externalBaseURL(r))
			if err != nil {
				writeEnterpriseOnboardingError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"domains": summary.Domains})
		case http.MethodPost:
			var req application.CreateEnterpriseDomainRequest
			if err := decodeEnterpriseOnboardingBody(w, r, &req); err != nil {
				return
			}
			domainVerification, err := h.svc.CreateDomain(ctx, clientID, organizationID, actorUserID, req, clientIP(r), r.UserAgent())
			h.writeResult(w, http.StatusCreated, domainVerification, err)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}
	if len(parts) == 4 && parts[3] == "verify" && r.Method == http.MethodPost {
		domainVerification, err := h.svc.VerifyDomain(ctx, clientID, organizationID, actorUserID, parts[2], clientIP(r), r.UserAgent())
		h.writeResult(w, http.StatusOK, domainVerification, err)
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func (h *EnterpriseOnboardingHandler) handleSSOConnections(w http.ResponseWriter, r *http.Request, ctx context.Context, client *domain.Client, organizationID, actorUserID string, parts []string) {
	if len(parts) == 2 {
		switch r.Method {
		case http.MethodGet:
			connections, err := h.svc.ListSSOConnections(ctx, client.ID, organizationID, actorUserID, h.externalBaseURL(r))
			h.writeResult(w, http.StatusOK, map[string]interface{}{"sso_connections": connections}, err)
		case http.MethodPost:
			var req application.CreateEnterpriseOnboardingSSORequest
			if err := decodeEnterpriseOnboardingBody(w, r, &req); err != nil {
				return
			}
			connection, err := h.svc.CreateSSOConnection(ctx, client.ID, organizationID, actorUserID, req, h.externalBaseURL(r), clientIP(r), r.UserAgent())
			h.writeResult(w, http.StatusCreated, connection, err)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}
	if len(parts) == 3 {
		if r.Method != http.MethodPatch {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req application.UpdateEnterpriseSSOConnectionRequest
		if err := decodeEnterpriseOnboardingBody(w, r, &req); err != nil {
			return
		}
		connection, err := h.svc.UpdateSSOConnection(ctx, client.ID, organizationID, actorUserID, parts[2], req, h.externalBaseURL(r), clientIP(r), r.UserAgent())
		h.writeResult(w, http.StatusOK, connection, err)
		return
	}
	if len(parts) == 4 && parts[3] == "test-sign-in" && r.Method == http.MethodPost {
		redirectURL, err := h.svc.TestSSOSignIn(ctx, client, organizationID, actorUserID, parts[2], h.externalBaseURL(r), clientIP(r), r.UserAgent())
		h.writeResult(w, http.StatusOK, map[string]string{"redirect_url": redirectURL}, err)
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func (h *EnterpriseOnboardingHandler) handleSCIMDirectories(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID, organizationID, actorUserID string, parts []string) {
	if len(parts) == 2 {
		switch r.Method {
		case http.MethodGet:
			directories, err := h.svc.ListSCIMDirectories(ctx, clientID, organizationID, actorUserID, h.externalBaseURL(r))
			h.writeResult(w, http.StatusOK, map[string]interface{}{"scim_directories": directories}, err)
		case http.MethodPost:
			var req application.CreateEnterpriseOnboardingSCIMRequest
			if err := decodeEnterpriseOnboardingBody(w, r, &req); err != nil {
				return
			}
			directory, err := h.svc.CreateSCIMDirectory(ctx, clientID, organizationID, actorUserID, req, h.externalBaseURL(r), clientIP(r), r.UserAgent())
			h.writeResult(w, http.StatusCreated, directory, err)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}
	if len(parts) == 3 {
		if r.Method != http.MethodPatch {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req application.UpdateEnterpriseOnboardingSCIMRequest
		if err := decodeEnterpriseOnboardingBody(w, r, &req); err != nil {
			return
		}
		directory, err := h.svc.UpdateSCIMDirectory(ctx, clientID, organizationID, actorUserID, parts[2], req, h.externalBaseURL(r), clientIP(r), r.UserAgent())
		h.writeResult(w, http.StatusOK, directory, err)
		return
	}
	if len(parts) == 4 && parts[3] == "rotate-token" && r.Method == http.MethodPost {
		directory, err := h.svc.RotateSCIMToken(ctx, clientID, organizationID, actorUserID, parts[2], h.externalBaseURL(r), clientIP(r), r.UserAgent())
		h.writeResult(w, http.StatusOK, directory, err)
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func (h *EnterpriseOnboardingHandler) handleAuditEvents(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID, organizationID, actorUserID string, parts []string) {
	if len(parts) != 2 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a number"})
			return
		}
		limit = parsed
	}
	events, err := h.svc.ListAuditEvents(ctx, clientID, organizationID, actorUserID, limit)
	h.writeResult(w, http.StatusOK, map[string]interface{}{"events": events}, err)
}

func (h *EnterpriseOnboardingHandler) writeResult(w http.ResponseWriter, status int, payload interface{}, err error) {
	if err != nil {
		writeEnterpriseOnboardingError(w, err)
		return
	}
	writeJSON(w, status, payload)
}

func (h *EnterpriseOnboardingHandler) externalBaseURL(r *http.Request) string {
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

func splitEnterpriseOnboardingPath(path string) []string {
	trimmed := strings.Trim(strings.TrimPrefix(path, "/api/auth/enterprise-onboarding/organizations/"), "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func decodeEnterpriseOnboardingBody(w http.ResponseWriter, r *http.Request, out interface{}) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(out); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return err
	}
	return nil
}

func writeEnterpriseOnboardingError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, domain.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	case errors.Is(err, domain.ErrInvalidSSOConnection), errors.Is(err, domain.ErrInvalidSCIMResource), errors.Is(err, domain.ErrInvalidSCIMToken), errors.Is(err, domain.ErrRedisRequired):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "required") || strings.Contains(msg, "invalid") || strings.Contains(msg, "must") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}
