package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type ClientHandler struct {
	svc      *application.ClientService
	adaptive *application.AdaptiveSecurityService
	m2m      *M2MHandler
	sso      *EnterpriseSSOHandler
	scim     *SCIMHandler
}

func NewClientHandler(svc *application.ClientService, adaptive *application.AdaptiveSecurityService, m2m *M2MHandler, sso *EnterpriseSSOHandler, scim *SCIMHandler) *ClientHandler {
	return &ClientHandler{svc: svc, adaptive: adaptive, m2m: m2m, sso: sso, scim: scim}
}

func (h *ClientHandler) RegisterRoutes(mux *http.ServeMux, adminMw func(http.Handler) http.Handler) {
	mux.Handle("/api/admin/clients", adminMw(http.HandlerFunc(h.handleClients)))
	mux.Handle("/api/admin/clients/", adminMw(http.HandlerFunc(h.handleClientByID)))
}

func (h *ClientHandler) handleClients(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w, "*", false)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if r.Method == http.MethodPost {
		var req application.CreateClientRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		resp, err := h.svc.CreateClient(ctx, req)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		SetAdminAuditTarget(r, "client", resp.Client.ID, resp.Client.ID)
		SetAdminAuditAfter(r, safeClientMetadata(resp.Client))
		writeJSON(w, http.StatusCreated, resp)
		return
	}

	if r.Method == http.MethodGet {
		if scopedID := scopedClientID(GetAdminActor(r)); scopedID != "" {
			client, err := h.svc.GetClient(ctx, scopedID)
			if err != nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "client not found"})
				return
			}
			SetAdminAuditAfter(r, map[string]interface{}{"count": 1, "scoped": true})
			writeJSON(w, http.StatusOK, []*domain.Client{client})
			return
		}
		clients, err := h.svc.ListClients(ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		SetAdminAuditAfter(r, map[string]interface{}{"count": len(clients)})
		writeJSON(w, http.StatusOK, clients)
		return
	}

	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func (h *ClientHandler) handleClientByID(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w, "*", false)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	// /api/admin/clients/{id} or /api/admin/clients/{id}/rotate-jwt|rotate-secret or /api/admin/clients/{id}/rotate-key|rotate-api-key
	if len(parts) < 5 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "client ID required"})
		return
	}
	clientID := parts[4]

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if len(parts) == 6 && parts[5] == "security-policy" {
		h.handleSecurityPolicy(w, r, ctx, clientID)
		return
	}
	if len(parts) >= 6 && parts[5] == "service-accounts" {
		if h.m2m == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		h.m2m.handleAdminServiceAccounts(w, r, ctx, clientID, parts)
		return
	}
	if len(parts) >= 6 && parts[5] == "sso-connections" {
		if h.sso == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		h.sso.handleAdminConnections(w, r, ctx, clientID, parts)
		return
	}
	if len(parts) >= 6 && parts[5] == "scim-directories" {
		if h.scim == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		h.scim.handleAdminDirectories(w, r, ctx, clientID, parts)
		return
	}

	// Check for rotate actions
	if len(parts) >= 6 {
		action := parts[5]
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		switch action {
		case "rotate-jwt", "rotate-secret":
			if !h.requireAdminAction(w, r, ctx, clientID, domain.SecurityActionClientKeyRotate) {
				return
			}
			before, _ := h.svc.GetClient(ctx, clientID)
			SetAdminAuditBefore(r, safeClientMetadata(before))
			newSecret, client, err := h.svc.RotateJWTSecret(ctx, clientID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			SetAdminAuditAfter(r, map[string]interface{}{"client": safeClientMetadata(client), "jwt_secret_rotated": true})
			writeJSON(w, http.StatusOK, map[string]interface{}{"client": client, "jwt_secret": newSecret})
		case "rotate-key", "rotate-api-key":
			if !h.requireAdminAction(w, r, ctx, clientID, domain.SecurityActionClientKeyRotate) {
				return
			}
			before, _ := h.svc.GetClient(ctx, clientID)
			SetAdminAuditBefore(r, safeClientMetadata(before))
			newKey, client, err := h.svc.RotateAPIKey(ctx, clientID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			SetAdminAuditAfter(r, map[string]interface{}{"client": safeClientMetadata(client), "api_key_rotated": true})
			writeJSON(w, http.StatusOK, map[string]interface{}{"client": client, "api_key": newKey})
		default:
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown action"})
		}
		return
	}

	if r.Method == http.MethodGet {
		client, err := h.svc.GetClient(ctx, clientID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "client not found"})
			return
		}
		SetAdminAuditAfter(r, safeClientMetadata(client))
		writeJSON(w, http.StatusOK, client)
		return
	}

	if r.Method == http.MethodPatch {
		before, _ := h.svc.GetClient(ctx, clientID)
		SetAdminAuditBefore(r, safeClientMetadata(before))
		var req application.UpdateClientRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		client, err := h.svc.UpdateClient(ctx, clientID, req)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "client not found"})
			return
		}
		SetAdminAuditAfter(r, safeClientMetadata(client))
		writeJSON(w, http.StatusOK, client)
		return
	}

	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func (h *ClientHandler) handleSecurityPolicy(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID string) {
	switch r.Method {
	case http.MethodGet:
		client, err := h.svc.GetClient(ctx, clientID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "client not found"})
			return
		}
		policy := application.DefaultAdaptiveSecurityPolicy()
		if h.adaptive != nil {
			policy = h.adaptive.ClientPolicy(client)
		}
		writeJSON(w, http.StatusOK, policy)
	case http.MethodPut, http.MethodPatch:
		if !h.requireAdminAction(w, r, ctx, clientID, domain.SecurityActionClientKeyRotate) {
			return
		}
		var policy domain.AdaptiveSecurityPolicy
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&policy); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		client, err := h.svc.GetClient(ctx, clientID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "client not found"})
			return
		}
		if client.Settings == nil {
			client.Settings = map[string]interface{}{}
		}
		normalized := application.NormalizeAdaptiveSecurityPolicy(policy)
		settings := make(map[string]interface{}, len(client.Settings)+1)
		for key, value := range client.Settings {
			settings[key] = value
		}
		settings["adaptive_security"] = normalized
		client, err = h.svc.UpdateClient(ctx, clientID, application.UpdateClientRequest{Settings: settings})
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "client not found"})
			return
		}
		SetAdminAuditAfter(r, map[string]interface{}{"client": safeClientMetadata(client), "adaptive_security": normalized})
		writeJSON(w, http.StatusOK, normalized)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *ClientHandler) requireAdminAction(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID, action string) bool {
	if h.adaptive == nil {
		return true
	}
	decision, err := h.adaptive.EvaluateAdminAction(ctx, clientID, action, GetAdminActor(r), stepUpTokenFromRequest(r), clientIP(r), r.UserAgent())
	if err != nil {
		writeAdaptiveSecurityError(w, r, err)
		return false
	}
	if decision != nil && (decision.Blocked || decision.StepUpRequired) {
		writeAdaptiveActionDecision(w, decision)
		return false
	}
	return true
}
