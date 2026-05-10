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

type OrganizationHandler struct {
	svc      *application.OrganizationService
	adaptive *application.AdaptiveSecurityService
	cfg      *HandlerConfig
}

type organizationTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func NewOrganizationHandler(svc *application.OrganizationService, args ...interface{}) *OrganizationHandler {
	var adaptive *application.AdaptiveSecurityService
	var cfg *HandlerConfig
	for _, arg := range args {
		switch value := arg.(type) {
		case *application.AdaptiveSecurityService:
			adaptive = value
		case *HandlerConfig:
			cfg = value
		}
	}
	return &OrganizationHandler{svc: svc, adaptive: adaptive, cfg: cfg}
}

func (h *OrganizationHandler) RegisterRoutes(mux *http.ServeMux, authMw func(http.HandlerFunc) http.HandlerFunc) {
	if h == nil || h.svc == nil {
		return
	}
	mux.HandleFunc("/api/auth/organizations", CORSHandler(h.cfg.AllowOrigin, authMw(h.handleOrganizations)))
	mux.HandleFunc("/api/auth/organizations/", CORSHandler(h.cfg.AllowOrigin, authMw(h.handleOrganizationPath)))
	mux.HandleFunc("/api/auth/organization-invitations/accept", CORSHandler(h.cfg.AllowOrigin, authMw(h.acceptInvitation)))
}

func (h *OrganizationHandler) handleOrganizations(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	switch r.Method {
	case http.MethodGet:
		orgs, err := h.svc.ListOrganizations(ctx, client.ID, claims.Subject)
		if err != nil {
			writeOrganizationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"organizations": orgs})
	case http.MethodPost:
		var req application.CreateOrganizationRequest
		if err := decodeOrganizationBody(w, r, &req); err != nil {
			return
		}
		org, err := h.svc.CreateOrganization(ctx, client.ID, claims.Subject, req, clientIP(r), r.UserAgent())
		if err != nil {
			writeOrganizationError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, org)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *OrganizationHandler) handleOrganizationPath(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	parts := splitOrganizationPath(r.URL.Path)
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	organizationID := parts[0]

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if len(parts) == 1 {
		h.handleOrganization(w, r, ctx, client, organizationID, claims.Subject)
		return
	}

	switch parts[1] {
	case "authorization":
		h.handleAuthorization(w, r, ctx, client.ID, organizationID, claims.Subject, parts)
	case "members":
		h.handleMembers(w, r, ctx, client, organizationID, claims.Subject, parts)
	case "invitations":
		h.handleInvitations(w, r, ctx, client.ID, organizationID, claims.Subject, parts)
	case "token":
		h.issueOrganizationToken(w, r, ctx, client, organizationID, claims.Subject, parts)
	case "security-policy":
		h.handleSecurityPolicy(w, r, ctx, client, organizationID, claims.Subject, parts)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (h *OrganizationHandler) handleAuthorization(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID, organizationID, actorUserID string, parts []string) {
	if len(parts) < 3 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	switch parts[2] {
	case "policy":
		if len(parts) != 3 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			policy, err := h.svc.GetAuthorizationPolicy(ctx, clientID, organizationID, actorUserID)
			if err != nil {
				writeOrganizationError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, policy)
		case http.MethodPut, http.MethodPatch:
			var req application.UpdateAuthorizationPolicyRequest
			if err := decodeOrganizationBody(w, r, &req); err != nil {
				return
			}
			policy, err := h.svc.UpdateAuthorizationPolicy(ctx, clientID, organizationID, actorUserID, req, clientIP(r), r.UserAgent())
			if err != nil {
				writeOrganizationError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, policy)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	case "group-mappings":
		h.handleAuthorizationGroupMappings(w, r, ctx, clientID, organizationID, actorUserID, parts)
	case "simulate":
		if len(parts) != 3 || r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		var req application.AuthorizationSimulationRequest
		if err := decodeOrganizationBody(w, r, &req); err != nil {
			return
		}
		decision, err := h.svc.SimulateAuthorization(ctx, clientID, organizationID, actorUserID, req)
		if err != nil {
			writeOrganizationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, decision)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (h *OrganizationHandler) handleAuthorizationGroupMappings(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID, organizationID, actorUserID string, parts []string) {
	if len(parts) == 3 {
		switch r.Method {
		case http.MethodGet:
			mappings, err := h.svc.ListGroupMappings(ctx, clientID, organizationID, actorUserID)
			if err != nil {
				writeOrganizationError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"group_mappings": mappings})
		case http.MethodPost:
			var req application.UpsertGroupMappingRequest
			if err := decodeOrganizationBody(w, r, &req); err != nil {
				return
			}
			mapping, err := h.svc.UpsertGroupMapping(ctx, clientID, organizationID, actorUserID, "", req, clientIP(r), r.UserAgent())
			if err != nil {
				writeOrganizationError(w, err)
				return
			}
			writeJSON(w, http.StatusCreated, mapping)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}
	if len(parts) != 4 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	mappingID := parts[3]
	switch r.Method {
	case http.MethodPatch, http.MethodPut:
		var req application.UpsertGroupMappingRequest
		if err := decodeOrganizationBody(w, r, &req); err != nil {
			return
		}
		mapping, err := h.svc.UpsertGroupMapping(ctx, clientID, organizationID, actorUserID, mappingID, req, clientIP(r), r.UserAgent())
		if err != nil {
			writeOrganizationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, mapping)
	case http.MethodDelete:
		if err := h.svc.DeleteGroupMapping(ctx, clientID, organizationID, actorUserID, mappingID, clientIP(r), r.UserAgent()); err != nil {
			writeOrganizationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *OrganizationHandler) handleOrganization(w http.ResponseWriter, r *http.Request, ctx context.Context, client *domain.Client, organizationID, actorUserID string) {
	switch r.Method {
	case http.MethodGet:
		org, err := h.svc.GetOrganization(ctx, client.ID, organizationID, actorUserID)
		if err != nil {
			writeOrganizationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, org)
	case http.MethodPatch:
		var req application.UpdateOrganizationRequest
		if err := decodeOrganizationBody(w, r, &req); err != nil {
			return
		}
		if !h.requireStepUp(w, r, ctx, client, organizationID, actorUserID, domain.SecurityActionOrganizationUpdate) {
			return
		}
		org, err := h.svc.UpdateOrganization(ctx, client.ID, organizationID, actorUserID, req, clientIP(r), r.UserAgent())
		if err != nil {
			writeOrganizationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, org)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *OrganizationHandler) handleMembers(w http.ResponseWriter, r *http.Request, ctx context.Context, client *domain.Client, organizationID, actorUserID string, parts []string) {
	if len(parts) == 2 {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		members, err := h.svc.ListMembers(ctx, client.ID, organizationID, actorUserID)
		if err != nil {
			writeOrganizationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"members": members})
		return
	}
	if len(parts) != 3 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	targetUserID := parts[2]
	switch r.Method {
	case http.MethodPatch:
		var req application.UpdateOrganizationMemberRequest
		if err := decodeOrganizationBody(w, r, &req); err != nil {
			return
		}
		if !h.requireStepUp(w, r, ctx, client, organizationID, actorUserID, domain.SecurityActionOrganizationMemberRole) {
			return
		}
		member, err := h.svc.UpdateMember(ctx, client.ID, organizationID, targetUserID, actorUserID, req, clientIP(r), r.UserAgent())
		if err != nil {
			writeOrganizationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, member)
	case http.MethodDelete:
		if !h.requireStepUp(w, r, ctx, client, organizationID, actorUserID, domain.SecurityActionOrganizationMemberRemove) {
			return
		}
		if err := h.svc.RemoveMember(ctx, client.ID, organizationID, targetUserID, actorUserID, clientIP(r), r.UserAgent()); err != nil {
			writeOrganizationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *OrganizationHandler) handleSecurityPolicy(w http.ResponseWriter, r *http.Request, ctx context.Context, client *domain.Client, organizationID, actorUserID string, parts []string) {
	if len(parts) != 2 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		if _, err := h.svc.GetOrganization(ctx, client.ID, organizationID, actorUserID); err != nil {
			writeOrganizationError(w, err)
			return
		}
		policy := application.DefaultAdaptiveSecurityPolicy()
		if h.adaptive != nil {
			policy = h.adaptive.OrganizationPolicy(ctx, client, organizationID)
		}
		writeJSON(w, http.StatusOK, policy)
	case http.MethodPut, http.MethodPatch:
		var req domain.AdaptiveSecurityPolicy
		if err := decodeOrganizationBody(w, r, &req); err != nil {
			return
		}
		if !h.requireStepUp(w, r, ctx, client, organizationID, actorUserID, domain.SecurityActionOrganizationUpdate) {
			return
		}
		policy, err := h.svc.UpdateSecurityPolicy(ctx, client.ID, organizationID, actorUserID, req, clientIP(r), r.UserAgent())
		if err != nil {
			writeOrganizationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, policy)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *OrganizationHandler) handleInvitations(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID, organizationID, actorUserID string, parts []string) {
	if len(parts) == 2 {
		switch r.Method {
		case http.MethodGet:
			invitations, err := h.svc.ListInvitations(ctx, clientID, organizationID, actorUserID)
			if err != nil {
				writeOrganizationError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"invitations": invitations})
		case http.MethodPost:
			var req application.InviteOrganizationMemberRequest
			if err := decodeOrganizationBody(w, r, &req); err != nil {
				return
			}
			invitation, err := h.svc.InviteMember(ctx, clientID, organizationID, actorUserID, req, clientIP(r), r.UserAgent())
			if err != nil {
				writeOrganizationError(w, err)
				return
			}
			writeJSON(w, http.StatusCreated, invitation)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}
	if len(parts) == 4 && parts[3] == "revoke" {
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if err := h.svc.RevokeInvitation(ctx, clientID, organizationID, parts[2], actorUserID, clientIP(r), r.UserAgent()); err != nil {
			writeOrganizationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func (h *OrganizationHandler) issueOrganizationToken(w http.ResponseWriter, r *http.Request, ctx context.Context, client *domain.Client, organizationID, userID string, parts []string) {
	if len(parts) != 2 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !h.requireStepUp(w, r, ctx, client, organizationID, userID, domain.SecurityActionOrganizationTokenIssue) {
		return
	}
	token, err := h.svc.IssueOrganizationAccessToken(ctx, client, organizationID, userID, h.cfg.AccessTTL)
	if err != nil {
		writeOrganizationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, organizationTokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(h.cfg.AccessTTL.Seconds()),
	})
}

func (h *OrganizationHandler) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	claims := GetUserClaims(r)
	if client == nil || claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := decodeOrganizationBody(w, r, &req); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	result, err := h.svc.AcceptInvitation(ctx, client.ID, claims.Subject, req.Token, clientIP(r), r.UserAgent())
	if err != nil {
		writeOrganizationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *OrganizationHandler) requireStepUp(w http.ResponseWriter, r *http.Request, ctx context.Context, client *domain.Client, organizationID, actorUserID, action string) bool {
	if h.adaptive == nil {
		return true
	}
	decision, err := h.adaptive.EvaluateAction(ctx, client, organizationID, actorUserID, action, stepUpTokenFromRequest(r), clientIP(r), r.UserAgent())
	if err != nil {
		writeAdaptiveSecurityError(w, err)
		return false
	}
	if decision != nil && (decision.Blocked || decision.StepUpRequired) {
		writeAdaptiveActionDecision(w, decision)
		return false
	}
	return true
}

func splitOrganizationPath(path string) []string {
	trimmed := strings.Trim(strings.TrimPrefix(path, "/api/auth/organizations/"), "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func decodeOrganizationBody(w http.ResponseWriter, r *http.Request, out interface{}) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(out); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return err
	}
	return nil
}

func writeOrganizationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, domain.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	case errors.Is(err, domain.ErrDuplicateOrganization), errors.Is(err, domain.ErrDuplicateMembership), errors.Is(err, domain.ErrAuthorizationPolicyConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, domain.ErrInvalidRole), errors.Is(err, domain.ErrInvalidPermission), errors.Is(err, domain.ErrInvalidInvitation), errors.Is(err, domain.ErrInvitationExpired), errors.Is(err, domain.ErrInvalidAuthorizationPolicy), errors.Is(err, domain.ErrInvalidGroupMapping):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	default:
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "required") || strings.Contains(msg, "invalid") || strings.Contains(msg, "must") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
}
