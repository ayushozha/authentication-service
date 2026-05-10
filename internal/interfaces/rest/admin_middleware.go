package rest

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
)

const (
	adminActorContextKey contextKey = "admin_actor"
	adminAuditContextKey contextKey = "admin_audit"
)

type adminRouteRequirement struct {
	Permission      string
	RequireAllScope bool
	TargetType      string
	TargetID        string
	TargetClientID  string
	EventType       string
}

type adminRequestAudit struct {
	EventType      string
	TargetType     string
	TargetID       string
	TargetClientID string
	RequestID      string
	Before         map[string]interface{}
	After          map[string]interface{}
	Metadata       map[string]interface{}
}

func RequireAdminAuth(adminSvc *application.AdminService, adminAPIKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
			if requestID == "" {
				requestID = uuid.New().String()
			}
			w.Header().Set("X-Request-ID", requestID)

			req := adminRequirementForRequest(r)
			audit := &adminRequestAudit{
				EventType:      req.EventType,
				TargetType:     req.TargetType,
				TargetID:       req.TargetID,
				TargetClientID: req.TargetClientID,
				RequestID:      requestID,
				Before:         map[string]interface{}{},
				After:          map[string]interface{}{},
				Metadata: map[string]interface{}{
					"method": r.Method,
					"path":   r.URL.Path,
				},
			}

			actor, authErr := authenticateAdminRequest(r, adminSvc, adminAPIKey)
			if authErr != nil {
				status := statusForAdminAuthError(authErr)
				logAdminRequest(adminSvc, r, nil, audit, status, authErr)
				writeJSON(w, status, map[string]string{"error": authErr.Error()})
				return
			}
			if adminSvc != nil {
				if err := adminSvc.Authorize(actor, req.Permission, req.TargetClientID, req.RequireAllScope); err != nil {
					logAdminRequest(adminSvc, r, actor, audit, http.StatusForbidden, err)
					writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
					return
				}
			}

			ctx := context.WithValue(r.Context(), adminActorContextKey, actor)
			ctx = context.WithValue(ctx, adminAuditContextKey, audit)
			rec := &adminStatusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r.WithContext(ctx))
			logAdminRequest(adminSvc, r, actor, audit, rec.status, nil)
		})
	}
}

func authenticateAdminRequest(r *http.Request, adminSvc *application.AdminService, adminAPIKey string) (*domain.AdminActor, error) {
	if key := strings.TrimSpace(r.Header.Get("X-Admin-Key")); key != "" {
		if !application.ConstantTimeSecretEqual(key, adminAPIKey) {
			return nil, domain.ErrInvalidAdminToken
		}
		if adminSvc == nil {
			return &domain.AdminActor{
				Type:      domain.AdminActorTypeBreakGlass,
				ID:        "master-key",
				Email:     "break-glass-master-key",
				Roles:     []string{domain.AdminRoleOwner},
				ScopeType: domain.AdminScopeAll,
			}, nil
		}
		return adminSvc.BreakGlassActor(r.Context(), clientIP(r))
	}
	token := bearerToken(r)
	if token == "" {
		return nil, domain.ErrInvalidAdminToken
	}
	if adminSvc == nil {
		return nil, domain.ErrInvalidAdminToken
	}
	return adminSvc.ValidateAccessToken(r.Context(), token)
}

func statusForAdminAuthError(err error) int {
	switch {
	case errors.Is(err, domain.ErrRateLimit):
		return http.StatusTooManyRequests
	case errors.Is(err, domain.ErrAccountSuspended), errors.Is(err, domain.ErrAdminPermissionDenied):
		return http.StatusForbidden
	default:
		return http.StatusUnauthorized
	}
}

func adminRequirementForRequest(r *http.Request) adminRouteRequirement {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/admin/"), "/")
	parts := []string{}
	if path != "" {
		parts = strings.Split(path, "/")
	}
	req := adminRouteRequirement{
		Permission: application.AdminPermissionClientsRead,
		TargetType: "admin_api",
		TargetID:   r.URL.Path,
		EventType:  "admin.api.request",
	}
	if len(parts) == 0 {
		return req
	}
	switch parts[0] {
	case "users":
		req.TargetType = "admin_user"
		req.EventType = "admin.admin_users." + methodAction(r.Method)
		req.RequireAllScope = true
		if r.Method == http.MethodGet {
			req.Permission = application.AdminPermissionAdminsRead
		} else {
			req.Permission = application.AdminPermissionAdminsManage
		}
	case "audit-events":
		req.Permission = application.AdminPermissionAuditRead
		req.TargetType = "audit_events"
		req.TargetClientID = strings.TrimSpace(r.URL.Query().Get("client_id"))
		req.TargetID = req.TargetClientID
		req.EventType = "admin.audit_events." + methodAction(r.Method)
	case "clients":
		return clientAdminRequirement(r, parts)
	}
	return req
}

func clientAdminRequirement(r *http.Request, parts []string) adminRouteRequirement {
	req := adminRouteRequirement{
		Permission: application.AdminPermissionClientsRead,
		TargetType: "client",
		EventType:  "admin.clients." + methodAction(r.Method),
	}
	if len(parts) == 1 {
		if r.Method == http.MethodPost {
			req.Permission = application.AdminPermissionClientsCreate
			req.RequireAllScope = true
		}
		return req
	}
	clientID := parts[1]
	req.TargetID = clientID
	req.TargetClientID = clientID
	if len(parts) == 2 {
		if r.Method == http.MethodPatch {
			req.Permission = application.AdminPermissionClientsUpdate
		}
		return req
	}
	switch parts[2] {
	case "rotate-jwt", "rotate-secret", "rotate-key", "rotate-api-key":
		req.Permission = application.AdminPermissionClientsRotate
		req.EventType = "admin.clients.rotate_secret"
	case "service-accounts":
		req.TargetType = "service_account"
		req.EventType = "admin.service_accounts." + methodAction(r.Method)
		if isReadMethod(r.Method) {
			req.Permission = application.AdminPermissionM2MRead
		} else {
			req.Permission = application.AdminPermissionM2MManage
		}
		if len(parts) > 3 {
			req.TargetID = parts[3]
		}
	case "sso-connections":
		req.TargetType = "sso_connection"
		req.EventType = "admin.sso_connections." + methodAction(r.Method)
		if isReadMethod(r.Method) {
			req.Permission = application.AdminPermissionSSORead
		} else {
			req.Permission = application.AdminPermissionSSOManage
		}
		if len(parts) > 3 {
			req.TargetID = parts[3]
		}
	case "scim-directories":
		req.TargetType = "scim_directory"
		req.EventType = "admin.scim_directories." + methodAction(r.Method)
		if isReadMethod(r.Method) {
			req.Permission = application.AdminPermissionSCIMRead
		} else {
			req.Permission = application.AdminPermissionSCIMManage
		}
		if len(parts) > 3 {
			req.TargetID = parts[3]
		}
	default:
		req.Permission = application.AdminPermissionClientsUpdate
	}
	return req
}

func methodAction(method string) string {
	switch method {
	case http.MethodGet:
		return "read"
	case http.MethodPost:
		return "create"
	case http.MethodPatch:
		return "update"
	case http.MethodDelete:
		return "delete"
	default:
		return strings.ToLower(method)
	}
}

func isReadMethod(method string) bool {
	return method == http.MethodGet
}

func logAdminRequest(adminSvc *application.AdminService, r *http.Request, actor *domain.AdminActor, audit *adminRequestAudit, status int, err error) {
	if adminSvc == nil || audit == nil {
		return
	}
	event := &domain.AuditEvent{
		ClientID:       audit.TargetClientID,
		EventType:      audit.EventType,
		TargetType:     audit.TargetType,
		TargetID:       audit.TargetID,
		RequestID:      audit.RequestID,
		IPAddress:      clientIP(r),
		UserAgent:      r.UserAgent(),
		Metadata:       cloneAuditMap(audit.Metadata),
		BeforeMetadata: cloneAuditMap(audit.Before),
		AfterMetadata:  cloneAuditMap(audit.After),
	}
	event.Metadata["status"] = status
	if err != nil {
		event.Metadata["error"] = err.Error()
	}
	if actor != nil {
		event.ActorType = actor.Type
		event.ActorID = actor.ID
		event.ActorEmail = actor.Email
	} else {
		event.ActorType = "unknown"
	}
	adminSvc.LogAdminAction(r.Context(), event)
}

func GetAdminActor(r *http.Request) *domain.AdminActor {
	actor, _ := r.Context().Value(adminActorContextKey).(*domain.AdminActor)
	return actor
}

func SetAdminAuditTarget(r *http.Request, targetType, targetID, clientID string) {
	audit, _ := r.Context().Value(adminAuditContextKey).(*adminRequestAudit)
	if audit == nil {
		return
	}
	if strings.TrimSpace(targetType) != "" {
		audit.TargetType = targetType
	}
	if strings.TrimSpace(targetID) != "" {
		audit.TargetID = targetID
	}
	if strings.TrimSpace(clientID) != "" {
		audit.TargetClientID = clientID
	}
}

func SetAdminAuditBefore(r *http.Request, before map[string]interface{}) {
	audit, _ := r.Context().Value(adminAuditContextKey).(*adminRequestAudit)
	if audit != nil {
		audit.Before = cloneAuditMap(before)
	}
}

func SetAdminAuditAfter(r *http.Request, after map[string]interface{}) {
	audit, _ := r.Context().Value(adminAuditContextKey).(*adminRequestAudit)
	if audit != nil {
		audit.After = cloneAuditMap(after)
	}
}

func AddAdminAuditMetadata(r *http.Request, key string, value interface{}) {
	audit, _ := r.Context().Value(adminAuditContextKey).(*adminRequestAudit)
	if audit == nil {
		return
	}
	if audit.Metadata == nil {
		audit.Metadata = map[string]interface{}{}
	}
	audit.Metadata[key] = value
}

func cloneAuditMap(in map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for key, value := range in {
		out[key] = value
	}
	return out
}

type adminStatusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *adminStatusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *adminStatusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func safeClientMetadata(client *domain.Client) map[string]interface{} {
	if client == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"id":              client.ID,
		"name":            client.Name,
		"slug":            client.Slug,
		"allowed_origins": client.AllowedOrigins,
		"webhook_url":     client.WebhookURL,
		"settings":        client.Settings,
		"status":          client.Status,
		"token_mode":      client.TokenMode,
	}
}

func scopedClientID(actor *domain.AdminActor) string {
	if actor == nil || actor.IsAllScoped() || actor.ScopeType != domain.AdminScopeClient {
		return ""
	}
	return actor.ScopeClientID
}

func parseLimitQuery(raw string) (int, bool) {
	if raw == "" {
		return 0, true
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return parsed, true
}
