package rest

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type AuditHandler struct {
	svc      *application.AuditService
	adaptive *application.AdaptiveSecurityService
}

func NewAuditHandler(svc *application.AuditService, adaptive *application.AdaptiveSecurityService) *AuditHandler {
	return &AuditHandler{svc: svc, adaptive: adaptive}
}

func (h *AuditHandler) RegisterRoutes(mux *http.ServeMux, adminMw func(http.Handler) http.Handler) {
	mux.Handle("/api/admin/audit-events", adminMw(http.HandlerFunc(h.handleAuditEvents)))
	mux.Handle("/api/admin/audit-events/export", adminMw(http.HandlerFunc(h.handleAuditExport)))
	mux.Handle("/api/admin/audit-events/legal-hold", adminMw(http.HandlerFunc(h.handleLegalHold)))
	mux.Handle("/api/admin/audit-events/retention/purge", adminMw(http.HandlerFunc(h.handleRetentionPurge)))
	mux.Handle("/api/admin/audit-events/chain/verify", adminMw(http.HandlerFunc(h.handleChainVerify)))
}

func (h *AuditHandler) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w, "*", false)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	filter, ok := auditFilterFromRequest(w, r)
	if !ok {
		return
	}
	if !scopeAuditFilter(w, r, &filter) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if filter.ClientID != "" && !h.requireAdminAction(w, r, ctx, filter.ClientID, domain.SecurityActionAuditExport) {
		return
	}
	events, err := h.svc.ListEvents(ctx, filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load audit events"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"events": events})
}

func (h *AuditHandler) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w, "*", false)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "jsonl" && format != "ndjson" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "format must be csv or jsonl"})
		return
	}
	filter, ok := auditFilterFromRequest(w, r)
	if !ok {
		return
	}
	if !scopeAuditFilter(w, r, &filter) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if filter.ClientID != "" && !h.requireAdminAction(w, r, ctx, filter.ClientID, domain.SecurityActionAuditExport) {
		return
	}
	events, err := h.svc.ListEvents(ctx, filter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load audit events"})
		return
	}

	if format == "csv" {
		writeAuditCSV(w, events)
		return
	}
	writeAuditJSONL(w, events)
}

func (h *AuditHandler) requireAdminAction(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID, action string) bool {
	if h == nil || h.adaptive == nil {
		return true
	}
	decision, err := h.adaptive.EvaluateAdminAction(ctx, clientID, action, GetAdminActor(r), stepUpTokenFromRequest(r), clientIP(r), r.UserAgent())
	if err != nil {
		writeAdaptiveSecurityError(w, r, err)
		return false
	}
	if decision != nil && (decision.Blocked || decision.StepUpRequired) {
		writeAdaptiveActionDecision(w, r, decision)
		return false
	}
	return true
}

func (h *AuditHandler) handleLegalHold(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w, "*", false)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodPatch {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !requireAllScopeAuditOperation(w, r) {
		return
	}
	var req domain.AuditLegalHoldRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	result, err := h.svc.SetLegalHold(ctx, req)
	if err != nil {
		writeAuditOperationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *AuditHandler) handleRetentionPurge(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w, "*", false)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !requireAllScopeAuditOperation(w, r) {
		return
	}
	req := domain.AuditRetentionPurgeRequest{DryRun: true}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := h.svc.PurgeExpired(ctx, req)
	if err != nil {
		writeAuditOperationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *AuditHandler) handleChainVerify(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w, "*", false)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	filter, ok := auditFilterFromRequest(w, r)
	if !ok {
		return
	}
	if !scopeAuditFilter(w, r, &filter) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := h.svc.VerifyChain(ctx, filter)
	if err != nil {
		writeAuditOperationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func auditFilterFromRequest(w http.ResponseWriter, r *http.Request) (domain.AuditEventFilter, bool) {
	limit := 0
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a number"})
			return domain.AuditEventFilter{}, false
		}
		limit = parsed
	}
	from, ok := parseAuditTimeQuery(w, r, "from")
	if !ok {
		return domain.AuditEventFilter{}, false
	}
	to, ok := parseAuditTimeQuery(w, r, "to")
	if !ok {
		return domain.AuditEventFilter{}, false
	}
	var legalHold *bool
	if rawLegalHold := strings.TrimSpace(r.URL.Query().Get("legal_hold")); rawLegalHold != "" {
		parsed, err := strconv.ParseBool(rawLegalHold)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "legal_hold must be true or false"})
			return domain.AuditEventFilter{}, false
		}
		legalHold = &parsed
	}
	return domain.AuditEventFilter{
		ClientID:   r.URL.Query().Get("client_id"),
		UserID:     r.URL.Query().Get("user_id"),
		EventType:  r.URL.Query().Get("event_type"),
		ActorType:  r.URL.Query().Get("actor_type"),
		ActorID:    r.URL.Query().Get("actor_id"),
		TargetType: r.URL.Query().Get("target_type"),
		TargetID:   r.URL.Query().Get("target_id"),
		RequestID:  r.URL.Query().Get("request_id"),
		From:       from,
		To:         to,
		LegalHold:  legalHold,
		Limit:      limit,
	}, true
}

func scopeAuditFilter(w http.ResponseWriter, r *http.Request, filter *domain.AuditEventFilter) bool {
	actor := GetAdminActor(r)
	if actor == nil || actor.IsAllScoped() {
		return true
	}
	if actor.ScopeClientID == "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "audit access requires a client-scoped admin identity"})
		return false
	}
	if filter.ClientID != "" && filter.ClientID != actor.ScopeClientID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return false
	}
	filter.ClientID = actor.ScopeClientID
	AddAdminAuditMetadata(r, "scope_enforced", true)
	return true
}

func requireAllScopeAuditOperation(w http.ResponseWriter, r *http.Request) bool {
	actor := GetAdminActor(r)
	if actor == nil || actor.IsAllScoped() {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "audit operation requires an all-scoped admin identity"})
	return false
}

func writeAuditCSV(w http.ResponseWriter, events []*domain.AuditEvent) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="authservice-audit-events.csv"`)
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{
		"id", "client_id", "user_id", "event_type", "actor_type", "actor_id", "actor_email",
		"target_type", "target_id", "request_id", "ip_address", "user_agent",
		"metadata", "before_metadata", "after_metadata", "created_at", "retention_until",
		"legal_hold", "legal_hold_reason", "legal_hold_at", "chain_scope", "previous_hash",
		"event_hash", "hash_algorithm",
	})
	for _, event := range events {
		userID := ""
		if event.UserID != nil {
			userID = *event.UserID
		}
		metadata, _ := json.Marshal(event.Metadata)
		beforeMetadata, _ := json.Marshal(event.BeforeMetadata)
		afterMetadata, _ := json.Marshal(event.AfterMetadata)
		retentionUntil := ""
		if event.RetentionUntil != nil {
			retentionUntil = event.RetentionUntil.Format(time.RFC3339Nano)
		}
		legalHoldAt := ""
		if event.LegalHoldAt != nil {
			legalHoldAt = event.LegalHoldAt.Format(time.RFC3339Nano)
		}
		_ = writer.Write([]string{
			strconv.FormatInt(event.ID, 10),
			event.ClientID,
			userID,
			event.EventType,
			event.ActorType,
			event.ActorID,
			event.ActorEmail,
			event.TargetType,
			event.TargetID,
			event.RequestID,
			event.IPAddress,
			event.UserAgent,
			string(metadata),
			string(beforeMetadata),
			string(afterMetadata),
			event.CreatedAt.Format(time.RFC3339Nano),
			retentionUntil,
			strconv.FormatBool(event.LegalHold),
			event.LegalHoldReason,
			legalHoldAt,
			event.ChainScope,
			event.PreviousHash,
			event.EventHash,
			event.HashAlgorithm,
		})
	}
	writer.Flush()
}

func writeAuditJSONL(w http.ResponseWriter, events []*domain.AuditEvent) {
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="authservice-audit-events.ndjson"`)
	encoder := json.NewEncoder(w)
	for _, event := range events {
		_ = encoder.Encode(event)
	}
}

func parseAuditTimeQuery(w http.ResponseWriter, r *http.Request, key string) (time.Time, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return time.Time{}, true
	}
	if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return parsed, true
	}
	if parsed, err := time.Parse("2006-01-02", raw); err == nil {
		return parsed, true
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": key + " must be RFC3339 or YYYY-MM-DD"})
	return time.Time{}, false
}

func writeAuditOperationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidRequest):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, domain.ErrNotFound):
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "audit operation is not supported by this repository"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}
