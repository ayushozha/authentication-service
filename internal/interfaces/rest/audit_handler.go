package rest

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type AuditHandler struct {
	svc *application.AuditService
}

func NewAuditHandler(svc *application.AuditService) *AuditHandler {
	return &AuditHandler{svc: svc}
}

func (h *AuditHandler) RegisterRoutes(mux *http.ServeMux, adminMw func(http.Handler) http.Handler) {
	mux.Handle("/api/admin/audit-events", adminMw(http.HandlerFunc(h.handleAuditEvents)))
	mux.Handle("/api/admin/audit-events/export", adminMw(http.HandlerFunc(h.handleAuditExport)))
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

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

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

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

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
	return domain.AuditEventFilter{
		ClientID:  r.URL.Query().Get("client_id"),
		UserID:    r.URL.Query().Get("user_id"),
		EventType: r.URL.Query().Get("event_type"),
		Limit:     limit,
	}, true
}

func writeAuditCSV(w http.ResponseWriter, events []*domain.AuditEvent) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="authservice-audit-events.csv"`)
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"id", "client_id", "user_id", "event_type", "ip_address", "user_agent", "metadata", "created_at"})
	for _, event := range events {
		userID := ""
		if event.UserID != nil {
			userID = *event.UserID
		}
		metadata, _ := json.Marshal(event.Metadata)
		_ = writer.Write([]string{
			strconv.FormatInt(event.ID, 10),
			event.ClientID,
			userID,
			event.EventType,
			event.IPAddress,
			event.UserAgent,
			string(metadata),
			event.CreatedAt.Format(time.RFC3339Nano),
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
