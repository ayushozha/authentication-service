package rest

import (
	"context"
	"net/http"
	"strconv"
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

	limit := 0
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a number"})
			return
		}
		limit = parsed
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	events, err := h.svc.ListEvents(ctx, domain.AuditEventFilter{
		ClientID:  r.URL.Query().Get("client_id"),
		UserID:    r.URL.Query().Get("user_id"),
		EventType: r.URL.Query().Get("event_type"),
		Limit:     limit,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load audit events"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"events": events})
}
