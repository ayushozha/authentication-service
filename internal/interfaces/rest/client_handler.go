package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
)

type ClientHandler struct {
	svc *application.ClientService
}

func NewClientHandler(svc *application.ClientService) *ClientHandler {
	return &ClientHandler{svc: svc}
}

func (h *ClientHandler) RegisterRoutes(mux *http.ServeMux, adminMw func(http.Handler) http.Handler) {
	mux.Handle("/api/admin/clients", adminMw(http.HandlerFunc(h.handleClients)))
	mux.Handle("/api/admin/clients/", adminMw(http.HandlerFunc(h.handleClientByID)))
}

func (h *ClientHandler) handleClients(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w, "*")
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
		writeJSON(w, http.StatusCreated, resp)
		return
	}

	if r.Method == http.MethodGet {
		clients, err := h.svc.ListClients(ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		writeJSON(w, http.StatusOK, clients)
		return
	}

	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func (h *ClientHandler) handleClientByID(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w, "*")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	// /api/admin/clients/{id} or /api/admin/clients/{id}/rotate-jwt or /api/admin/clients/{id}/rotate-key
	if len(parts) < 5 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "client ID required"})
		return
	}
	clientID := parts[4]

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Check for rotate actions
	if len(parts) >= 6 {
		action := parts[5]
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		switch action {
		case "rotate-jwt":
			newSecret, client, err := h.svc.RotateJWTSecret(ctx, clientID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"client": client, "jwt_secret": newSecret})
		case "rotate-key":
			newKey, client, err := h.svc.RotateAPIKey(ctx, clientID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
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
		writeJSON(w, http.StatusOK, client)
		return
	}

	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}
