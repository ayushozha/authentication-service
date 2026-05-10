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

type SCIMHandler struct {
	svc *application.SCIMService
	cfg *HandlerConfig
}

func NewSCIMHandler(svc *application.SCIMService, cfg *HandlerConfig) *SCIMHandler {
	return &SCIMHandler{svc: svc, cfg: cfg}
}

func (h *SCIMHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/scim/v2/", h.handleSCIM)
}

func (h *SCIMHandler) handleSCIM(w http.ResponseWriter, r *http.Request) {
	setCorsHeaders(w, "*", false)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if h.svc == nil {
		writeSCIMError(w, http.StatusNotFound, "not found")
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/"), "/"), "/")
	if len(parts) < 4 || parts[0] != "scim" || parts[1] != "v2" {
		writeSCIMError(w, http.StatusNotFound, "not found")
		return
	}
	directoryID := parts[2]
	resource := parts[3]

	token := bearerToken(r)
	if token == "" {
		writeSCIMError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	directory, err := h.svc.AuthenticateDirectory(ctx, directoryID, token)
	if err != nil {
		writeSCIMError(w, http.StatusUnauthorized, err.Error())
		return
	}

	switch resource {
	case "ServiceProviderConfig":
		h.handleServiceProviderConfig(w, r)
	case "ResourceTypes":
		h.handleResourceTypes(w, r)
	case "Schemas":
		h.handleSchemas(w, r)
	case "Users":
		h.handleUsers(w, r, ctx, directory, parts)
	case "Groups":
		h.handleGroups(w, r, ctx, directory, parts)
	default:
		writeSCIMError(w, http.StatusNotFound, "unknown resource")
	}
}

func (h *SCIMHandler) handleServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeSCIMJSON(w, http.StatusOK, map[string]interface{}{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":                 map[string]bool{"supported": true},
		"bulk":                  map[string]interface{}{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]interface{}{"supported": false, "maxResults": 0},
		"changePassword":        map[string]bool{"supported": false},
		"sort":                  map[string]bool{"supported": false},
		"etag":                  map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]string{{"type": "oauthbearertoken", "name": "Bearer Token"}},
	})
}

func (h *SCIMHandler) handleResourceTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeSCIMJSON(w, http.StatusOK, []map[string]interface{}{
		{"id": "User", "name": "User", "endpoint": "/Users", "schema": "urn:ietf:params:scim:schemas:core:2.0:User"},
		{"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": "urn:ietf:params:scim:schemas:core:2.0:Group"},
	})
}

func (h *SCIMHandler) handleSchemas(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeSCIMJSON(w, http.StatusOK, []map[string]interface{}{
		{"id": "urn:ietf:params:scim:schemas:core:2.0:User", "name": "User"},
		{"id": "urn:ietf:params:scim:schemas:core:2.0:Group", "name": "Group"},
	})
}

func (h *SCIMHandler) handleUsers(w http.ResponseWriter, r *http.Request, ctx context.Context, directory *domain.SCIMDirectory, parts []string) {
	baseURL := h.externalBaseURL(r)
	if len(parts) == 4 {
		switch r.Method {
		case http.MethodGet:
			resp, err := h.svc.ListUsers(ctx, directory, baseURL)
			h.writeSCIMResult(w, http.StatusOK, resp, err)
		case http.MethodPost:
			var req application.SCIMUserResource
			if err := decodeSCIMBody(w, r, &req); err != nil {
				return
			}
			resp, err := h.svc.UpsertUser(ctx, directory, req, baseURL)
			h.writeSCIMResult(w, http.StatusCreated, resp, err)
		default:
			writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}
	if len(parts) != 5 {
		writeSCIMError(w, http.StatusNotFound, "not found")
		return
	}
	userID := parts[4]
	switch r.Method {
	case http.MethodGet:
		resp, err := h.svc.GetUser(ctx, directory, userID, baseURL)
		h.writeSCIMResult(w, http.StatusOK, resp, err)
	case http.MethodPut:
		var req application.SCIMUserResource
		if err := decodeSCIMBody(w, r, &req); err != nil {
			return
		}
		req.ID = userID
		resp, err := h.svc.UpsertUser(ctx, directory, req, baseURL)
		h.writeSCIMResult(w, http.StatusOK, resp, err)
	case http.MethodPatch:
		var req application.SCIMPatchRequest
		if err := decodeSCIMBody(w, r, &req); err != nil {
			return
		}
		resp, err := h.svc.PatchUser(ctx, directory, userID, req, baseURL)
		h.writeSCIMResult(w, http.StatusOK, resp, err)
	case http.MethodDelete:
		err := h.svc.DeleteUser(ctx, directory, userID)
		if err != nil {
			h.writeSCIMResult(w, http.StatusOK, nil, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *SCIMHandler) handleGroups(w http.ResponseWriter, r *http.Request, ctx context.Context, directory *domain.SCIMDirectory, parts []string) {
	baseURL := h.externalBaseURL(r)
	if len(parts) == 4 {
		switch r.Method {
		case http.MethodGet:
			resp, err := h.svc.ListGroups(ctx, directory, baseURL)
			h.writeSCIMResult(w, http.StatusOK, resp, err)
		case http.MethodPost:
			var req application.SCIMGroupResource
			if err := decodeSCIMBody(w, r, &req); err != nil {
				return
			}
			resp, err := h.svc.UpsertGroup(ctx, directory, req, baseURL)
			h.writeSCIMResult(w, http.StatusCreated, resp, err)
		default:
			writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}
	if len(parts) != 5 {
		writeSCIMError(w, http.StatusNotFound, "not found")
		return
	}
	groupID := parts[4]
	switch r.Method {
	case http.MethodGet:
		resp, err := h.svc.GetGroup(ctx, directory, groupID, baseURL)
		h.writeSCIMResult(w, http.StatusOK, resp, err)
	case http.MethodPut:
		var req application.SCIMGroupResource
		if err := decodeSCIMBody(w, r, &req); err != nil {
			return
		}
		req.ID = groupID
		resp, err := h.svc.UpsertGroup(ctx, directory, req, baseURL)
		h.writeSCIMResult(w, http.StatusOK, resp, err)
	case http.MethodPatch:
		var req application.SCIMPatchRequest
		if err := decodeSCIMBody(w, r, &req); err != nil {
			return
		}
		resp, err := h.svc.PatchGroup(ctx, directory, groupID, req, baseURL)
		h.writeSCIMResult(w, http.StatusOK, resp, err)
	case http.MethodDelete:
		err := h.svc.DeleteGroup(ctx, directory, groupID)
		if err != nil {
			h.writeSCIMResult(w, http.StatusOK, nil, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *SCIMHandler) handleAdminDirectories(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID string, parts []string) {
	if h.svc == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	switch len(parts) {
	case 6:
		switch r.Method {
		case http.MethodGet:
			directories, err := h.svc.ListDirectories(ctx, clientID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
				return
			}
			SetAdminAuditAfter(r, map[string]interface{}{"count": len(directories)})
			writeJSON(w, http.StatusOK, directories)
		case http.MethodPost:
			var req application.CreateSCIMDirectoryRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
				return
			}
			resp, err := h.svc.CreateDirectory(ctx, clientID, req)
			if err != nil {
				h.writeAdminError(w, err)
				return
			}
			SetAdminAuditTarget(r, "scim_directory", resp.Directory.ID, clientID)
			SetAdminAuditAfter(r, safeSCIMDirectoryMetadata(resp.Directory))
			writeJSON(w, http.StatusCreated, resp)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	case 7:
		directoryID := parts[6]
		switch r.Method {
		case http.MethodGet:
			directory, err := h.svc.GetDirectory(ctx, clientID, directoryID)
			if err != nil {
				h.writeAdminError(w, err)
				return
			}
			SetAdminAuditAfter(r, safeSCIMDirectoryMetadata(directory))
			writeJSON(w, http.StatusOK, directory)
		case http.MethodPatch:
			before, _ := h.svc.GetDirectory(ctx, clientID, directoryID)
			SetAdminAuditBefore(r, safeSCIMDirectoryMetadata(before))
			var req application.UpdateSCIMDirectoryRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
				return
			}
			directory, err := h.svc.UpdateDirectory(ctx, clientID, directoryID, req)
			if err != nil {
				h.writeAdminError(w, err)
				return
			}
			SetAdminAuditAfter(r, safeSCIMDirectoryMetadata(directory))
			writeJSON(w, http.StatusOK, directory)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	case 8:
		if parts[7] != "rotate-token" || r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		before, _ := h.svc.GetDirectory(ctx, clientID, parts[6])
		SetAdminAuditBefore(r, safeSCIMDirectoryMetadata(before))
		resp, err := h.svc.RotateDirectoryToken(ctx, clientID, parts[6])
		if err != nil {
			h.writeAdminError(w, err)
			return
		}
		SetAdminAuditAfter(r, safeSCIMDirectoryMetadata(resp.Directory))
		writeJSON(w, http.StatusOK, resp)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (h *SCIMHandler) writeSCIMResult(w http.ResponseWriter, status int, payload interface{}, err error) {
	if err == nil {
		writeSCIMJSON(w, status, payload)
		return
	}
	switch {
	case errors.Is(err, domain.ErrNotFound):
		writeSCIMError(w, http.StatusNotFound, "not found")
	case errors.Is(err, domain.ErrSSODomainNotAllowed):
		writeSCIMError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, domain.ErrInvalidSCIMResource):
		writeSCIMError(w, http.StatusBadRequest, err.Error())
	default:
		writeSCIMError(w, http.StatusInternalServerError, err.Error())
	}
}

func (h *SCIMHandler) writeAdminError(w http.ResponseWriter, err error) {
	if errors.Is(err, domain.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if errors.Is(err, domain.ErrInvalidSCIMResource) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}

func (h *SCIMHandler) externalBaseURL(r *http.Request) string {
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

func decodeSCIMBody(w http.ResponseWriter, r *http.Request, out interface{}) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(out); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid request body")
		return err
	}
	return nil
}

func writeSCIMJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	writeSCIMJSON(w, status, map[string]interface{}{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":  detail,
		"status":  status,
	})
}

func safeSCIMDirectoryMetadata(directory *domain.SCIMDirectory) map[string]interface{} {
	if directory == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"id":              directory.ID,
		"client_id":       directory.ClientID,
		"organization_id": directory.OrganizationID,
		"name":            directory.Name,
		"provider":        directory.Provider,
		"status":          directory.Status,
		"token_prefix":    directory.TokenPrefix,
		"domains":         directory.Domains,
	}
}
