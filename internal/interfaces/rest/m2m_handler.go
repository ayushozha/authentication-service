package rest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

type M2MHandler struct {
	svc      *application.M2MService
	adaptive *application.AdaptiveSecurityService
	cfg      *HandlerConfig
}

func NewM2MHandler(svc *application.M2MService, adaptive *application.AdaptiveSecurityService, cfg *HandlerConfig) *M2MHandler {
	return &M2MHandler{svc: svc, adaptive: adaptive, cfg: cfg}
}

func (h *M2MHandler) RegisterOAuthRoutes(mux *http.ServeMux) {
	if h == nil || h.svc == nil {
		return
	}
	mux.HandleFunc("/oauth/token", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.token)))
	mux.HandleFunc("/api/oauth/token", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.token)))
	mux.HandleFunc("/oauth/introspect", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.introspect)))
	mux.HandleFunc("/api/oauth/introspect", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.introspect)))
}

func (h *M2MHandler) token(w http.ResponseWriter, r *http.Request) {
	var req application.ClientCredentialsRequest
	if err := decodeOAuthRequest(w, r, &req); err != nil {
		return
	}
	applyBasicAuthCredentials(r, &req.ClientID, &req.ClientSecret)
	if strings.TrimSpace(req.GrantType) == "" {
		req.GrantType = "client_credentials"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, err := h.svc.IssueClientCredentialsToken(ctx, req, clientIP(r), r.UserAgent(), h.cfg.AccessTTL)
	if err != nil {
		writeM2MError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *M2MHandler) introspect(w http.ResponseWriter, r *http.Request) {
	var req application.TokenIntrospectionRequest
	if err := decodeOAuthRequest(w, r, &req); err != nil {
		return
	}
	applyBasicAuthCredentials(r, &req.ClientID, &req.ClientSecret)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	resp, err := h.svc.IntrospectToken(ctx, req, clientIP(r), r.UserAgent())
	if err != nil {
		writeM2MError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *M2MHandler) handleAdminServiceAccounts(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID string, parts []string) {
	if h == nil || h.svc == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if len(parts) == 6 {
		switch r.Method {
		case http.MethodGet:
			accounts, err := h.svc.ListServiceAccounts(ctx, clientID)
			if err != nil {
				writeM2MError(w, err)
				return
			}
			SetAdminAuditAfter(r, map[string]interface{}{"count": len(accounts)})
			writeJSON(w, http.StatusOK, map[string]interface{}{"service_accounts": accounts})
		case http.MethodPost:
			var req application.CreateServiceAccountRequest
			if err := decodeJSONBody(w, r, &req); err != nil {
				return
			}
			resp, err := h.svc.CreateServiceAccount(ctx, clientID, req, clientIP(r), r.UserAgent())
			if err != nil {
				writeM2MError(w, err)
				return
			}
			SetAdminAuditTarget(r, "service_account", resp.ServiceAccount.ID, clientID)
			SetAdminAuditAfter(r, safeServiceAccountMetadata(resp.ServiceAccount))
			writeJSON(w, http.StatusCreated, resp)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}
	if len(parts) < 7 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	serviceAccountID := parts[6]
	if len(parts) == 7 {
		switch r.Method {
		case http.MethodGet:
			account, err := h.svc.GetServiceAccount(ctx, clientID, serviceAccountID)
			if err != nil {
				writeM2MError(w, err)
				return
			}
			SetAdminAuditAfter(r, safeServiceAccountMetadata(account))
			writeJSON(w, http.StatusOK, account)
		case http.MethodPatch:
			before, _ := h.svc.GetServiceAccount(ctx, clientID, serviceAccountID)
			SetAdminAuditBefore(r, safeServiceAccountMetadata(before))
			var req application.UpdateServiceAccountRequest
			if err := decodeJSONBody(w, r, &req); err != nil {
				return
			}
			account, err := h.svc.UpdateServiceAccount(ctx, clientID, serviceAccountID, req, clientIP(r), r.UserAgent())
			if err != nil {
				writeM2MError(w, err)
				return
			}
			SetAdminAuditAfter(r, safeServiceAccountMetadata(account))
			writeJSON(w, http.StatusOK, account)
		case http.MethodDelete:
			before, _ := h.svc.GetServiceAccount(ctx, clientID, serviceAccountID)
			SetAdminAuditBefore(r, safeServiceAccountMetadata(before))
			account, err := h.svc.UpdateServiceAccount(ctx, clientID, serviceAccountID, application.UpdateServiceAccountRequest{Status: "disabled"}, clientIP(r), r.UserAgent())
			if err != nil {
				writeM2MError(w, err)
				return
			}
			SetAdminAuditAfter(r, safeServiceAccountMetadata(account))
			writeJSON(w, http.StatusOK, account)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}
	if parts[7] != "keys" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if len(parts) == 8 {
		switch r.Method {
		case http.MethodGet:
			keys, err := h.svc.ListServiceAccountKeys(ctx, clientID, serviceAccountID)
			if err != nil {
				writeM2MError(w, err)
				return
			}
			SetAdminAuditAfter(r, map[string]interface{}{"count": len(keys), "service_account_id": serviceAccountID})
			writeJSON(w, http.StatusOK, map[string]interface{}{"keys": keys})
		case http.MethodPost:
			var req application.CreateServiceAccountKeyRequest
			if err := decodeOptionalJSONBody(w, r, &req); err != nil {
				return
			}
			resp, err := h.svc.CreateServiceAccountKey(ctx, clientID, serviceAccountID, req, clientIP(r), r.UserAgent())
			if err != nil {
				writeM2MError(w, err)
				return
			}
			SetAdminAuditTarget(r, "service_account_key", resp.Key.ID, clientID)
			SetAdminAuditAfter(r, safeServiceAccountKeyMetadata(resp.Key))
			writeJSON(w, http.StatusCreated, resp)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}
	if len(parts) < 9 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	keyID := parts[8]
	if len(parts) == 9 {
		if r.Method != http.MethodDelete {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		SetAdminAuditBefore(r, map[string]interface{}{"key_id": keyID, "service_account_id": serviceAccountID})
		if err := h.svc.RevokeServiceAccountKey(ctx, clientID, serviceAccountID, keyID, clientIP(r), r.UserAgent()); err != nil {
			writeM2MError(w, err)
			return
		}
		SetAdminAuditAfter(r, map[string]interface{}{"key_id": keyID, "service_account_id": serviceAccountID, "status": "revoked"})
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
		return
	}
	if len(parts) == 10 && parts[9] == "rotate" {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if !h.requireAdminAction(w, r, ctx, clientID, domain.SecurityActionServiceAccountKeyRotate) {
			return
		}
		resp, err := h.svc.RotateServiceAccountKey(ctx, clientID, serviceAccountID, keyID, clientIP(r), r.UserAgent())
		if err != nil {
			writeM2MError(w, err)
			return
		}
		SetAdminAuditTarget(r, "service_account_key", resp.Key.ID, clientID)
		SetAdminAuditAfter(r, safeServiceAccountKeyMetadata(resp.Key))
		writeJSON(w, http.StatusOK, resp)
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func (h *M2MHandler) requireAdminAction(w http.ResponseWriter, r *http.Request, ctx context.Context, clientID, action string) bool {
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

func decodeOAuthRequest(w http.ResponseWriter, r *http.Request, out interface{}) error {
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		return decodeJSONBody(w, r, out)
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form body"})
		return err
	}
	raw, _ := json.Marshal(map[string]string{
		"grant_type":    r.FormValue("grant_type"),
		"client_id":     r.FormValue("client_id"),
		"client_secret": r.FormValue("client_secret"),
		"scope":         r.FormValue("scope"),
		"token":         r.FormValue("token"),
	})
	return json.Unmarshal(raw, out)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, out interface{}) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(out); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return err
	}
	return nil
}

func decodeOptionalJSONBody(w http.ResponseWriter, r *http.Request, out interface{}) error {
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(out)
	if err == nil || errors.Is(err, io.EOF) {
		return nil
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	return err
}

func applyBasicAuthCredentials(r *http.Request, clientID, clientSecret *string) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		return
	}
	*clientID = id
	*clientSecret = secret
}

func writeM2MError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, domain.ErrInvalidClientCredentials):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
	case errors.Is(err, domain.ErrInvalidScope):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_scope"})
	case errors.Is(err, domain.ErrForbidden):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	default:
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "required") || strings.Contains(msg, "invalid") || strings.Contains(msg, "must") || strings.Contains(msg, "unsupported") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
}

func safeServiceAccountMetadata(account *domain.ServiceAccount) map[string]interface{} {
	if account == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"id":          account.ID,
		"client_id":   account.ClientID,
		"name":        account.Name,
		"description": account.Description,
		"scopes":      account.Scopes,
		"status":      account.Status,
	}
}

func safeServiceAccountKeyMetadata(key *domain.ServiceAccountKey) map[string]interface{} {
	if key == nil {
		return map[string]interface{}{}
	}
	return map[string]interface{}{
		"id":                 key.ID,
		"client_id":          key.ClientID,
		"service_account_id": key.ServiceAccountID,
		"name":               key.Name,
		"key_prefix":         key.KeyPrefix,
		"scopes":             key.Scopes,
		"status":             key.Status,
	}
}
