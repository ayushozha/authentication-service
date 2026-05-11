package rest

import (
	"net/http"
	"strings"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type UIConfigHandler struct {
	cfg *HandlerConfig
}

func NewUIConfigHandler(cfg *HandlerConfig) *UIConfigHandler {
	return &UIConfigHandler{cfg: cfg}
}

func (h *UIConfigHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/auth/ui/config", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodGet, h.config)))
}

func (h *UIConfigHandler) config(w http.ResponseWriter, r *http.Request) {
	client := GetClient(r)
	if client == nil {
		writeError(w, r, http.StatusUnauthorized, "missing_client", "Missing client.")
		return
	}

	ui := sanitizedUISettings(client)
	if _, ok := ui["brand_name"]; !ok && strings.TrimSpace(client.Name) != "" {
		ui["brand_name"] = client.Name
	}
	if _, ok := ui["custom_domain"]; !ok && len(client.AllowedOrigins) > 0 {
		ui["custom_domain"] = client.AllowedOrigins[0]
	}
	if _, ok := ui["locale"]; !ok {
		ui["locale"] = "en"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"client": map[string]interface{}{
			"id":              client.ID,
			"name":            client.Name,
			"slug":            client.Slug,
			"status":          client.Status,
			"token_mode":      client.TokenMode,
			"allowed_origins": client.AllowedOrigins,
		},
		"ui": ui,
		"hosted_paths": map[string]string{
			"login":     "/login.html",
			"signup":    "/signup.html",
			"account":   "/account.html",
			"forgot":    "/forgot-password.html",
			"reset":     "/reset-password.html",
			"verify":    "/verify-email.html",
			"mfa":       "/2fa.html",
			"portal":    "/portal.html",
			"script":    "/authservice.js",
			"ui_script": "/auth-ui.js",
			"ui_styles": "/auth-ui.css",
		},
	})
}

func sanitizedUISettings(client *domain.Client) map[string]interface{} {
	out := map[string]interface{}{}
	if client == nil || client.Settings == nil {
		return out
	}

	if nested, ok := mapSetting(client.Settings["auth_ui"]); ok {
		copyKnownUISettings(out, nested)
	}
	copyKnownUISettings(out, client.Settings)
	return out
}

func copyKnownUISettings(out map[string]interface{}, settings map[string]interface{}) {
	for _, key := range []string{
		"brand_name",
		"logo_url",
		"primary_color",
		"accent_color",
		"background_color",
		"text_color",
		"theme",
		"locale",
		"locales",
		"oauth_providers",
		"allow_signup",
		"passkey_first",
		"custom_domain",
		"support_url",
		"privacy_url",
		"terms_url",
		"redirect_url",
	} {
		if value, ok := settings[key]; ok {
			out[key] = value
		}
	}
}

func mapSetting(value interface{}) (map[string]interface{}, bool) {
	if value == nil {
		return nil, false
	}
	if typed, ok := value.(map[string]interface{}); ok {
		return typed, true
	}
	return nil, false
}
