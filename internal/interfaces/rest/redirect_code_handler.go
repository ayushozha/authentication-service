package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

const redirectAuthCodeTTL = 2 * time.Minute

func RegisterRedirectCodeRoute(mux *http.ServeMux, cfg *HandlerConfig) {
	mux.HandleFunc("/api/auth/redirect/exchange", CORSHandler(cfg.AllowOrigin, MethodCheck(http.MethodPost, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req)
		code := strings.TrimSpace(req.Code)
		if code == "" {
			code = strings.TrimSpace(r.URL.Query().Get("code"))
		}
		if code == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code is required"})
			return
		}
		resp, err := consumeRedirectAuthCode(r.Context(), cfg, code)
		if err != nil {
			if err == domain.ErrRedisRequired {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "redirect code exchange requires Redis"})
				return
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired code"})
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})))
}

func redirectWithAuthCode(w http.ResponseWriter, r *http.Request, cfg *HandlerConfig, resp *application.AuthResponse, refreshToken string, includeRefresh bool) {
	code, err := issueRedirectAuthCode(r.Context(), cfg, resp, refreshToken, includeRefresh)
	if err != nil {
		http.Redirect(w, r, strings.TrimRight(cfg.BaseURL, "/")+"/login.html?error=redirect_code_unavailable", http.StatusFound)
		return
	}
	http.Redirect(w, r, strings.TrimRight(cfg.BaseURL, "/")+"/login.html?auth_code="+url.QueryEscape(code), http.StatusFound)
}

func issueRedirectAuthCode(ctx context.Context, cfg *HandlerConfig, resp *application.AuthResponse, refreshToken string, includeRefresh bool) (string, error) {
	if cfg == nil || cfg.Cache == nil {
		return "", domain.ErrRedisRequired
	}
	if resp == nil || strings.TrimSpace(resp.AccessToken) == "" {
		return "", domain.ErrInvalidToken
	}
	code, err := application.GenerateToken(24)
	if err != nil {
		return "", err
	}
	payload := *resp
	if includeRefresh {
		payload.RefreshToken = refreshToken
	} else {
		payload.RefreshToken = ""
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	if err := cfg.Cache.Set(ctx, redirectAuthCodeKey(code), string(encoded), redirectAuthCodeTTL); err != nil {
		return "", err
	}
	return code, nil
}

func consumeRedirectAuthCode(ctx context.Context, cfg *HandlerConfig, code string) (*application.AuthResponse, error) {
	if cfg == nil || cfg.Cache == nil {
		return nil, domain.ErrRedisRequired
	}
	key := redirectAuthCodeKey(code)
	raw, err := cfg.Cache.Get(ctx, key)
	if err != nil || raw == "" {
		return nil, domain.ErrInvalidToken
	}
	_ = cfg.Cache.Del(ctx, key)
	var resp application.AuthResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return nil, domain.ErrInvalidToken
	}
	if strings.TrimSpace(resp.AccessToken) == "" {
		return nil, domain.ErrInvalidToken
	}
	return &resp, nil
}

func redirectAuthCodeKey(code string) string {
	return "auth_redirect:" + application.HashToken(code)
}
