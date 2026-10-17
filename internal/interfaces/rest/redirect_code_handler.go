package rest

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
)

const redirectAuthCodeTTL = 2 * time.Minute
const boundRedirectCodePrefix = "app_s256."

type redirectCodePayload struct {
	application.AuthResponse
	AppCodeChallenge string `json:"_app_code_challenge,omitempty"`
}

func RegisterRedirectCodeRoute(mux *http.ServeMux, cfg *HandlerConfig) {
	mux.HandleFunc("/api/auth/redirect/exchange", CORSHandler(cfg.AllowOrigin, MethodCheck(http.MethodPost, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Code         string `json:"code"`
			CodeVerifier string `json:"code_verifier"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req)
		code := strings.TrimSpace(req.Code)
		if code == "" {
			code = strings.TrimSpace(r.URL.Query().Get("code"))
		}
		if code == "" {
			writeError(w, r, http.StatusBadRequest, "code_is_required", "Code is required.")
			return
		}
		resp, err := consumeRedirectAuthCode(r.Context(), cfg, code, req.CodeVerifier)
		if err != nil {
			if err == domain.ErrRedisRequired {
				writeError(w, r, http.StatusServiceUnavailable, "redirect_code_unavailable", "Redirect code exchange requires Redis.")
				return
			}
			writeError(w, r, http.StatusBadRequest, "invalid_or_expired_token", "Invalid or expired code.")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})))
}

func redirectWithAuthCode(w http.ResponseWriter, r *http.Request, cfg *HandlerConfig, client *domain.Client, resp *application.AuthResponse, refreshToken string, includeRefresh bool, appChallenge ...string) {
	code, err := issueRedirectAuthCode(r.Context(), cfg, resp, refreshToken, includeRefresh, appChallenge...)
	if err != nil {
		redirectWithLoginAuthError(w, r, cfg, "AUTH_SERVICE_UNAVAILABLE")
		return
	}
	target := strings.TrimRight(cfg.BaseURL, "/") + "/login.html"
	if override := clientOAuthRedirectURL(client); override != "" {
		target = override
	}
	separator := "?"
	if strings.Contains(target, "?") {
		separator = "&"
	}
	http.Redirect(w, r, target+separator+"auth_code="+url.QueryEscape(code), http.StatusFound)
}

// clientOAuthRedirectURL returns the client's opt-in post-OAuth redirect
// target (settings.ui.oauth_redirect_url). The URL is only honored when its
// origin matches one of the client's allowed origins, so a tampered or
// misconfigured setting can never send auth codes to a foreign origin.
func clientOAuthRedirectURL(client *domain.Client) string {
	if client == nil || client.Settings == nil {
		return ""
	}
	ui, ok := client.Settings["ui"].(map[string]interface{})
	if !ok {
		return ""
	}
	raw, _ := ui["oauth_redirect_url"].(string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Fragment != "" {
		return ""
	}
	for _, origin := range client.AllowedOrigins {
		allowed, err := url.Parse(strings.TrimSpace(origin))
		if err != nil {
			continue
		}
		if allowed.Scheme == parsed.Scheme && allowed.Host == parsed.Host {
			return parsed.String()
		}
	}
	return ""
}

func issueRedirectAuthCode(ctx context.Context, cfg *HandlerConfig, resp *application.AuthResponse, refreshToken string, includeRefresh bool, appChallenge ...string) (string, error) {
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
	payload := redirectCodePayload{AuthResponse: *resp}
	if len(appChallenge) == 1 {
		payload.AppCodeChallenge = appChallenge[0]
	}
	if payload.AppCodeChallenge != "" {
		// Old binaries only read auth_redirect keys and must never be able to
		// exchange a verifier-bound code during rolling deploys or rollback.
		code = boundRedirectCodePrefix + code
	}
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

func consumeRedirectAuthCode(ctx context.Context, cfg *HandlerConfig, code string, codeVerifier ...string) (*application.AuthResponse, error) {
	if cfg == nil || cfg.Cache == nil {
		return nil, domain.ErrRedisRequired
	}
	key := redirectAuthCodeKey(code)
	raw, err := cfg.Cache.Get(ctx, key)
	if err != nil || raw == "" {
		return nil, domain.ErrInvalidToken
	}
	var payload redirectCodePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, domain.ErrInvalidToken
	}
	if payload.AppCodeChallenge != "" {
		if len(codeVerifier) != 1 || !validAppVerifier(codeVerifier[0], payload.AppCodeChallenge) ||
			payload.AppSessionBinding != "S256" || payload.IdentityPolicy != "provider_subject" || payload.Provider != "google" || payload.ProviderSubject == "" {
			return nil, domain.ErrInvalidToken
		}
	} else if payload.AppSessionBinding != "" || payload.IdentityPolicy != "" || payload.ProviderSubject != "" {
		// Never return a binding claim for an unbound/partially written payload.
		return nil, domain.ErrInvalidToken
	}
	if strings.TrimSpace(payload.AccessToken) == "" {
		return nil, domain.ErrInvalidToken
	}
	// Verify first so a wrong verifier cannot burn someone else's code; consume
	// atomically afterwards so only one caller can receive its credentials.
	consumed, err := cfg.Cache.GetDel(ctx, key)
	if err != nil || consumed != raw {
		return nil, domain.ErrInvalidToken
	}
	return &payload.AuthResponse, nil
}

func validAppVerifier(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, c := range verifier {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", c)) {
			return false
		}
	}
	digest := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(digest[:])), []byte(challenge)) == 1
}

func redirectAuthCodeKey(code string) string {
	if strings.HasPrefix(code, boundRedirectCodePrefix) {
		return "auth_redirect_bound:" + application.HashToken(code)
	}
	return "auth_redirect:" + application.HashToken(code)
}
