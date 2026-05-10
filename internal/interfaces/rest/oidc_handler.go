package rest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
)

type OIDCHandler struct {
	svc     *application.OIDCService
	authSvc *application.AuthService
	m2mSvc  *application.M2MService
	cfg     *HandlerConfig
}

func NewOIDCHandler(svc *application.OIDCService, authSvc *application.AuthService, m2mSvc *application.M2MService, cfg *HandlerConfig) *OIDCHandler {
	return &OIDCHandler{svc: svc, authSvc: authSvc, m2mSvc: m2mSvc, cfg: cfg}
}

func (h *OIDCHandler) RegisterRoutes(mux *http.ServeMux) {
	if h == nil || h.svc == nil {
		return
	}
	mux.HandleFunc("/.well-known/openid-configuration", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodGet, h.discovery)))
	mux.HandleFunc("/.well-known/oauth-authorization-server", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodGet, h.discovery)))
	mux.HandleFunc("/authorize", CORSHandler(h.cfg.AllowOrigin, h.authorize))
	mux.HandleFunc("/token", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.token)))
	mux.HandleFunc("/userinfo", CORSHandler(h.cfg.AllowOrigin, h.userinfo))
	mux.HandleFunc("/revoke", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.revoke)))
	mux.HandleFunc("/introspect", CORSHandler(h.cfg.AllowOrigin, MethodCheck(http.MethodPost, h.introspect)))
	mux.HandleFunc("/logout", CORSHandler(h.cfg.AllowOrigin, h.logout))
	mux.HandleFunc("/oidc/login", CORSHandler(h.cfg.AllowOrigin, h.login))
}

func (h *OIDCHandler) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, application.OIDCDiscovery(h.issuer(r)))
}

func (h *OIDCHandler) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	sessionToken := ""
	if cookie, err := r.Cookie("auth_refresh"); err == nil {
		sessionToken = cookie.Value
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	result, err := h.svc.Authorize(ctx, application.OIDCAuthorizeRequest{
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		ResponseType:        r.FormValue("response_type"),
		Scope:               r.FormValue("scope"),
		State:               r.FormValue("state"),
		Nonce:               r.FormValue("nonce"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
		Prompt:              r.FormValue("prompt"),
		MaxAge:              r.FormValue("max_age"),
		ACRValues:           r.FormValue("acr_values"),
		Audience:            r.FormValue("audience"),
		Resources:           r.Form["resource"],
		Consent:             r.FormValue("consent"),
	}, sessionToken, bearerToken(r), h.issuer(r), clientIP(r), r.UserAgent())
	if err != nil {
		h.writeAuthorizeError(w, r, err)
		return
	}
	if result.NeedsLogin {
		http.Redirect(w, r, h.loginRedirectURL(r, result), http.StatusFound)
		return
	}
	if result.NeedsConsent {
		h.renderConsent(w, r, result)
		return
	}
	http.Redirect(w, r, result.RedirectURL, http.StatusFound)
}

func (h *OIDCHandler) token(w http.ResponseWriter, r *http.Request) {
	req, err := decodeOIDCTokenRequest(w, r)
	if err != nil {
		return
	}
	switch req.GrantType {
	case "authorization_code":
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		resp, err := h.svc.ExchangeAuthorizationCode(ctx, req, h.issuer(r), clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
		if err != nil {
			h.writeOAuthError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	case "refresh_token":
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		resp, err := h.svc.RefreshToken(ctx, req, h.issuer(r), clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
		if err != nil {
			h.writeOAuthError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	case "client_credentials":
		if h.m2mSvc == nil {
			h.writeOAuthError(w, fmt.Errorf("unsupported grant_type"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		resp, err := h.m2mSvc.IssueClientCredentialsToken(ctx, application.ClientCredentialsRequest{
			GrantType:    req.GrantType,
			ClientID:     req.ClientID,
			ClientSecret: req.ClientSecret,
			Scope:        req.Scope,
		}, clientIP(r), r.UserAgent(), h.cfg.AccessTTL)
		if err != nil {
			writeM2MError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	default:
		h.writeOAuthError(w, &application.OAuthError{Code: "unsupported_grant_type", Description: "grant_type is not supported", Status: http.StatusBadRequest})
	}
}

func (h *OIDCHandler) userinfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	token := bearerToken(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	resp, err := h.svc.UserInfo(ctx, token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		h.writeOAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *OIDCHandler) revoke(w http.ResponseWriter, r *http.Request) {
	req, err := decodeOIDCRevocationRequest(w, r)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := h.svc.RevokeToken(ctx, req, clientIP(r), r.UserAgent()); err != nil {
		h.writeOAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{})
}

func (h *OIDCHandler) introspect(w http.ResponseWriter, r *http.Request) {
	req, err := decodeOIDCRevocationRequest(w, r)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	resp, err := h.svc.IntrospectToken(ctx, req.Token, req.ClientID, req.ClientSecret)
	if err != nil {
		h.writeOAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *OIDCHandler) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	refreshToken := ""
	if cookie, err := r.Cookie("auth_refresh"); err == nil {
		refreshToken = cookie.Value
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	resp, err := h.svc.Logout(ctx, application.OIDCLogoutRequest{
		IDTokenHint:           r.FormValue("id_token_hint"),
		ClientID:              r.FormValue("client_id"),
		PostLogoutRedirectURI: r.FormValue("post_logout_redirect_uri"),
		State:                 r.FormValue("state"),
	}, refreshToken)
	ClearRefreshCookie(w, h.cfg)
	if err != nil {
		h.writeOAuthError(w, err)
		return
	}
	if resp.RedirectURL != "" {
		http.Redirect(w, r, resp.RedirectURL, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (h *OIDCHandler) login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.renderLogin(w, r, "")
	case http.MethodPost:
		h.submitLogin(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *OIDCHandler) submitLogin(w http.ResponseWriter, r *http.Request) {
	if h.authSvc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "login is not configured"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	clientID := r.FormValue("client_id")
	returnTo := safeOIDCReturnTo(r.FormValue("return_to"))
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	client, err := h.svc.LoginClient(ctx, clientID)
	if err != nil {
		h.renderLogin(w, r, "Invalid client")
		return
	}
	resp, refreshToken, err := h.authSvc.Login(ctx, client, application.LoginRequest{
		Email:    r.FormValue("email"),
		Password: r.FormValue("password"),
	}, clientIP(r), r.UserAgent(), h.cfg.AccessTTL, h.cfg.RefreshTTL)
	if err != nil {
		h.renderLogin(w, r, "Invalid email or password")
		return
	}
	if resp != nil && resp.Requires2FA {
		h.renderLogin(w, r, "Two-factor authentication is required. Sign in with your app session, then retry this authorization request.")
		return
	}
	if refreshToken != "" {
		SetRefreshCookie(w, refreshToken, h.cfg.RefreshTTL, h.cfg)
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (h *OIDCHandler) renderLogin(w http.ResponseWriter, r *http.Request, message string) {
	_ = r.ParseForm()
	clientID := r.FormValue("client_id")
	returnTo := safeOIDCReturnTo(r.FormValue("return_to"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in</title><style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f7f8fb;color:#111827;min-height:100vh;display:grid;place-items:center;margin:0;padding:20px}
main{width:100%%;max-width:400px;background:#fff;border:1px solid #d8dee8;border-radius:8px;padding:24px;box-shadow:0 1px 2px rgba(15,23,42,.08)}
h1{font-size:22px;margin:0 0 6px}.sub{color:#64748b;margin:0 0 18px}.field{display:grid;gap:6px;margin:0 0 12px}label{font-size:13px;font-weight:700}
input{min-height:40px;border:1px solid #cbd5e1;border-radius:8px;padding:8px 10px;font:inherit}button{width:100%%;min-height:42px;border:0;border-radius:8px;background:#145c57;color:white;font-weight:800;cursor:pointer}
.msg{background:#fff1f2;border:1px solid #fecdd3;color:#be123c;border-radius:8px;padding:10px;margin:0 0 14px;font-size:14px}
</style></head><body><main><h1>Sign in</h1><p class="sub">Continue to the requested application.</p>%s
<form method="post" action="/oidc/login">
<input type="hidden" name="client_id" value="%s"><input type="hidden" name="return_to" value="%s">
<div class="field"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" required autofocus></div>
<div class="field"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required></div>
<button type="submit">Sign in</button></form></main></body></html>`,
		loginMessageHTML(message), html.EscapeString(clientID), html.EscapeString(returnTo))
}

func (h *OIDCHandler) renderConsent(w http.ResponseWriter, r *http.Request, result *application.OIDCAuthorizeResult) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = r.ParseForm()
	hidden := strings.Builder{}
	for key, values := range r.Form {
		if key == "consent" {
			continue
		}
		for _, value := range values {
			hidden.WriteString(`<input type="hidden" name="`)
			hidden.WriteString(html.EscapeString(key))
			hidden.WriteString(`" value="`)
			hidden.WriteString(html.EscapeString(value))
			hidden.WriteString(`">`)
		}
	}
	scopes := html.EscapeString(strings.Join(result.Scopes, ", "))
	audiences := html.EscapeString(strings.Join(result.Audiences, ", "))
	clientName := html.EscapeString(result.ConsentClient)
	if clientName == "" && result.Client != nil {
		clientName = html.EscapeString(result.Client.Name)
	}
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Consent</title><style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f7f8fb;color:#111827;min-height:100vh;display:grid;place-items:center;margin:0;padding:20px}
main{width:100%%;max-width:460px;background:#fff;border:1px solid #d8dee8;border-radius:8px;padding:24px;box-shadow:0 1px 2px rgba(15,23,42,.08)}
h1{font-size:22px;margin:0 0 10px}.meta{border:1px solid #e2e8f0;border-radius:8px;padding:12px;margin:14px 0;color:#334155;font-size:14px}
.actions{display:flex;gap:10px}button,a{flex:1;min-height:40px;border-radius:8px;display:grid;place-items:center;font-weight:800;text-decoration:none}
button{border:0;background:#145c57;color:white;cursor:pointer}a{border:1px solid #cbd5e1;color:#111827;background:#fff}
</style></head><body><main><h1>Authorize %s</h1><p>This application is requesting access to your AuthService account.</p>
<div class="meta"><strong>Scopes:</strong> %s<br><strong>Audiences:</strong> %s</div>
<form method="get" action="/authorize">%s<input type="hidden" name="consent" value="accept"><div class="actions"><button type="submit">Allow</button><a href="/logout">Cancel</a></div></form>
</main></body></html>`, clientName, scopes, audiences, hidden.String())
}

func (h *OIDCHandler) writeAuthorizeError(w http.ResponseWriter, r *http.Request, err error) {
	var oauthErr *application.OAuthError
	if errors.As(err, &oauthErr) && oauthErr.RedirectURI != "" {
		redirectURL, parseErr := url.Parse(oauthErr.RedirectURI)
		if parseErr == nil {
			q := redirectURL.Query()
			q.Set("error", oauthErr.Code)
			if oauthErr.Description != "" {
				q.Set("error_description", oauthErr.Description)
			}
			if oauthErr.State != "" {
				q.Set("state", oauthErr.State)
			}
			redirectURL.RawQuery = q.Encode()
			http.Redirect(w, r, redirectURL.String(), http.StatusFound)
			return
		}
	}
	h.writeOAuthError(w, err)
}

func (h *OIDCHandler) writeOAuthError(w http.ResponseWriter, err error) {
	var oauthErr *application.OAuthError
	if errors.As(err, &oauthErr) {
		status := oauthErr.Status
		if status == 0 || status == http.StatusFound {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]string{
			"error":             firstNonEmptyString(oauthErr.Code, "invalid_request"),
			"error_description": oauthErr.Description,
		})
		return
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "unsupported") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type", "error_description": err.Error()})
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": err.Error()})
}

func decodeOIDCTokenRequest(w http.ResponseWriter, r *http.Request) (application.OIDCTokenRequest, error) {
	values, err := decodeOAuthValues(w, r)
	if err != nil {
		return application.OIDCTokenRequest{}, err
	}
	req := application.OIDCTokenRequest{
		GrantType:    values.Get("grant_type"),
		Code:         values.Get("code"),
		RedirectURI:  values.Get("redirect_uri"),
		ClientID:     values.Get("client_id"),
		ClientSecret: values.Get("client_secret"),
		CodeVerifier: values.Get("code_verifier"),
		RefreshToken: values.Get("refresh_token"),
		Scope:        values.Get("scope"),
	}
	applyBasicAuthCredentials(r, &req.ClientID, &req.ClientSecret)
	return req, nil
}

func decodeOIDCRevocationRequest(w http.ResponseWriter, r *http.Request) (application.OIDCRevocationRequest, error) {
	values, err := decodeOAuthValues(w, r)
	if err != nil {
		return application.OIDCRevocationRequest{}, err
	}
	req := application.OIDCRevocationRequest{
		Token:         values.Get("token"),
		TokenTypeHint: values.Get("token_type_hint"),
		ClientID:      values.Get("client_id"),
		ClientSecret:  values.Get("client_secret"),
	}
	applyBasicAuthCredentials(r, &req.ClientID, &req.ClientSecret)
	return req, nil
}

func decodeOAuthValues(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		var body map[string]interface{}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "invalid JSON body"})
			return nil, err
		}
		values := url.Values{}
		for key, value := range body {
			values.Set(key, fmt.Sprint(value))
		}
		return values, nil
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "invalid form body"})
		return nil, err
	}
	return r.Form, nil
}

func (h *OIDCHandler) issuer(r *http.Request) string {
	if h.cfg != nil && strings.TrimSpace(h.cfg.BaseURL) != "" {
		return strings.TrimRight(strings.TrimSpace(h.cfg.BaseURL), "/")
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (h *OIDCHandler) loginRedirectURL(r *http.Request, result *application.OIDCAuthorizeResult) string {
	base := "/oidc/login"
	if result != nil && strings.TrimSpace(result.LoginURL) != "" {
		base = strings.TrimSpace(result.LoginURL)
	}
	loginURL, err := url.Parse(base)
	if err != nil {
		loginURL, _ = url.Parse("/oidc/login")
	}
	q := loginURL.Query()
	if result != nil && result.Client != nil {
		q.Set("client_id", result.Client.ID)
	}
	q.Set("return_to", r.URL.RequestURI())
	loginURL.RawQuery = q.Encode()
	return loginURL.String()
}

func bearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func safeOIDCReturnTo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.IsAbs() {
		return "/"
	}
	clean := parsed.RequestURI()
	if clean == "/authorize" || strings.HasPrefix(clean, "/authorize?") {
		return clean
	}
	return "/"
}

func loginMessageHTML(message string) string {
	if strings.TrimSpace(message) == "" {
		return ""
	}
	return `<div class="msg">` + html.EscapeString(message) + `</div>`
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
