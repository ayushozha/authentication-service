package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
	"golang.org/x/oauth2"
)

func TestClientOAuthRedirectURL(t *testing.T) {
	withUI := func(redirectURL string, origins ...string) *domain.Client {
		return &domain.Client{
			AllowedOrigins: origins,
			Settings: map[string]interface{}{
				"ui": map[string]interface{}{"oauth_redirect_url": redirectURL},
			},
		}
	}

	cases := []struct {
		name   string
		client *domain.Client
		want   string
	}{
		{"nil client", nil, ""},
		{"no settings", &domain.Client{AllowedOrigins: []string{"https://app.example.com"}}, ""},
		{"empty url", withUI("", "https://app.example.com"), ""},
		{"origin allowed", withUI("https://app.example.com/auth/callback", "https://app.example.com"), "https://app.example.com/auth/callback"},
		{"origin allowed with existing query", withUI("https://app.example.com/auth/callback?src=oauth", "https://app.example.com"), "https://app.example.com/auth/callback?src=oauth"},
		{"origin not in allowed list", withUI("https://evil.example.com/auth/callback", "https://app.example.com"), ""},
		{"subdomain mismatch", withUI("https://sub.app.example.com/cb", "https://app.example.com"), ""},
		{"scheme downgrade rejected", withUI("http://app.example.com/cb", "https://app.example.com"), ""},
		{"localhost http allowed when listed", withUI("http://localhost:3000/auth/callback", "https://app.example.com", "http://localhost:3000"), "http://localhost:3000/auth/callback"},
		{"port mismatch", withUI("http://localhost:4000/cb", "http://localhost:3000"), ""},
		{"fragment rejected", withUI("https://app.example.com/cb#frag", "https://app.example.com"), ""},
		{"relative url rejected", withUI("/auth/callback", "https://app.example.com"), ""},
		{"javascript scheme rejected", withUI("javascript:alert(1)", "https://app.example.com"), ""},
		{"non-string setting", &domain.Client{
			AllowedOrigins: []string{"https://app.example.com"},
			Settings:       map[string]interface{}{"ui": map[string]interface{}{"oauth_redirect_url": 42}},
		}, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientOAuthRedirectURL(tc.client); got != tc.want {
				t.Fatalf("clientOAuthRedirectURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestE2EOAuthPerClientRedirectOverride(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"access_token":  "provider-access",
				"refresh_token": "provider-refresh",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		case "/userinfo":
			writeJSON(w, http.StatusOK, map[string]string{
				"id":    "redirect-override-user",
				"email": "redirect-override@example.com",
				"name":  "Redirect Override",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	providers := map[string]*application.OAuthProviderConfig{
		"test": {
			OAuth2Config: &oauth2.Config{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "https://auth.example.com/api/auth/oauth/test/callback",
				Scopes:       []string{"profile", "email"},
				Endpoint: oauth2.Endpoint{
					AuthURL:  provider.URL + "/authorize",
					TokenURL: provider.URL + "/token",
				},
			},
			UserInfoURL: provider.URL + "/userinfo",
			ParseUser: func(data []byte) (string, string, string, string, error) {
				var payload struct {
					ID    string `json:"id"`
					Email string `json:"email"`
					Name  string `json:"name"`
				}
				if err := json.Unmarshal(data, &payload); err != nil {
					return "", "", "", "", err
				}
				return payload.ID, payload.Email, payload.Name, "", nil
			},
		},
	}

	env := newE2EEnv(t, e2eOptions{oauthProviders: providers})

	runCallback := func(t *testing.T) string {
		beginRec := env.request(t, http.MethodGet, "/api/auth/oauth/test", nil, env.apiHeaders())
		assertStatus(t, beginRec, http.StatusFound)
		beginURL, err := url.Parse(beginRec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse begin redirect: %v", err)
		}
		state := beginURL.Query().Get("state")
		if state == "" {
			t.Fatalf("missing oauth state in begin redirect")
		}
		callbackRec := env.request(t, http.MethodGet, "/api/auth/oauth/test/callback?code=oauth-code&state="+url.QueryEscape(state), nil, nil)
		assertStatus(t, callbackRec, http.StatusFound)
		return callbackRec.Header().Get("Location")
	}

	// With ui.oauth_redirect_url set to an allowed origin, the auth code is
	// handed to the client app instead of the hosted login page.
	env.clients.setSettings(env.client.ID, map[string]interface{}{
		"ui": map[string]interface{}{"oauth_redirect_url": "https://app.example.com/auth/callback"},
	})
	location := runCallback(t)
	if !strings.HasPrefix(location, "https://app.example.com/auth/callback?auth_code=") {
		t.Fatalf("expected override redirect, got: %s", location)
	}
	resp := authResponseFromRedirect(t, env, location)
	if resp.AccessToken == "" {
		t.Fatalf("override auth code did not exchange for an access token")
	}

	// A redirect URL outside the allowed origins is ignored — the flow falls
	// back to the hosted login page.
	env.clients.setSettings(env.client.ID, map[string]interface{}{
		"ui": map[string]interface{}{"oauth_redirect_url": "https://evil.example.com/auth/callback"},
	})
	location = runCallback(t)
	if !strings.HasPrefix(location, "https://auth.example.com/login.html?auth_code=") {
		t.Fatalf("expected hosted login fallback for disallowed origin, got: %s", location)
	}
}
