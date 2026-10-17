package rest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/Ayush10/authentication-service/internal/domain"
	"golang.org/x/oauth2"
)

type appOAuthProfile struct {
	subject, email string
	status         int
}

func appOAuthEnv(t *testing.T, profile *appOAuthProfile) *e2eEnv {
	t.Helper()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			writeJSON(w, 200, map[string]any{"access_token": "provider-token", "token_type": "Bearer", "expires_in": 3600})
		case "/userinfo":
			status := profile.status
			if status == 0 {
				status = http.StatusOK
			}
			writeJSON(w, status, map[string]string{"id": profile.subject, "email": profile.email})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)
	providers := map[string]*application.OAuthProviderConfig{"google": {
		OAuth2Config: &oauth2.Config{
			ClientID: "google-client", ClientSecret: "google-secret", RedirectURL: "https://auth.example.com/api/auth/oauth/google/callback",
			Endpoint: oauth2.Endpoint{AuthURL: provider.URL + "/authorize", TokenURL: provider.URL + "/token"},
		},
		UserInfoURL: provider.URL + "/userinfo",
		ParseUser: func(data []byte) (string, string, string, string, error) {
			var user struct{ ID, Email string }
			err := json.Unmarshal(data, &user)
			return user.ID, user.Email, "Fixture User", "", err
		},
	}}
	env := newE2EEnv(t, e2eOptions{oauthProviders: providers})
	env.clients.setSettings(env.client.ID, map[string]any{"ui": map[string]any{"oauth_redirect_url": "https://app.example.com/auth/callback"}})
	return env
}

func appChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func appOAuthQuery(verifier string) string {
	return "session_mode=token&app_code_challenge=" + appChallenge(verifier) + "&app_code_challenge_method=S256&identity_policy=provider_subject"
}

func appOAuthCallback(t *testing.T, env *e2eEnv, query string) *httptest.ResponseRecorder {
	t.Helper()
	begin := env.request(t, "GET", "/api/auth/oauth/google?"+query, nil, env.apiHeaders())
	assertStatus(t, begin, http.StatusFound)
	location, err := url.Parse(begin.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(query, "app_code_challenge=") {
		if begin.Header().Get("X-App-Session-Binding") != "S256" {
			t.Fatal("strict begin must affirm accepted S256 binding")
		}
		decoded, _ := base64.RawURLEncoding.DecodeString(location.Query().Get("state"))
		if json.Valid(decoded) {
			t.Fatal("strict OAuth state must be opaque, not contain PKCE payload")
		}
	} else if begin.Header().Get("X-App-Session-Binding") != "" {
		t.Fatal("legacy begin must not claim app binding")
	}
	return env.request(t, "GET", "/api/auth/oauth/google/callback?code=provider-code&state="+url.QueryEscape(location.Query().Get("state")), nil, nil)
}

func appOAuthCode(t *testing.T, env *e2eEnv, verifier string) string {
	t.Helper()
	callback := appOAuthCallback(t, env, appOAuthQuery(verifier))
	assertStatus(t, callback, http.StatusFound)
	location, err := url.Parse(callback.Header().Get("Location"))
	if err != nil || location.Query().Get("auth_code") == "" {
		t.Fatalf("expected app code, location=%q err=%v", callback.Header().Get("Location"), err)
	}
	return location.Query().Get("auth_code")
}

func TestAppOAuthBindingRequiresCompleteGoogleS256OptIn(t *testing.T) {
	env := appOAuthEnv(t, &appOAuthProfile{subject: "google-user", email: "google@example.test"})
	challenge := appChallenge(strings.Repeat("a", 43))
	for _, query := range []string{
		"identity_policy=provider_subject",
		"app_code_challenge=" + challenge,
		"app_code_challenge=" + challenge + "&app_code_challenge_method=plain&identity_policy=provider_subject",
		"app_code_challenge=" + challenge + "&app_code_challenge_method=S256&identity_policy=email",
		"app_code_challenge=invalid&app_code_challenge_method=S256&identity_policy=provider_subject",
	} {
		rec := env.request(t, "GET", "/api/auth/oauth/google?"+query, nil, env.apiHeaders())
		assertStatus(t, rec, http.StatusBadRequest)
		if rec.Header().Get("X-App-Session-Binding") != "" {
			t.Fatal("invalid begin must not claim app binding")
		}
	}
	rec := env.request(t, "GET", "/api/auth/oauth/github?"+appOAuthQuery(strings.Repeat("a", 43)), nil, env.apiHeaders())
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestAppOAuthExchangeBindsVerifierAndPreservesCodeAfterMismatch(t *testing.T) {
	env := appOAuthEnv(t, &appOAuthProfile{subject: "google-subject-1", email: "google@example.test"})
	verifier := strings.Repeat("a", 43)
	code := appOAuthCode(t, env, verifier)
	// An old deployed exchange ignores verifier metadata but only knows the
	// legacy namespace. It must not find strict credentials during rollout.
	legacyRaw, legacyErr := env.cache.Get(context.Background(), "auth_redirect:"+application.HashToken(code))
	if legacyErr == nil || legacyRaw != "" || !strings.HasPrefix(code, boundRedirectCodePrefix) {
		t.Fatal("old unbound exchange can discover a strict code")
	}
	for _, wrong := range []string{"", strings.Repeat("b", 43), strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 42) + "!"} {
		rec := env.request(t, "POST", "/api/auth/redirect/exchange", map[string]string{"code": code, "code_verifier": wrong}, nil)
		assertStatus(t, rec, http.StatusBadRequest)
		if strings.Contains(rec.Body.String(), "access_token") {
			t.Fatal("invalid verifier leaked credentials")
		}
	}
	rec := env.request(t, "POST", "/api/auth/redirect/exchange", map[string]string{"code": code, "code_verifier": verifier}, nil)
	assertStatus(t, rec, http.StatusOK)
	var resp application.AuthResponse
	decodeBody(t, rec, &resp)
	if resp.AccessToken == "" || resp.RefreshToken == "" || resp.AppSessionBinding != "S256" || resp.IdentityPolicy != "provider_subject" || resp.Provider != "google" || resp.ProviderSubject != "google-subject-1" {
		t.Fatalf("strict exchange metadata missing: %+v", resp)
	}
	if strings.Contains(rec.Body.String(), "_app_code_challenge") || strings.Contains(rec.Body.String(), verifier) {
		t.Fatal("private cache binding material returned")
	}
	replay := env.request(t, "POST", "/api/auth/redirect/exchange", map[string]string{"code": code, "code_verifier": verifier}, nil)
	assertStatus(t, replay, http.StatusBadRequest)
}

func TestAppOAuthConcurrentExchangeHasOneWinner(t *testing.T) {
	env := appOAuthEnv(t, &appOAuthProfile{subject: "google-subject", email: "google@example.test"})
	verifier := strings.Repeat("c", 43)
	code := appOAuthCode(t, env, verifier)
	var wg sync.WaitGroup
	results := make(chan int, 8)
	for range 8 {
		wg.Go(func() {
			rec := env.request(t, "POST", "/api/auth/redirect/exchange", map[string]string{"code": code, "code_verifier": verifier}, nil)
			results <- rec.Code
		})
	}
	wg.Wait()
	close(results)
	winners := 0
	for status := range results {
		if status == 200 {
			winners++
		} else if status != 400 {
			t.Fatalf("unexpected exchange status %d", status)
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent exchange winners=%d, want 1", winners)
	}
}

func TestAppOAuthStrictIdentityNeverMergesEmailAndLegacyRemainsCompatible(t *testing.T) {
	profile := &appOAuthProfile{subject: "first-google-subject", email: "shared@example.test"}
	env := appOAuthEnv(t, profile)
	existing, err := env.users.CreateOAuth(context.Background(), env.client.ID, profile.email, "Existing", "")
	if err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("d", 43)
	conflict := appOAuthCallback(t, env, appOAuthQuery(verifier))
	if strings.Contains(conflict.Header().Get("Location"), "auth_code=") {
		t.Fatal("strict flow merged an existing email into the provider subject")
	}
	if _, err := env.oauth.FindByProvider(context.Background(), env.client.ID, "google", profile.subject); err != domain.ErrNotFound {
		t.Fatalf("strict email conflict must not link an account: %v", err)
	}
	// Legacy clients continue their existing email-linking behavior and receive
	// no strict-policy or browser-binding assertion.
	legacy := appOAuthCallback(t, env, "session_mode=token")
	resp := authResponseFromRedirect(t, env, legacy.Header().Get("Location"))
	if resp.AppSessionBinding != "" || resp.IdentityPolicy != "" || resp.Provider != "" || resp.ProviderSubject != "" {
		t.Fatal("legacy exchange falsely claimed strict binding")
	}
	account, err := env.oauth.FindByProvider(context.Background(), env.client.ID, "google", profile.subject)
	if err != nil || account.UserID != existing.ID {
		t.Fatalf("legacy email-linking compatibility changed: %#v, %v", account, err)
	}
	// Existing provider links resolve by subject, even if the provider email
	// changes to another user's address. The different user is never selected.
	other, err := env.users.CreateOAuth(context.Background(), env.client.ID, "other@example.test", "Other", "")
	if err != nil {
		t.Fatal(err)
	}
	profile.email = other.Email
	code := appOAuthCode(t, env, verifier)
	strict := env.request(t, "POST", "/api/auth/redirect/exchange", map[string]string{"code": code, "code_verifier": verifier}, nil)
	assertStatus(t, strict, 200)
	decodeBody(t, strict, &resp)
	claims, err := application.ValidateAccessToken(context.Background(), env.client, resp.AccessToken)
	if err != nil || claims.Subject != existing.ID || claims.Subject == other.ID {
		t.Fatalf("stable provider subject changed with email: %#v, %v", claims, err)
	}
}

func TestAppOAuthStrictRejectsMissingProviderSubjectAndStateReplay(t *testing.T) {
	profile := &appOAuthProfile{email: "user@example.test"}
	env := appOAuthEnv(t, profile)
	query := appOAuthQuery(strings.Repeat("e", 43))
	begin := env.request(t, "GET", "/api/auth/oauth/google?"+query, nil, env.apiHeaders())
	location, _ := url.Parse(begin.Header().Get("Location"))
	callbackURL := "/api/auth/oauth/google/callback?code=provider-code&state=" + url.QueryEscape(location.Query().Get("state"))
	callback := env.request(t, "GET", callbackURL, nil, nil)
	if strings.Contains(callback.Header().Get("Location"), "auth_code=") {
		t.Fatal("empty provider subject established a session")
	}
	profile.subject = "later-subject"
	replay := env.request(t, "GET", callbackURL, nil, nil)
	if strings.Contains(replay.Header().Get("Location"), "auth_code=") {
		t.Fatal("reused OAuth state established a session")
	}
}

func TestAppOAuthStrictRejectsUnsuccessfulUserInfo(t *testing.T) {
	env := appOAuthEnv(t, &appOAuthProfile{subject: "untrusted-error-id", email: "user@example.test", status: http.StatusUnauthorized})
	callback := appOAuthCallback(t, env, appOAuthQuery(strings.Repeat("f", 43)))
	if strings.Contains(callback.Header().Get("Location"), "auth_code=") {
		t.Fatal("non-successful userinfo must not establish strict identity")
	}
}
