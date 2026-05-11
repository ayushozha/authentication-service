package rest

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ayush10/authentication-service/internal/application"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"github.com/pquerna/otp/totp"
)

type browserAPIResult struct {
	OK     bool                   `json:"ok"`
	Status int                    `json:"status"`
	Body   map[string]interface{} `json:"body"`
	Error  string                 `json:"error"`
	Name   string                 `json:"name"`
}

func TestBrowserGradePasskeyRegistrationLoginAndRejectedSignature(t *testing.T) {
	chromePath := requireChrome(t)
	env := newE2EEnv(t, e2eOptions{})
	user := signupE2EUser(t, env, "browser-passkey@example.com", e2ePassword)
	server, baseURL := startBrowserE2EServer(t, env)
	defer server.Close()

	env.clients.setAllowedOrigins(env.client.ID, []string{baseURL})
	env.clients.setSettings(env.client.ID, map[string]interface{}{
		"webauthn_display_name": "Browser E2E Auth",
		"webauthn_rp_id":        "localhost",
		"webauthn_rp_origin":    baseURL,
	})

	ctx, cancel := newBrowserContext(t, chromePath)
	defer cancel()

	var authenticatorID webauthn.AuthenticatorID
	err := chromedp.Run(ctx,
		webauthn.Enable(),
		chromedp.ActionFunc(func(ctx context.Context) error {
			id, err := webauthn.AddVirtualAuthenticator(&webauthn.VirtualAuthenticatorOptions{
				Protocol:                    webauthn.AuthenticatorProtocolCtap2,
				Ctap2version:                webauthn.Ctap2versionCtap21,
				Transport:                   webauthn.AuthenticatorTransportInternal,
				HasResidentKey:              true,
				HasUserVerification:         true,
				AutomaticPresenceSimulation: true,
				IsUserVerified:              true,
				DefaultBackupEligibility:    true,
				DefaultBackupState:          true,
			}).Do(ctx)
			if err != nil {
				return err
			}
			authenticatorID = id
			return nil
		}),
		chromedp.Navigate(baseURL+"/webauthn-test"),
		chromedp.WaitReady("body", chromedp.ByQuery),
	)
	if err != nil {
		t.Fatalf("prepare browser WebAuthn context: %v", err)
	}

	register := evalBrowserAPI(t, ctx, fmt.Sprintf(`window.registerPasskey(%q, %q)`, env.apiKey, user.AccessToken))
	if !register.OK || register.Status != http.StatusCreated {
		t.Fatalf("passkey registration failed: %+v", register)
	}

	passkeysRec := env.request(t, http.MethodGet, "/api/auth/passkeys", nil, env.bearerHeaders(user.AccessToken))
	assertStatus(t, passkeysRec, http.StatusOK)
	if !strings.Contains(passkeysRec.Body.String(), "MacBook browser test") {
		t.Fatalf("registered passkey was not listed: %s", passkeysRec.Body.String())
	}

	login := evalBrowserAPI(t, ctx, fmt.Sprintf(`window.loginPasskey(%q)`, env.apiKey))
	if !login.OK || login.Status != http.StatusOK || login.Body["access_token"] == "" || login.Body["refresh_token"] == "" {
		t.Fatalf("passkey login failed: %+v", login)
	}

	if err := chromedp.Run(ctx, webauthn.SetResponseOverrideBits(authenticatorID).WithIsBogusSignature(true)); err != nil {
		t.Fatalf("enable bogus passkey signature override: %v", err)
	}
	bogusLogin := evalBrowserAPI(t, ctx, fmt.Sprintf(`window.loginPasskey(%q)`, env.apiKey))
	if bogusLogin.Status != http.StatusUnauthorized {
		t.Fatalf("bogus passkey signature should be rejected with 401, got %+v", bogusLogin)
	}

	if err := chromedp.Run(ctx, webauthn.SetResponseOverrideBits(authenticatorID)); err != nil {
		t.Fatalf("clear passkey signature override: %v", err)
	}
	recoveredLogin := evalBrowserAPI(t, ctx, fmt.Sprintf(`window.loginPasskey(%q)`, env.apiKey))
	if !recoveredLogin.OK || recoveredLogin.Status != http.StatusOK || recoveredLogin.Body["access_token"] == "" {
		t.Fatalf("passkey login did not recover after clearing signature override: %+v", recoveredLogin)
	}
}

func TestBrowserPublicAuthPagesWorkOnDesktopIOSAndAndroidProfiles(t *testing.T) {
	chromePath := requireChrome(t)

	for idx, profile := range browserDeviceProfiles() {
		t.Run(profile.name, func(t *testing.T) {
			runPublicAuthPagesBrowserFlow(t, chromePath, profile, idx)
		})
	}
}

func TestBrowserPortalShellRendersOnDesktopIOSAndAndroidProfiles(t *testing.T) {
	chromePath := requireChrome(t)

	for _, profile := range browserDeviceProfiles() {
		t.Run(profile.name, func(t *testing.T) {
			env := newE2EEnv(t, e2eOptions{})
			server, baseURL := startBrowserE2EServer(t, env)
			defer server.Close()

			ctx, cancel := newBrowserContext(t, chromePath)
			defer cancel()

			actions := profile.actions()
			actions = append(actions,
				chromedp.Navigate(baseURL+"/portal.html"),
				chromedp.WaitVisible("#adminWorkspace", chromedp.ByQuery),
				chromedp.WaitVisible("#clientsTable", chromedp.ByQuery),
				chromedp.Click(`[data-workspace="account"]`, chromedp.ByQuery),
				chromedp.WaitVisible("#accountWorkspace", chromedp.ByQuery),
			)
			if err := chromedp.Run(ctx, actions...); err != nil {
				t.Fatalf("portal shell did not render: %v", err)
			}

			var portal struct {
				Title                 string `json:"title"`
				AccountVisible        bool   `json:"accountVisible"`
				AdminVisible          bool   `json:"adminVisible"`
				HasHorizontalOverflow bool   `json:"hasHorizontalOverflow"`
			}
			if err := chromedp.Run(ctx, chromedp.Evaluate(`(() => {
				const root = document.documentElement;
				const admin = document.querySelector("#adminWorkspace");
				const account = document.querySelector("#accountWorkspace");
				return {
					title: document.querySelector("#workspaceTitle")?.textContent || "",
					accountVisible: account && getComputedStyle(account).display !== "none",
					adminVisible: admin && getComputedStyle(admin).display !== "none",
					hasHorizontalOverflow: root.scrollWidth > root.clientWidth + 1
				};
			})()`, &portal)); err != nil {
				t.Fatalf("inspect portal layout: %v", err)
			}
			if portal.Title != "Account Portal" || !portal.AccountVisible || portal.AdminVisible {
				t.Fatalf("portal workspace switch failed: %+v", portal)
			}
			if portal.HasHorizontalOverflow {
				t.Fatalf("portal has horizontal document overflow on %s: %+v", profile.name, portal)
			}
		})
	}
}

func TestBrowserSDKSignupOrganizationsAndUserWidget(t *testing.T) {
	chromePath := requireChrome(t)
	env := newE2EEnv(t, e2eOptions{})
	server, baseURL := startBrowserE2EServer(t, env)
	defer server.Close()
	env.clients.setAllowedOrigins(env.client.ID, []string{baseURL})

	ctx, cancel := newBrowserContext(t, chromePath)
	defer cancel()

	email := fmt.Sprintf("browser-sdk-%d@example.com", time.Now().UnixNano())
	slug := fmt.Sprintf("browser-sdk-%d", time.Now().UnixNano())

	var result struct {
		OK           bool   `json:"ok"`
		Email        string `json:"email"`
		Display      string `json:"display"`
		WidgetText   string `json:"widgetText"`
		LoginCode    string `json:"loginCode"`
		PasskeyCode  string `json:"passkeyCode"`
		PasskeyError string `json:"passkeyError"`
		Error        string `json:"error"`
	}
	expr := fmt.Sprintf(`(async () => {
		try {
			const client = AuthService.createClient({ baseUrl: location.origin, apiKey: %q, sessionMode: "token" });
			const signup = await client.signup({ email: %q, password: %q, display_name: "SDK User" });
			if (!signup.access_token || !client.getAccessToken() || !client.getRefreshToken()) throw new Error("signup did not persist token session");

			let loginError = null;
			try {
				await client.login({ email: %q, password: "wrong-password" });
			} catch (err) {
				loginError = err;
			}
			if (!loginError || loginError.code !== "AUTH_INVALID_CREDENTIALS" || loginError.message !== "Invalid email or password." || loginError.retryable !== false) {
				throw new Error("login error was not canonical: " + JSON.stringify({
					code: loginError && loginError.code,
					message: loginError && loginError.message,
					retryable: loginError && loginError.retryable,
					providerCode: loginError && loginError.providerCode
				}));
			}

			let passkeyError = null;
			try {
				await client.request("/api/auth/passkey/login/finish", { method: "POST", body: {}, auth: false });
			} catch (err) {
				passkeyError = err;
			}
			if (!passkeyError || passkeyError.code !== "AUTH_INVALID_REQUEST" || passkeyError.message !== "We could not process that request. Try again." || passkeyError.providerCode !== "session_id_required" || passkeyError.retryable !== false) {
				throw new Error("passkey error was not canonical: " + JSON.stringify({
					code: passkeyError && passkeyError.code,
					message: passkeyError && passkeyError.message,
					retryable: passkeyError && passkeyError.retryable,
					providerCode: passkeyError && passkeyError.providerCode
				}));
			}

			const me = await client.me();
			const updated = await client.updateProfile({ display_name: "SDK Renamed", timezone: "America/Los_Angeles" });
			const org = await client.createOrganization({ name: "SDK Org", slug: %q });
			if (!org.organization || !org.organization.id) throw new Error("organization was not created");
			const orgToken = await client.createOrganizationToken(org.organization.id);
			if (!orgToken.access_token) throw new Error("organization token was not minted");

			const widget = client.mountUserButton(document.getElementById("widget"));
			await widget.refresh();
			const widgetText = document.getElementById("widget").textContent;
			return {
				ok: me.email === %q && updated.display_name === "SDK Renamed" && widgetText.includes("SDK Renamed"),
				email: me.email,
				display: updated.display_name,
				widgetText,
				loginCode: loginError.code,
				passkeyCode: passkeyError.code,
				passkeyError: passkeyError.message
			};
		} catch (err) {
			return { ok: false, error: err && err.message ? err.message : String(err) };
		}
	})()`, env.apiKey, email, e2ePassword, email, slug, email)

	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/sdk-test"),
		chromedp.WaitReady("#widget", chromedp.ByQuery),
		chromedp.Evaluate(expr, &result, evalAwaitPromise),
	); err != nil {
		t.Fatalf("SDK browser flow failed: %v", err)
	}
	if !result.OK {
		t.Fatalf("SDK browser flow returned failure: %+v", result)
	}
}

func runPublicAuthPagesBrowserFlow(t *testing.T, chromePath string, profile browserDeviceProfile, idx int) {
	t.Helper()

	env := newE2EEnv(t, e2eOptions{})
	server, baseURL := startBrowserE2EServer(t, env)
	defer server.Close()
	env.cfg.BaseURL = baseURL
	env.clients.setAllowedOrigins(env.client.ID, []string{baseURL})

	ctx, cancel := newBrowserContext(t, chromePath)
	defer cancel()

	email := fmt.Sprintf("browser-pages-%d-%d@example.com", idx, time.Now().UnixNano())
	resetPassword := "newpassword123"

	signupActions := profile.actions()
	signupActions = append(signupActions,
		chromedp.Navigate(baseURL+"/signup.html?api_key="+url.QueryEscape(env.apiKey)),
		chromedp.WaitVisible("#signupForm", chromedp.ByQuery),
		chromedp.SendKeys("#name", "Browser Test", chromedp.ByQuery),
		chromedp.SendKeys("#email", email, chromedp.ByQuery),
		chromedp.SendKeys("#password", e2ePassword, chromedp.ByQuery),
		chromedp.SendKeys("#confirmPassword", e2ePassword, chromedp.ByQuery),
		chromedp.Click("#tos", chromedp.ByQuery),
		chromedp.Click("#signupBtn", chromedp.ByQuery),
		chromedp.WaitVisible("#msg.success", chromedp.ByQuery),
	)
	if err := chromedp.Run(ctx, signupActions...); err != nil {
		t.Fatalf("signup page flow failed: %v", err)
	}
	if token := readBrowserAccessToken(t, ctx); token == "" {
		t.Fatal("signup page did not store an access token")
	}

	verifyURL := browserURLWithAPIKey(t, env.mailer.waitForVerifyURL(t), baseURL, env.apiKey)
	if err := chromedp.Run(ctx,
		chromedp.Navigate(verifyURL),
		chromedp.WaitVisible("#iconSuccess", chromedp.ByQuery),
	); err != nil {
		t.Fatalf("verify-email page flow failed: %v", err)
	}

	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/forgot-password.html?api_key="+url.QueryEscape(env.apiKey)),
		chromedp.WaitVisible("#forgotForm", chromedp.ByQuery),
		chromedp.SendKeys("#email", email, chromedp.ByQuery),
		chromedp.Click("#submitBtn", chromedp.ByQuery),
		chromedp.WaitVisible("#msg.success", chromedp.ByQuery),
	); err != nil {
		t.Fatalf("forgot-password page flow failed: %v", err)
	}

	resetURL := browserURLWithAPIKey(t, env.mailer.waitForPasswordResetURL(t), baseURL, env.apiKey)
	if err := chromedp.Run(ctx,
		chromedp.Navigate(resetURL),
		chromedp.WaitVisible("#resetForm", chromedp.ByQuery),
		chromedp.SendKeys("#password", resetPassword, chromedp.ByQuery),
		chromedp.SendKeys("#confirmPassword", resetPassword, chromedp.ByQuery),
		chromedp.Click("#resetBtn", chromedp.ByQuery),
		chromedp.WaitVisible("#msg.success", chromedp.ByQuery),
	); err != nil {
		t.Fatalf("reset-password page flow failed: %v", err)
	}

	if err := browserLogin(t, ctx, baseURL, env.apiKey, email, resetPassword); err != nil {
		t.Fatalf("login page flow failed: %v", err)
	}
	accessToken := readBrowserAccessToken(t, ctx)
	if accessToken == "" {
		t.Fatal("login page did not store an access token")
	}

	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/login.html?api_key="+url.QueryEscape(env.apiKey)),
		chromedp.WaitVisible("#loginForm", chromedp.ByQuery),
		chromedp.Click("#magicLinkToggle", chromedp.ByQuery),
		chromedp.WaitVisible("#magicSection", chromedp.ByQuery),
		chromedp.SendKeys("#magicEmail", email, chromedp.ByQuery),
		chromedp.Click("#magicForm button", chromedp.ByQuery),
		chromedp.WaitVisible("#msg.success", chromedp.ByQuery),
	); err != nil {
		t.Fatalf("magic-link page send flow failed: %v", err)
	}
	magicURL := rewriteURLToBase(t, env.mailer.waitForMagicURL(t), baseURL)
	magicResult := evalBrowserAPI(t, ctx, verifyMagicLinkExpression(magicURL))
	if !magicResult.OK || magicResult.Status != http.StatusOK || magicResult.Body["access_token"] == "" {
		t.Fatalf("magic-link browser verification failed: %+v", magicResult)
	}

	setupRec := env.request(t, http.MethodPost, "/api/auth/totp/setup", nil, env.bearerHeaders(accessToken))
	assertStatus(t, setupRec, http.StatusOK)
	var setup application.TOTPSetupResponse
	decodeBody(t, setupRec, &setup)
	code, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP setup code: %v", err)
	}
	enableRec := env.request(t, http.MethodPost, "/api/auth/totp/enable", map[string]string{"code": code}, env.bearerHeaders(accessToken))
	assertStatus(t, enableRec, http.StatusOK)

	loginCode, err := totp.GenerateCode(setup.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP login code: %v", err)
	}
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/login.html?api_key="+url.QueryEscape(env.apiKey)),
		chromedp.WaitVisible("#loginForm", chromedp.ByQuery),
		chromedp.SendKeys("#email", email, chromedp.ByQuery),
		chromedp.SendKeys("#password", resetPassword, chromedp.ByQuery),
		chromedp.Click("#loginBtn", chromedp.ByQuery),
		chromedp.WaitVisible("#totpSection", chromedp.ByQuery),
		chromedp.SendKeys("#totpCode", loginCode, chromedp.ByQuery),
		chromedp.Click("#totpBtn", chromedp.ByQuery),
		chromedp.WaitVisible("#msg.success", chromedp.ByQuery),
	); err != nil {
		t.Fatalf("TOTP browser login flow failed: %v", err)
	}
	if token := readBrowserAccessToken(t, ctx); token == "" {
		t.Fatal("TOTP login page did not store an access token")
	}
}

type browserDeviceProfile struct {
	name      string
	width     int64
	height    int64
	scale     float64
	mobile    bool
	userAgent string
	platform  string
}

func browserDeviceProfiles() []browserDeviceProfile {
	return []browserDeviceProfile{
		{
			name:   "Desktop Chrome",
			width:  1280,
			height: 900,
			scale:  1,
		},
		{
			name:     "iOS Safari viewport",
			width:    390,
			height:   844,
			scale:    3,
			mobile:   true,
			platform: "iPhone",
			userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 " +
				"(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
		},
		{
			name:     "Android Chrome viewport",
			width:    412,
			height:   915,
			scale:    2.625,
			mobile:   true,
			platform: "Android",
			userAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 " +
				"(KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
		},
	}
}

func (p browserDeviceProfile) actions() []chromedp.Action {
	actions := []chromedp.Action{
		emulation.SetDeviceMetricsOverride(p.width, p.height, p.scale, p.mobile).
			WithScreenWidth(p.width).
			WithScreenHeight(p.height),
	}
	if p.mobile {
		actions = append(actions, emulation.SetTouchEmulationEnabled(true).WithMaxTouchPoints(5))
	}
	if p.userAgent != "" {
		actions = append(actions, emulation.SetUserAgentOverride(p.userAgent).WithPlatform(p.platform))
	}
	return actions
}

func browserLogin(t *testing.T, ctx context.Context, baseURL, apiKey, email, password string) error {
	t.Helper()
	return chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/login.html?api_key="+url.QueryEscape(apiKey)),
		chromedp.WaitVisible("#loginForm", chromedp.ByQuery),
		chromedp.SendKeys("#email", email, chromedp.ByQuery),
		chromedp.SendKeys("#password", password, chromedp.ByQuery),
		chromedp.Click("#loginBtn", chromedp.ByQuery),
		chromedp.WaitVisible("#msg.success", chromedp.ByQuery),
	)
}

func readBrowserAccessToken(t *testing.T, ctx context.Context) string {
	t.Helper()
	var accessToken string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`localStorage.getItem("auth_access_token") || ""`, &accessToken)); err != nil {
		t.Fatalf("read browser access token: %v", err)
	}
	return accessToken
}

func browserURLWithAPIKey(t *testing.T, rawURL, baseURL, apiKey string) string {
	t.Helper()
	rewritten := rewriteURLToBase(t, rawURL, baseURL)
	parsed, err := url.Parse(rewritten)
	if err != nil {
		t.Fatalf("parse browser url %q: %v", rewritten, err)
	}
	query := parsed.Query()
	query.Set("api_key", apiKey)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func rewriteURLToBase(t *testing.T, rawURL, baseURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse generated auth url %q: %v", rawURL, err)
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse browser base url %q: %v", baseURL, err)
	}
	parsed.Scheme = base.Scheme
	parsed.Host = base.Host
	return parsed.String()
}

func verifyMagicLinkExpression(rawURL string) string {
	return fmt.Sprintf(`(async () => {
  try {
    const response = await fetch(%q, { headers: { Accept: 'application/json' } });
    let body = {};
    try { body = await response.json(); } catch (_) {}
    return { ok: response.ok, status: response.status, body };
  } catch (error) {
    return { ok: false, status: 0, error: String(error), name: error.name || '' };
  }
})()`, rawURL)
}

func evalBrowserAPI(t *testing.T, ctx context.Context, expression string) browserAPIResult {
	t.Helper()
	var result browserAPIResult
	if err := chromedp.Run(ctx, chromedp.Evaluate(expression, &result, evalAwaitPromise)); err != nil {
		t.Fatalf("evaluate browser expression %q: %v", expression, err)
	}
	return result
}

func evalAwaitPromise(params *runtime.EvaluateParams) *runtime.EvaluateParams {
	return params.WithAwaitPromise(true).WithReturnByValue(true)
}

func newBrowserContext(t *testing.T, chromePath string) (context.Context, context.CancelFunc) {
	t.Helper()
	userDataDir := t.TempDir()
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.UserDataDir(userDataDir),
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.Flag("host-resolver-rules", "MAP localhost 127.0.0.1"),
		chromedp.Flag("enable-features", "WebAuthenticationJSONSerialization"),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	ctx, timeoutCancel := context.WithTimeout(browserCtx, 45*time.Second)
	cancel := func() {
		timeoutCancel()
		browserCancel()
		allocCancel()
	}
	return ctx, cancel
}

func requireChrome(t *testing.T) string {
	t.Helper()
	chromePath := findChromePath()
	if chromePath == "" {
		t.Skip("Chrome/Chromium not found; install Chrome or set CHROME_BIN to run browser-grade E2E tests")
	}
	return chromePath
}

func findChromePath() string {
	for _, envName := range []string{"CHROME_BIN", "CHROMEDP_BROWSER_PATH"} {
		if path := strings.TrimSpace(os.Getenv(envName)); path != "" && isExecutable(path) {
			return path
		}
	}
	for _, path := range []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
	} {
		if isExecutable(path) {
			return path
		}
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if path, err := exec.LookPath(name); err == nil && isExecutable(path) {
			return path
		}
	}
	return ""
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0111 != 0
}

func startBrowserE2EServer(t *testing.T, env *e2eEnv) (*httptest.Server, string) {
	t.Helper()

	publicDir, err := filepath.Abs("../../../public")
	if err != nil {
		t.Fatalf("resolve public dir: %v", err)
	}
	fileServer := http.FileServer(http.Dir(publicDir))
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/webauthn-test":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(browserWebAuthnTestPage))
		case r.URL.Path == "/sdk-test":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(browserSDKTestPage))
		case strings.HasPrefix(r.URL.Path, "/api/"), strings.HasPrefix(r.URL.Path, "/.well-known/"), r.URL.Path == "/healthz":
			env.handler.ServeHTTP(w, r)
		default:
			fileServer.ServeHTTP(w, r)
		}
	})

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start browser test listener: %v", err)
	}
	server := &httptest.Server{
		Listener: listener,
		Config:   &http.Server{Handler: handler},
	}
	server.Start()
	port := listener.Addr().(*net.TCPAddr).Port
	return server, fmt.Sprintf("http://localhost:%d", port)
}

const browserWebAuthnTestPage = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>WebAuthn Browser E2E</title>
</head>
<body>
<script>
function base64urlToBuffer(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function headers(apiKey, accessToken) {
  const out = { 'Content-Type': 'application/json', 'X-API-Key': apiKey };
  if (accessToken) out.Authorization = 'Bearer ' + accessToken;
  return out;
}

async function jsonResult(response) {
  let body = {};
  try {
    body = await response.json();
  } catch (_) {}
  return { ok: response.ok, status: response.status, body };
}

async function registerPasskey(apiKey, accessToken) {
  try {
    const begin = await fetch('/api/auth/passkey/register/begin', {
      method: 'POST',
      headers: headers(apiKey, accessToken),
      credentials: 'include'
    });
    if (!begin.ok) return await jsonResult(begin);
    const options = await begin.json();
    options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
    options.publicKey.user.id = base64urlToBuffer(options.publicKey.user.id);
    if (options.publicKey.excludeCredentials) {
      options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map((credential) => {
        credential.id = base64urlToBuffer(credential.id);
        return credential;
      });
    }
    options.publicKey.authenticatorSelection = Object.assign({}, options.publicKey.authenticatorSelection || {}, {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required'
    });
    const credential = await navigator.credentials.create({ publicKey: options.publicKey });
    const finish = await fetch('/api/auth/passkey/register/finish?name=' + encodeURIComponent('MacBook browser test'), {
      method: 'POST',
      headers: headers(apiKey, accessToken),
      credentials: 'include',
      body: JSON.stringify({
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: bufferToBase64url(credential.response.attestationObject),
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON)
        }
      })
    });
    return await jsonResult(finish);
  } catch (error) {
    return { ok: false, status: 0, error: String(error), name: error.name || '' };
  }
}

async function loginPasskey(apiKey) {
  try {
    const begin = await fetch('/api/auth/passkey/login/begin', {
      method: 'POST',
      headers: headers(apiKey),
      credentials: 'include'
    });
    if (!begin.ok) return await jsonResult(begin);
    const options = await begin.json();
    const sessionID = options.session_id || '';
    options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
    if (options.publicKey.allowCredentials) {
      options.publicKey.allowCredentials = options.publicKey.allowCredentials.map((credential) => {
        credential.id = base64urlToBuffer(credential.id);
        return credential;
      });
    }
    const credential = await navigator.credentials.get({ publicKey: options.publicKey });
    const finish = await fetch('/api/auth/passkey/login/finish?session_mode=token&session_id=' + encodeURIComponent(sessionID), {
      method: 'POST',
      headers: headers(apiKey),
      credentials: 'include',
      body: JSON.stringify({
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: bufferToBase64url(credential.response.authenticatorData),
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          signature: bufferToBase64url(credential.response.signature),
          userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
        }
      })
    });
    return await jsonResult(finish);
  } catch (error) {
    return { ok: false, status: 0, error: String(error), name: error.name || '' };
  }
}

window.registerPasskey = registerPasskey;
window.loginPasskey = loginPasskey;
</script>
</body>
</html>`

const browserSDKTestPage = `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>AuthService SDK Browser E2E</title>
</head>
<body>
  <div id="widget"></div>
  <script src="/authservice.js"></script>
</body>
</html>`
