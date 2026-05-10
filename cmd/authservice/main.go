package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/pkg/jwtvalidator"
)

type cli struct {
	baseURL     string
	apiKey      string
	adminKey    string
	accessToken string
	httpClient  *http.Client
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "authservice:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	global := flag.NewFlagSet("authservice", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	c := &cli{httpClient: &http.Client{Timeout: 30 * time.Second}}
	global.StringVar(&c.baseURL, "base-url", getenv("AUTHSERVICE_BASE_URL", "http://localhost:8080"), "AuthService base URL")
	global.StringVar(&c.apiKey, "api-key", os.Getenv("AUTHSERVICE_API_KEY"), "client API key")
	global.StringVar(&c.adminKey, "admin-key", os.Getenv("AUTHSERVICE_ADMIN_KEY"), "admin API key")
	global.StringVar(&c.accessToken, "access-token", os.Getenv("AUTHSERVICE_ACCESS_TOKEN"), "user access token")
	if err := global.Parse(args); err != nil {
		return err
	}
	rest := global.Args()
	if len(rest) == 0 {
		usage()
		return nil
	}
	c.baseURL = strings.TrimRight(c.baseURL, "/")

	switch rest[0] {
	case "login":
		return c.login(rest[1:])
	case "token":
		return c.token(rest[1:])
	case "clients":
		return c.clients(rest[1:])
	case "service-accounts":
		return c.serviceAccounts(rest[1:])
	case "sso":
		return c.sso(rest[1:])
	case "scim":
		return c.scim(rest[1:])
	case "audit":
		return c.audit(rest[1:])
	case "key-rotation":
		return c.keyRotation(rest[1:])
	default:
		usage()
		return fmt.Errorf("unknown command %q", rest[0])
	}
}

func usage() {
	fmt.Println(`AuthService CLI

Usage:
  authservice [global flags] login --email user@example.com --password pass
  authservice [global flags] token inspect TOKEN [--jwks-url URL]
  authservice [global flags] clients list|create|get|update|rotate-api-key|rotate-jwt
  authservice [global flags] service-accounts list|create|get|update|disable|keys
  authservice [global flags] sso list|setup|get|update|delete
  authservice [global flags] scim list|setup|get|update|rotate-token
  authservice [global flags] audit export --format csv --output audit.csv
  authservice [global flags] key-rotation client-api-key|client-jwt|service-account-key|scim-token

Global flags may also come from AUTHSERVICE_BASE_URL, AUTHSERVICE_API_KEY, AUTHSERVICE_ADMIN_KEY, and AUTHSERVICE_ACCESS_TOKEN.`)
}

func (c *cli) login(args []string) error {
	fs := newFlagSet("login")
	email := fs.String("email", "", "email")
	password := fs.String("password", "", "password")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *email == "" || *password == "" {
		return errors.New("login requires --email and --password")
	}
	var out map[string]any
	if err := c.request(context.Background(), http.MethodPost, "/api/auth/login", map[string]any{
		"email":        *email,
		"password":     *password,
		"session_mode": "token",
	}, false, false, &out); err != nil {
		return err
	}
	return printJSON(out)
}

func (c *cli) token(args []string) error {
	if len(args) == 0 || args[0] != "inspect" {
		return errors.New("token supports: inspect")
	}
	fs := newFlagSet("token inspect")
	jwksURL := fs.String("jwks-url", "", "JWKS URL for verification")
	secret := fs.String("secret", "", "HS256 secret for verification")
	issuer := fs.String("issuer", "", "expected issuer")
	audience := fs.String("audience", "", "comma-separated expected audiences")
	clientID := fs.String("client-id", "", "expected client_id")
	tokenUse := fs.String("token-use", "", "expected token_use")
	scopes := fs.String("scopes", "", "comma-separated required scopes")
	orgPermissions := fs.String("org-permissions", "", "comma-separated required organization permissions")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("token inspect requires a token argument")
	}
	token := fs.Arg(0)
	if *jwksURL == "" && *secret == "" {
		header, payload, err := decodeJWTParts(token)
		if err != nil {
			return err
		}
		return printJSON(map[string]any{"verified": false, "header": header, "claims": payload})
	}
	validator := jwtvalidator.New(jwtvalidator.Config{
		Secret:                          *secret,
		JWKSURL:                         *jwksURL,
		Issuer:                          *issuer,
		Audience:                        csv(*audience),
		ClientID:                        *clientID,
		TokenUse:                        *tokenUse,
		RequiredScopes:                  csv(*scopes),
		RequiredOrganizationPermissions: csv(*orgPermissions),
	})
	claims, err := validator.Validate(token)
	if err != nil {
		return err
	}
	return printJSON(map[string]any{"verified": true, "claims": claims})
}

func (c *cli) clients(args []string) error {
	if len(args) == 0 {
		return errors.New("clients supports: list, create, get, update, rotate-api-key, rotate-jwt")
	}
	switch args[0] {
	case "list":
		var out any
		if err := c.request(context.Background(), http.MethodGet, "/api/admin/clients", nil, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "create":
		fs := newFlagSet("clients create")
		name := fs.String("name", "", "client name")
		slug := fs.String("slug", "", "client slug")
		origins := fs.String("allowed-origins", "", "comma-separated allowed origins")
		webhookURL := fs.String("webhook-url", "", "audit webhook URL")
		file := fs.String("file", "", "JSON request file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		body, err := requestBody(*file, map[string]any{"name": *name, "slug": *slug, "allowed_origins": csv(*origins), "webhook_url": *webhookURL})
		if err != nil {
			return err
		}
		var out any
		if err := c.request(context.Background(), http.MethodPost, "/api/admin/clients", body, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "get":
		id, err := singleArg(args[1:], "clients get requires CLIENT_ID")
		if err != nil {
			return err
		}
		var out any
		if err := c.request(context.Background(), http.MethodGet, "/api/admin/clients/"+url.PathEscape(id), nil, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "update":
		fs := newFlagSet("clients update")
		file := fs.String("file", "", "JSON request file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("clients update requires CLIENT_ID --file request.json")
		}
		body, err := requestBody(*file, nil)
		if err != nil {
			return err
		}
		var out any
		if err := c.request(context.Background(), http.MethodPatch, "/api/admin/clients/"+url.PathEscape(fs.Arg(0)), body, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "rotate-api-key", "rotate-jwt":
		id, err := singleArg(args[1:], "clients "+args[0]+" requires CLIENT_ID")
		if err != nil {
			return err
		}
		var out any
		if err := c.request(context.Background(), http.MethodPost, "/api/admin/clients/"+url.PathEscape(id)+"/"+args[0], nil, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	default:
		return fmt.Errorf("unknown clients action %q", args[0])
	}
}

func (c *cli) serviceAccounts(args []string) error {
	if len(args) == 0 {
		return errors.New("service-accounts supports: list, create, get, update, disable, keys")
	}
	if args[0] == "keys" {
		return c.serviceAccountKeys(args[1:])
	}
	fs := newFlagSet("service-accounts " + args[0])
	clientID := fs.String("client-id", "", "client ID")
	file := fs.String("file", "", "JSON request file")
	name := fs.String("name", "", "service account name")
	scopes := fs.String("scopes", "", "comma-separated scopes")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *clientID == "" {
		return errors.New("--client-id is required")
	}
	base := "/api/admin/clients/" + url.PathEscape(*clientID) + "/service-accounts"
	switch args[0] {
	case "list":
		var out any
		if err := c.request(context.Background(), http.MethodGet, base, nil, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "create":
		body, err := requestBody(*file, map[string]any{"name": *name, "scopes": csv(*scopes)})
		if err != nil {
			return err
		}
		var out any
		if err := c.request(context.Background(), http.MethodPost, base, body, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "get", "update", "disable":
		if fs.NArg() != 1 {
			return errors.New("service-accounts " + args[0] + " requires SERVICE_ACCOUNT_ID")
		}
		path := base + "/" + url.PathEscape(fs.Arg(0))
		method := http.MethodGet
		var body any
		if args[0] == "update" {
			method = http.MethodPatch
			var err error
			body, err = requestBody(*file, nil)
			if err != nil {
				return err
			}
		}
		if args[0] == "disable" {
			method = http.MethodDelete
		}
		var out any
		if err := c.request(context.Background(), method, path, body, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	default:
		return fmt.Errorf("unknown service-accounts action %q", args[0])
	}
}

func (c *cli) serviceAccountKeys(args []string) error {
	if len(args) == 0 {
		return errors.New("service-accounts keys supports: list, create, rotate, revoke")
	}
	fs := newFlagSet("service-accounts keys " + args[0])
	clientID := fs.String("client-id", "", "client ID")
	accountID := fs.String("service-account-id", "", "service account ID")
	name := fs.String("name", "", "key name")
	scopes := fs.String("scopes", "", "comma-separated scopes")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *clientID == "" || *accountID == "" {
		return errors.New("--client-id and --service-account-id are required")
	}
	base := "/api/admin/clients/" + url.PathEscape(*clientID) + "/service-accounts/" + url.PathEscape(*accountID) + "/keys"
	switch args[0] {
	case "list":
		var out any
		if err := c.request(context.Background(), http.MethodGet, base, nil, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "create":
		var out any
		if err := c.request(context.Background(), http.MethodPost, base, map[string]any{"name": *name, "scopes": csv(*scopes)}, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "rotate", "revoke":
		if fs.NArg() != 1 {
			return errors.New("service-accounts keys " + args[0] + " requires KEY_ID")
		}
		path := base + "/" + url.PathEscape(fs.Arg(0))
		method := http.MethodDelete
		if args[0] == "rotate" {
			method = http.MethodPost
			path += "/rotate"
		}
		var out any
		if err := c.request(context.Background(), method, path, nil, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	default:
		return fmt.Errorf("unknown service account key action %q", args[0])
	}
}

func (c *cli) sso(args []string) error {
	if len(args) == 0 {
		return errors.New("sso supports: list, setup, get, update, delete")
	}
	fs := newFlagSet("sso " + args[0])
	clientID := fs.String("client-id", "", "client ID")
	file := fs.String("file", "", "JSON request file")
	name := fs.String("name", "", "connection name")
	protocol := fs.String("protocol", "oidc", "oidc or saml")
	domains := fs.String("domains", "", "comma-separated domains")
	issuer := fs.String("issuer", "", "OIDC issuer")
	idpClientID := fs.String("idp-client-id", "", "OIDC client ID")
	idpClientSecret := fs.String("idp-client-secret", "", "OIDC client secret")
	idpMetadataURL := fs.String("idp-metadata-url", "", "SAML metadata URL")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *clientID == "" {
		return errors.New("--client-id is required")
	}
	base := "/api/admin/clients/" + url.PathEscape(*clientID) + "/sso-connections"
	switch args[0] {
	case "list":
		var out any
		if err := c.request(context.Background(), http.MethodGet, base, nil, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "setup":
		body := map[string]any{"name": *name, "protocol": *protocol, "domains": csv(*domains), "status": "active"}
		if *protocol == "oidc" {
			body["oidc"] = map[string]any{"issuer": *issuer, "client_id": *idpClientID, "client_secret": *idpClientSecret}
		} else {
			body["saml"] = map[string]any{"idp_metadata_url": *idpMetadataURL}
		}
		req, err := requestBody(*file, body)
		if err != nil {
			return err
		}
		var out any
		if err := c.request(context.Background(), http.MethodPost, base, req, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "get", "update", "delete":
		if fs.NArg() != 1 {
			return errors.New("sso " + args[0] + " requires CONNECTION_ID")
		}
		path := base + "/" + url.PathEscape(fs.Arg(0))
		method := http.MethodGet
		var body any
		if args[0] == "update" {
			method = http.MethodPatch
			var err error
			body, err = requestBody(*file, nil)
			if err != nil {
				return err
			}
		}
		if args[0] == "delete" {
			method = http.MethodDelete
		}
		var out any
		if err := c.request(context.Background(), method, path, body, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	default:
		return fmt.Errorf("unknown sso action %q", args[0])
	}
}

func (c *cli) scim(args []string) error {
	if len(args) == 0 {
		return errors.New("scim supports: list, setup, get, update, rotate-token")
	}
	fs := newFlagSet("scim " + args[0])
	clientID := fs.String("client-id", "", "client ID")
	file := fs.String("file", "", "JSON request file")
	name := fs.String("name", "", "directory name")
	domains := fs.String("domains", "", "comma-separated domains")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *clientID == "" {
		return errors.New("--client-id is required")
	}
	base := "/api/admin/clients/" + url.PathEscape(*clientID) + "/scim-directories"
	switch args[0] {
	case "list":
		var out any
		if err := c.request(context.Background(), http.MethodGet, base, nil, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "setup":
		body, err := requestBody(*file, map[string]any{"name": *name, "domains": csv(*domains)})
		if err != nil {
			return err
		}
		var out any
		if err := c.request(context.Background(), http.MethodPost, base, body, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	case "get", "update", "rotate-token":
		if fs.NArg() != 1 {
			return errors.New("scim " + args[0] + " requires DIRECTORY_ID")
		}
		path := base + "/" + url.PathEscape(fs.Arg(0))
		method := http.MethodGet
		var body any
		if args[0] == "update" {
			method = http.MethodPatch
			var err error
			body, err = requestBody(*file, nil)
			if err != nil {
				return err
			}
		}
		if args[0] == "rotate-token" {
			method = http.MethodPost
			path += "/rotate-token"
		}
		var out any
		if err := c.request(context.Background(), method, path, body, true, false, &out); err != nil {
			return err
		}
		return printJSON(out)
	default:
		return fmt.Errorf("unknown scim action %q", args[0])
	}
}

func (c *cli) audit(args []string) error {
	if len(args) == 0 || args[0] != "export" {
		return errors.New("audit supports: export")
	}
	fs := newFlagSet("audit export")
	format := fs.String("format", "csv", "csv or jsonl")
	output := fs.String("output", "", "output file")
	clientID := fs.String("client-id", "", "client filter")
	userID := fs.String("user-id", "", "user filter")
	eventType := fs.String("event-type", "", "event type filter")
	limit := fs.String("limit", "", "limit")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	values := url.Values{"format": []string{*format}}
	addQuery(values, "client_id", *clientID)
	addQuery(values, "user_id", *userID)
	addQuery(values, "event_type", *eventType)
	addQuery(values, "limit", *limit)
	raw, err := c.rawRequest(context.Background(), http.MethodGet, "/api/admin/audit-events/export?"+values.Encode(), nil, true, false)
	if err != nil {
		return err
	}
	if *output == "" {
		_, err = os.Stdout.Write(raw)
		return err
	}
	return os.WriteFile(*output, raw, 0o600)
}

func (c *cli) keyRotation(args []string) error {
	if len(args) == 0 {
		return errors.New("key-rotation supports: client-api-key, client-jwt, service-account-key, scim-token")
	}
	switch args[0] {
	case "client-api-key":
		return c.clients(append([]string{"rotate-api-key"}, args[1:]...))
	case "client-jwt":
		return c.clients(append([]string{"rotate-jwt"}, args[1:]...))
	case "service-account-key":
		return c.serviceAccountKeys(append([]string{"rotate"}, args[1:]...))
	case "scim-token":
		return c.scim(append([]string{"rotate-token"}, args[1:]...))
	default:
		return fmt.Errorf("unknown key-rotation action %q", args[0])
	}
}

func (c *cli) request(ctx context.Context, method, path string, body any, admin, auth bool, out any) error {
	raw, err := c.rawRequest(ctx, method, path, body, admin, auth)
	if err != nil {
		return err
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func (c *cli) rawRequest(ctx context.Context, method, path string, body any, admin, auth bool) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if admin {
		req.Header.Set("X-Admin-Key", c.adminKey)
	} else if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if auth && c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s %s failed: %s", method, path, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func getenv(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func csv(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func requestBody(file string, fallback map[string]any) (map[string]any, error) {
	if file == "" {
		if fallback == nil {
			return nil, errors.New("--file is required")
		}
		return fallback, nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	return body, nil
}

func printJSON(value any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func singleArg(args []string, message string) (string, error) {
	if len(args) != 1 {
		return "", errors.New(message)
	}
	return args[0], nil
}

func decodeJWTParts(token string) (map[string]any, map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, nil, errors.New("invalid JWT")
	}
	decode := func(part string) (map[string]any, error) {
		raw, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return nil, err
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	header, err := decode(parts[0])
	if err != nil {
		return nil, nil, err
	}
	payload, err := decode(parts[1])
	if err != nil {
		return nil, nil, err
	}
	return header, payload, nil
}

func addQuery(values url.Values, key, value string) {
	if strings.TrimSpace(value) != "" {
		values.Set(key, value)
	}
}
