package authservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type TokenStore interface {
	GetAccessToken() string
	SetAccessToken(string)
	GetRefreshToken() string
	SetRefreshToken(string)
}

type MemoryTokenStore struct {
	AccessToken  string
	RefreshToken string
}

func (s *MemoryTokenStore) GetAccessToken() string       { return s.AccessToken }
func (s *MemoryTokenStore) SetAccessToken(token string)  { s.AccessToken = token }
func (s *MemoryTokenStore) GetRefreshToken() string      { return s.RefreshToken }
func (s *MemoryTokenStore) SetRefreshToken(token string) { s.RefreshToken = token }

type Client struct {
	BaseURL     string
	APIKey      string
	AdminKey    string
	SessionMode string
	TokenStore  TokenStore
	HTTPClient  *http.Client
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), APIKey: apiKey, SessionMode: "token", TokenStore: &MemoryTokenStore{}, HTTPClient: http.DefaultClient}
}

func (c *Client) Request(ctx context.Context, method, path string, body any, admin bool, auth bool, out any) error {
	var reader io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			reader = strings.NewReader(v)
		default:
			raw, err := json.Marshal(v)
			if err != nil {
				return err
			}
			reader = bytes.NewReader(raw)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		if _, ok := body.(string); ok {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if admin && c.AdminKey != "" {
		req.Header.Set("X-Admin-Key", c.AdminKey)
	} else if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
	}
	if auth && c.TokenStore != nil && c.TokenStore.GetAccessToken() != "" {
		req.Header.Set("Authorization", "Bearer "+c.TokenStore.GetAccessToken())
	}
	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		return fmt.Errorf("authservice %s: %s", res.Status, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (c *Client) withSessionMode(body map[string]any) map[string]any {
	if body == nil {
		body = map[string]any{}
	}
	if c.SessionMode == "token" {
		if _, ok := body["session_mode"]; !ok {
			body["session_mode"] = "token"
		}
	}
	return body
}

func (c *Client) persist(resp map[string]any) map[string]any {
	if token, _ := resp["access_token"].(string); token != "" {
		c.TokenStore.SetAccessToken(token)
	}
	if token, _ := resp["refresh_token"].(string); token != "" {
		c.TokenStore.SetRefreshToken(token)
	}
	return resp
}

func (c *Client) Signup(ctx context.Context, body map[string]any) (map[string]any, error) {
	var out map[string]any
	err := c.Request(ctx, http.MethodPost, "/api/auth/signup", c.withSessionMode(body), false, false, &out)
	return c.persist(out), err
}

func (c *Client) Login(ctx context.Context, body map[string]any) (map[string]any, error) {
	var out map[string]any
	err := c.Request(ctx, http.MethodPost, "/api/auth/login", c.withSessionMode(body), false, false, &out)
	return c.persist(out), err
}

func (c *Client) Refresh(ctx context.Context) (map[string]any, error) {
	body := c.withSessionMode(map[string]any{"refresh_token": c.TokenStore.GetRefreshToken()})
	var out map[string]any
	err := c.Request(ctx, http.MethodPost, "/api/auth/refresh", body, false, false, &out)
	return c.persist(out), err
}

func (c *Client) Me(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.Request(ctx, http.MethodGet, "/api/auth/me", nil, false, true, &out)
}
func (c *Client) CreateClient(ctx context.Context, body map[string]any) (map[string]any, error) {
	var out map[string]any
	return out, c.Request(ctx, http.MethodPost, "/api/admin/clients", body, true, false, &out)
}
func (c *Client) ListClients(ctx context.Context) ([]map[string]any, error) {
	var out []map[string]any
	return out, c.Request(ctx, http.MethodGet, "/api/admin/clients", nil, true, false, &out)
}
func (c *Client) RotateClientAPIKey(ctx context.Context, id string) (map[string]any, error) {
	var out map[string]any
	return out, c.Request(ctx, http.MethodPost, "/api/admin/clients/"+url.PathEscape(id)+"/rotate-api-key", nil, true, false, &out)
}
func (c *Client) CreateServiceAccount(ctx context.Context, clientID string, body map[string]any) (map[string]any, error) {
	var out map[string]any
	return out, c.Request(ctx, http.MethodPost, "/api/admin/clients/"+url.PathEscape(clientID)+"/service-accounts", body, true, false, &out)
}
func (c *Client) CreateSSOConnection(ctx context.Context, clientID string, body map[string]any) (map[string]any, error) {
	var out map[string]any
	return out, c.Request(ctx, http.MethodPost, "/api/admin/clients/"+url.PathEscape(clientID)+"/sso-connections", body, true, false, &out)
}
func (c *Client) CreateSCIMDirectory(ctx context.Context, clientID string, body map[string]any) (map[string]any, error) {
	var out map[string]any
	return out, c.Request(ctx, http.MethodPost, "/api/admin/clients/"+url.PathEscape(clientID)+"/scim-directories", body, true, false, &out)
}
