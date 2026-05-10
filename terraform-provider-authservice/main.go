package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

type apiClient struct {
	baseURL     string
	adminKey    string
	apiKey      string
	accessToken string
	httpClient  *http.Client
}

func main() {
	plugin.Serve(&plugin.ServeOpts{ProviderFunc: Provider})
}

func Provider() *schema.Provider {
	p := &schema.Provider{
		Schema: map[string]*schema.Schema{
			"base_url": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("AUTHSERVICE_BASE_URL", nil),
				Description: "AuthService base URL.",
			},
			"admin_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AUTHSERVICE_ADMIN_KEY", nil),
				Description: "Admin API key for client, SSO, SCIM, and service-account resources.",
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AUTHSERVICE_API_KEY", nil),
				Description: "Client API key for organization resources.",
			},
			"access_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("AUTHSERVICE_ACCESS_TOKEN", nil),
				Description: "User access token for organization resources.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"authservice_client":          resourceClient(),
			"authservice_service_account": resourceServiceAccount(),
			"authservice_sso_connection":  resourceSSOConnection(),
			"authservice_scim_directory":  resourceSCIMDirectory(),
			"authservice_organization":    resourceOrganization(),
		},
	}
	p.ConfigureContextFunc = func(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
		return &apiClient{
			baseURL:     strings.TrimRight(d.Get("base_url").(string), "/"),
			adminKey:    d.Get("admin_key").(string),
			apiKey:      d.Get("api_key").(string),
			accessToken: d.Get("access_token").(string),
			httpClient:  &http.Client{Timeout: 30 * time.Second},
		}, nil
	}
	return p
}

func resourceClient() *schema.Resource {
	return &schema.Resource{
		CreateContext: createClientResource,
		ReadContext:   readClientResource,
		UpdateContext: updateClientResource,
		DeleteContext: deleteClientResource,
		Importer:      &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
		Schema: map[string]*schema.Schema{
			"name":            {Type: schema.TypeString, Required: true},
			"slug":            {Type: schema.TypeString, Optional: true},
			"allowed_origins": {Type: schema.TypeList, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}},
			"webhook_url":     {Type: schema.TypeString, Optional: true},
			"settings":        {Type: schema.TypeMap, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}},
			"status":          {Type: schema.TypeString, Optional: true, Computed: true},
			"token_mode":      {Type: schema.TypeString, Computed: true},
			"api_key":         {Type: schema.TypeString, Computed: true, Sensitive: true},
			"jwt_secret":      {Type: schema.TypeString, Computed: true, Sensitive: true},
		},
	}
}

func createClientResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	body := map[string]any{
		"name":            d.Get("name").(string),
		"slug":            d.Get("slug").(string),
		"allowed_origins": stringList(d.Get("allowed_origins").([]interface{})),
		"webhook_url":     d.Get("webhook_url").(string),
		"settings":        d.Get("settings").(map[string]interface{}),
	}
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodPost, "/api/admin/clients", body, true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	client := nestedMap(out, "client")
	d.SetId(stringValue(client["id"]))
	_ = d.Set("api_key", out["api_key"])
	_ = d.Set("jwt_secret", out["jwt_secret"])
	return setClientFields(d, client)
}

func readClientResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodGet, "/api/admin/clients/"+d.Id(), nil, true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	return setClientFields(d, out)
}

func updateClientResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	body := map[string]any{
		"name":            d.Get("name").(string),
		"allowed_origins": stringList(d.Get("allowed_origins").([]interface{})),
		"webhook_url":     d.Get("webhook_url").(string),
		"settings":        d.Get("settings").(map[string]interface{}),
		"status":          d.Get("status").(string),
	}
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodPatch, "/api/admin/clients/"+d.Id(), body, true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	return setClientFields(d, out)
}

func deleteClientResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	body := map[string]any{"status": "disabled"}
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodPatch, "/api/admin/clients/"+d.Id(), body, true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

func setClientFields(d *schema.ResourceData, client map[string]any) diag.Diagnostics {
	if client == nil {
		d.SetId("")
		return nil
	}
	_ = d.Set("name", client["name"])
	_ = d.Set("slug", client["slug"])
	_ = d.Set("allowed_origins", client["allowed_origins"])
	_ = d.Set("webhook_url", client["webhook_url"])
	_ = d.Set("settings", client["settings"])
	_ = d.Set("status", client["status"])
	_ = d.Set("token_mode", client["token_mode"])
	return nil
}

func resourceServiceAccount() *schema.Resource {
	return &schema.Resource{
		CreateContext: createServiceAccountResource,
		ReadContext:   readServiceAccountResource,
		UpdateContext: updateServiceAccountResource,
		DeleteContext: deleteServiceAccountResource,
		Schema: map[string]*schema.Schema{
			"client_id":     {Type: schema.TypeString, Required: true, ForceNew: true},
			"name":          {Type: schema.TypeString, Required: true},
			"description":   {Type: schema.TypeString, Optional: true},
			"scopes":        {Type: schema.TypeList, Required: true, Elem: &schema.Schema{Type: schema.TypeString}},
			"status":        {Type: schema.TypeString, Optional: true, Computed: true},
			"client_secret": {Type: schema.TypeString, Computed: true, Sensitive: true},
			"key_id":        {Type: schema.TypeString, Computed: true},
		},
	}
}

func createServiceAccountResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	clientID := d.Get("client_id").(string)
	body := serviceAccountBody(d)
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodPost, adminClientPath(clientID, "/service-accounts"), body, true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	account := nestedMap(out, "service_account")
	key := nestedMap(out, "key")
	d.SetId(stringValue(account["id"]))
	_ = d.Set("client_secret", out["client_secret"])
	_ = d.Set("key_id", key["id"])
	return setServiceAccountFields(d, account)
}

func readServiceAccountResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	clientID := d.Get("client_id").(string)
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodGet, adminClientPath(clientID, "/service-accounts/"+d.Id()), nil, true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	return setServiceAccountFields(d, out)
}

func updateServiceAccountResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	clientID := d.Get("client_id").(string)
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodPatch, adminClientPath(clientID, "/service-accounts/"+d.Id()), serviceAccountBody(d), true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	return setServiceAccountFields(d, out)
}

func deleteServiceAccountResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	clientID := d.Get("client_id").(string)
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodDelete, adminClientPath(clientID, "/service-accounts/"+d.Id()), nil, true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

func serviceAccountBody(d *schema.ResourceData) map[string]any {
	return map[string]any{
		"name":        d.Get("name").(string),
		"description": d.Get("description").(string),
		"scopes":      stringList(d.Get("scopes").([]interface{})),
		"status":      d.Get("status").(string),
	}
}

func setServiceAccountFields(d *schema.ResourceData, account map[string]any) diag.Diagnostics {
	if account == nil {
		d.SetId("")
		return nil
	}
	_ = d.Set("name", account["name"])
	_ = d.Set("description", account["description"])
	_ = d.Set("scopes", account["scopes"])
	_ = d.Set("status", account["status"])
	return nil
}

func resourceSSOConnection() *schema.Resource {
	return &schema.Resource{
		CreateContext: createSSOResource,
		ReadContext:   readSSOResource,
		UpdateContext: updateSSOResource,
		DeleteContext: deleteSSOResource,
		Schema: map[string]*schema.Schema{
			"client_id":           {Type: schema.TypeString, Required: true, ForceNew: true},
			"name":                {Type: schema.TypeString, Required: true},
			"slug":                {Type: schema.TypeString, Optional: true},
			"protocol":            {Type: schema.TypeString, Required: true},
			"status":              {Type: schema.TypeString, Optional: true, Computed: true},
			"domains":             {Type: schema.TypeList, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}},
			"enforce_for_domains": {Type: schema.TypeBool, Optional: true},
			"oidc":                {Type: schema.TypeMap, Optional: true, Sensitive: true},
			"saml":                {Type: schema.TypeMap, Optional: true, Sensitive: true},
			"attribute_mapping":   {Type: schema.TypeMap, Optional: true},
		},
	}
}

func createSSOResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	clientID := d.Get("client_id").(string)
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodPost, adminClientPath(clientID, "/sso-connections"), ssoBody(d), true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	d.SetId(stringValue(out["id"]))
	return setSSOFields(d, out)
}

func readSSOResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	clientID := d.Get("client_id").(string)
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodGet, adminClientPath(clientID, "/sso-connections/"+d.Id()), nil, true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	return setSSOFields(d, out)
}

func updateSSOResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	clientID := d.Get("client_id").(string)
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodPatch, adminClientPath(clientID, "/sso-connections/"+d.Id()), ssoBody(d), true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	return setSSOFields(d, out)
}

func deleteSSOResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	clientID := d.Get("client_id").(string)
	if err := meta.(*apiClient).request(ctx, http.MethodDelete, adminClientPath(clientID, "/sso-connections/"+d.Id()), nil, true, false, nil); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

func ssoBody(d *schema.ResourceData) map[string]any {
	return map[string]any{
		"name":                d.Get("name").(string),
		"slug":                d.Get("slug").(string),
		"protocol":            d.Get("protocol").(string),
		"status":              d.Get("status").(string),
		"domains":             stringList(d.Get("domains").([]interface{})),
		"enforce_for_domains": d.Get("enforce_for_domains").(bool),
		"oidc":                d.Get("oidc").(map[string]interface{}),
		"saml":                d.Get("saml").(map[string]interface{}),
		"attribute_mapping":   d.Get("attribute_mapping").(map[string]interface{}),
	}
}

func setSSOFields(d *schema.ResourceData, connection map[string]any) diag.Diagnostics {
	if connection == nil {
		d.SetId("")
		return nil
	}
	_ = d.Set("name", connection["name"])
	_ = d.Set("slug", connection["slug"])
	_ = d.Set("protocol", connection["protocol"])
	_ = d.Set("status", connection["status"])
	_ = d.Set("domains", connection["domains"])
	_ = d.Set("enforce_for_domains", connection["enforce_for_domains"])
	_ = d.Set("attribute_mapping", connection["attribute_mapping"])
	return nil
}

func resourceSCIMDirectory() *schema.Resource {
	return &schema.Resource{
		CreateContext: createSCIMResource,
		ReadContext:   readSCIMResource,
		UpdateContext: updateSCIMResource,
		DeleteContext: deleteSCIMResource,
		Schema: map[string]*schema.Schema{
			"client_id": {Type: schema.TypeString, Required: true, ForceNew: true},
			"name":      {Type: schema.TypeString, Required: true},
			"domains":   {Type: schema.TypeList, Optional: true, Elem: &schema.Schema{Type: schema.TypeString}},
			"status":    {Type: schema.TypeString, Optional: true, Computed: true},
			"token":     {Type: schema.TypeString, Computed: true, Sensitive: true},
		},
	}
}

func createSCIMResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	clientID := d.Get("client_id").(string)
	body := map[string]any{"name": d.Get("name").(string), "domains": stringList(d.Get("domains").([]interface{}))}
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodPost, adminClientPath(clientID, "/scim-directories"), body, true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	directory := nestedMap(out, "directory")
	d.SetId(stringValue(directory["id"]))
	_ = d.Set("token", out["token"])
	return setSCIMFields(d, directory)
}

func readSCIMResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	clientID := d.Get("client_id").(string)
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodGet, adminClientPath(clientID, "/scim-directories/"+d.Id()), nil, true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	return setSCIMFields(d, out)
}

func updateSCIMResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	clientID := d.Get("client_id").(string)
	body := map[string]any{"name": d.Get("name").(string), "domains": stringList(d.Get("domains").([]interface{})), "status": d.Get("status").(string)}
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodPatch, adminClientPath(clientID, "/scim-directories/"+d.Id()), body, true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	return setSCIMFields(d, out)
}

func deleteSCIMResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	clientID := d.Get("client_id").(string)
	body := map[string]any{"status": "disabled"}
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodPatch, adminClientPath(clientID, "/scim-directories/"+d.Id()), body, true, false, &out); err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return nil
}

func setSCIMFields(d *schema.ResourceData, directory map[string]any) diag.Diagnostics {
	if directory == nil {
		d.SetId("")
		return nil
	}
	_ = d.Set("name", directory["name"])
	_ = d.Set("domains", directory["domains"])
	_ = d.Set("status", directory["status"])
	return nil
}

func resourceOrganization() *schema.Resource {
	return &schema.Resource{
		CreateContext: createOrganizationResource,
		ReadContext:   readOrganizationResource,
		UpdateContext: updateOrganizationResource,
		DeleteContext: deleteOrganizationResource,
		Schema: map[string]*schema.Schema{
			"name": {Type: schema.TypeString, Required: true},
			"slug": {Type: schema.TypeString, Optional: true},
		},
	}
}

func createOrganizationResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	body := map[string]any{"name": d.Get("name").(string), "slug": d.Get("slug").(string)}
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodPost, "/api/auth/organizations", body, false, true, &out); err != nil {
		return diag.FromErr(err)
	}
	org := nestedMap(out, "organization")
	d.SetId(stringValue(org["id"]))
	return setOrganizationFields(d, org)
}

func readOrganizationResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodGet, "/api/auth/organizations/"+d.Id(), nil, false, true, &out); err != nil {
		return diag.FromErr(err)
	}
	return setOrganizationFields(d, nestedMap(out, "organization"))
}

func updateOrganizationResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	body := map[string]any{"name": d.Get("name").(string), "slug": d.Get("slug").(string)}
	var out map[string]any
	if err := meta.(*apiClient).request(ctx, http.MethodPatch, "/api/auth/organizations/"+d.Id(), body, false, true, &out); err != nil {
		return diag.FromErr(err)
	}
	return setOrganizationFields(d, out)
}

func deleteOrganizationResource(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}

func setOrganizationFields(d *schema.ResourceData, org map[string]any) diag.Diagnostics {
	if org == nil {
		d.SetId("")
		return nil
	}
	_ = d.Set("name", org["name"])
	_ = d.Set("slug", org["slug"])
	return nil
}

func (c *apiClient) request(ctx context.Context, method, path string, body any, admin, auth bool, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if admin {
		req.Header.Set("X-Admin-Key", c.adminKey)
	} else if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("not found")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s %s failed: %s", method, path, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return err
		}
	}
	return nil
}

func adminClientPath(clientID, suffix string) string {
	return "/api/admin/clients/" + clientID + suffix
}

func stringList(values []interface{}) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if text := strings.TrimSpace(fmt.Sprint(value)); text != "" {
			out = append(out, text)
		}
	}
	return out
}

func nestedMap(in map[string]any, key string) map[string]any {
	if in == nil {
		return nil
	}
	if value, ok := in[key].(map[string]any); ok {
		return value
	}
	return nil
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}
