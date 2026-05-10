package domain

import (
	"strings"
	"time"
)

const (
	EnterpriseDomainStatusPending  = "pending"
	EnterpriseDomainStatusVerified = "verified"
	EnterpriseDomainStatusFailed   = "failed"
)

const (
	EnterpriseProviderOkta            = "okta"
	EnterpriseProviderMicrosoftEntra  = "microsoft-entra"
	EnterpriseProviderGoogleWorkspace = "google-workspace"
	EnterpriseProviderPing            = "ping"
	EnterpriseProviderOneLogin        = "onelogin"
	EnterpriseProviderGenericSAML     = "generic-saml"
	EnterpriseProviderGenericOIDC     = "generic-oidc"
)

type EnterpriseDomainVerification struct {
	ID             string     `json:"id"`
	ClientID       string     `json:"client_id"`
	OrganizationID string     `json:"organization_id"`
	Domain         string     `json:"domain"`
	Status         string     `json:"status"`
	TXTName        string     `json:"txt_name"`
	TXTValue       string     `json:"txt_value"`
	LastError      string     `json:"last_error,omitempty"`
	VerifiedAt     *time.Time `json:"verified_at,omitempty"`
	LastCheckedAt  *time.Time `json:"last_checked_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type EnterpriseProviderGuide struct {
	Provider          string   `json:"provider"`
	DisplayName       string   `json:"display_name"`
	Protocols         []string `json:"protocols"`
	SAMLInstructions  []string `json:"saml_instructions,omitempty"`
	OIDCInstructions  []string `json:"oidc_instructions,omitempty"`
	SCIMInstructions  []string `json:"scim_instructions,omitempty"`
	DocumentationURL  string   `json:"documentation_url,omitempty"`
	SCIMDocumentation string   `json:"scim_documentation_url,omitempty"`
}

type EnterpriseSetupHelper struct {
	Provider        string   `json:"provider"`
	Protocol        string   `json:"protocol"`
	ACSURL          string   `json:"acs_url,omitempty"`
	SPEntityID      string   `json:"sp_entity_id,omitempty"`
	SPMetadataURL   string   `json:"sp_metadata_url,omitempty"`
	OIDCRedirectURI string   `json:"oidc_redirect_uri,omitempty"`
	SCIMBaseURL     string   `json:"scim_base_url,omitempty"`
	Instructions    []string `json:"instructions,omitempty"`
}

type EnterpriseConnectionWarning struct {
	Code     string `json:"code"`
	Level    string `json:"level"`
	Message  string `json:"message"`
	Detail   string `json:"detail,omitempty"`
	Deadline string `json:"deadline,omitempty"`
}

type EnterpriseConnectionHealth struct {
	Status        string                        `json:"status"`
	LastLoginAt   *time.Time                    `json:"last_login_at,omitempty"`
	LastSyncAt    *time.Time                    `json:"last_sync_at,omitempty"`
	LastErrorAt   *time.Time                    `json:"last_error_at,omitempty"`
	LastError     string                        `json:"last_error,omitempty"`
	Warnings      []EnterpriseConnectionWarning `json:"warnings,omitempty"`
	TestSignInURL string                        `json:"test_sign_in_url,omitempty"`
}

func NormalizeEnterpriseProvider(provider, protocol string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	provider = strings.ReplaceAll(provider, "_", "-")
	switch provider {
	case EnterpriseProviderOkta,
		EnterpriseProviderMicrosoftEntra,
		EnterpriseProviderGoogleWorkspace,
		EnterpriseProviderPing,
		EnterpriseProviderOneLogin,
		EnterpriseProviderGenericSAML,
		EnterpriseProviderGenericOIDC:
		return provider
	}
	if strings.EqualFold(protocol, SSOProtocolOIDC) {
		return EnterpriseProviderGenericOIDC
	}
	return EnterpriseProviderGenericSAML
}
