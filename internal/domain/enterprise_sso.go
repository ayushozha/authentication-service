package domain

import (
	"net/mail"
	"strings"
	"time"
)

const (
	SSOProtocolOIDC = "oidc"
	SSOProtocolSAML = "saml"

	SSOConnectionStatusActive   = "active"
	SSOConnectionStatusInactive = "inactive"
)

type EnterpriseSSOConnection struct {
	ID                string                  `json:"id"`
	ClientID          string                  `json:"client_id"`
	Name              string                  `json:"name"`
	Slug              string                  `json:"slug"`
	Protocol          string                  `json:"protocol"`
	Status            string                  `json:"status"`
	Domains           []string                `json:"domains"`
	EnforceForDomains bool                    `json:"enforce_for_domains"`
	OIDC              EnterpriseSSOOIDCConfig `json:"oidc,omitempty"`
	SAML              EnterpriseSSOSAMLConfig `json:"saml,omitempty"`
	AttributeMapping  map[string]string       `json:"attribute_mapping,omitempty"`
	CreatedAt         time.Time               `json:"created_at"`
	UpdatedAt         time.Time               `json:"updated_at"`
}

type EnterpriseSSOOIDCConfig struct {
	Issuer       string   `json:"issuer,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

type EnterpriseSSOSAMLConfig struct {
	IDPEntityID      string `json:"idp_entity_id,omitempty"`
	IDPSSOURL        string `json:"idp_sso_url,omitempty"`
	IDPCertificate   string `json:"idp_certificate,omitempty"`
	IDPMetadataXML   string `json:"idp_metadata_xml,omitempty"`
	SPEntityID       string `json:"sp_entity_id,omitempty"`
	SPMetadataURL    string `json:"sp_metadata_url,omitempty"`
	ACSURL           string `json:"acs_url,omitempty"`
	SPPrivateKeyPEM  string `json:"sp_private_key_pem,omitempty"`
	SPCertificatePEM string `json:"sp_certificate_pem,omitempty"`
}

type EnterpriseSSOIdentity struct {
	ID           string    `json:"id"`
	ClientID     string    `json:"client_id"`
	ConnectionID string    `json:"connection_id"`
	UserID       string    `json:"user_id"`
	ExternalID   string    `json:"external_id"`
	Email        string    `json:"email"`
	RawProfile   []byte    `json:"-"`
	LastLoginAt  time.Time `json:"last_login_at"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func NormalizeSSODomains(domains []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		d := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(domain, "@")))
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func EmailDomain(email string) string {
	address, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil {
		return ""
	}
	parts := strings.Split(address.Address, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parts[1]))
}

func SSODomainAllowed(email string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	emailDomain := EmailDomain(email)
	if emailDomain == "" {
		return false
	}
	for _, domain := range NormalizeSSODomains(domains) {
		if emailDomain == domain {
			return true
		}
	}
	return false
}
