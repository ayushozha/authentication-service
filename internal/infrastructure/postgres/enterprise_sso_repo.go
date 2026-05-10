package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

type EnterpriseSSORepo struct {
	db *sql.DB
}

func NewEnterpriseSSORepo(db *sql.DB) *EnterpriseSSORepo {
	return &EnterpriseSSORepo{db: db}
}

func (r *EnterpriseSSORepo) CreateConnection(ctx context.Context, connection *domain.EnterpriseSSOConnection) error {
	oidcJSON, err := json.Marshal(connection.OIDC)
	if err != nil {
		return err
	}
	samlJSON, err := json.Marshal(connection.SAML)
	if err != nil {
		return err
	}
	mappingJSON, err := json.Marshal(connection.AttributeMapping)
	if err != nil {
		return err
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO enterprise_sso_connections
			(id, client_id, organization_id, name, slug, provider, protocol, status, domains, enforce_for_domains,
			 oidc_config, saml_config, attribute_mapping, last_login_at, last_error_at, last_error, metadata_refreshed_at, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
		connection.ID, connection.ClientID, nullString(connection.OrganizationID), connection.Name, connection.Slug,
		connection.Provider, connection.Protocol, connection.Status, pq.Array(connection.Domains), connection.EnforceForDomains,
		oidcJSON, samlJSON, mappingJSON, connection.LastLoginAt, connection.LastErrorAt, connection.LastError, connection.MetadataRefreshedAt,
		connection.CreatedAt, connection.UpdatedAt,
	)
	return err
}

func (r *EnterpriseSSORepo) ListConnections(ctx context.Context, clientID string) ([]*domain.EnterpriseSSOConnection, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, organization_id, name, slug, provider, protocol, status, domains, enforce_for_domains,
		       oidc_config, saml_config, attribute_mapping, last_login_at, last_error_at, last_error,
		       metadata_refreshed_at, created_at, updated_at
		FROM enterprise_sso_connections
		WHERE client_id = $1
		ORDER BY created_at DESC`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	connections := []*domain.EnterpriseSSOConnection{}
	for rows.Next() {
		connection, err := scanEnterpriseSSOConnection(rows)
		if err != nil {
			return nil, err
		}
		connections = append(connections, connection)
	}
	return connections, rows.Err()
}

func (r *EnterpriseSSORepo) ListConnectionsForOrganization(ctx context.Context, clientID, organizationID string) ([]*domain.EnterpriseSSOConnection, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, organization_id, name, slug, provider, protocol, status, domains, enforce_for_domains,
		       oidc_config, saml_config, attribute_mapping, last_login_at, last_error_at, last_error,
		       metadata_refreshed_at, created_at, updated_at
		FROM enterprise_sso_connections
		WHERE client_id = $1 AND organization_id = $2
		ORDER BY created_at DESC`, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	connections := []*domain.EnterpriseSSOConnection{}
	for rows.Next() {
		connection, err := scanEnterpriseSSOConnection(rows)
		if err != nil {
			return nil, err
		}
		connections = append(connections, connection)
	}
	return connections, rows.Err()
}

func (r *EnterpriseSSORepo) GetConnection(ctx context.Context, clientID, connectionID string) (*domain.EnterpriseSSOConnection, error) {
	return scanEnterpriseSSOConnection(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, organization_id, name, slug, provider, protocol, status, domains, enforce_for_domains,
		       oidc_config, saml_config, attribute_mapping, last_login_at, last_error_at, last_error,
		       metadata_refreshed_at, created_at, updated_at
		FROM enterprise_sso_connections
		WHERE client_id = $1 AND id = $2`, clientID, connectionID))
}

func (r *EnterpriseSSORepo) GetConnectionByID(ctx context.Context, connectionID string) (*domain.EnterpriseSSOConnection, error) {
	return scanEnterpriseSSOConnection(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, organization_id, name, slug, provider, protocol, status, domains, enforce_for_domains,
		       oidc_config, saml_config, attribute_mapping, last_login_at, last_error_at, last_error,
		       metadata_refreshed_at, created_at, updated_at
		FROM enterprise_sso_connections
		WHERE id = $1`, connectionID))
}

func (r *EnterpriseSSORepo) GetConnectionBySlug(ctx context.Context, clientID, slug string) (*domain.EnterpriseSSOConnection, error) {
	return scanEnterpriseSSOConnection(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, organization_id, name, slug, provider, protocol, status, domains, enforce_for_domains,
		       oidc_config, saml_config, attribute_mapping, last_login_at, last_error_at, last_error,
		       metadata_refreshed_at, created_at, updated_at
		FROM enterprise_sso_connections
		WHERE client_id = $1 AND slug = $2`, clientID, slug))
}

func (r *EnterpriseSSORepo) GetActiveConnectionByDomain(ctx context.Context, clientID, domainName string) (*domain.EnterpriseSSOConnection, error) {
	return scanEnterpriseSSOConnection(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, organization_id, name, slug, provider, protocol, status, domains, enforce_for_domains,
		       oidc_config, saml_config, attribute_mapping, last_login_at, last_error_at, last_error,
		       metadata_refreshed_at, created_at, updated_at
		FROM enterprise_sso_connections
		WHERE client_id = $1 AND status = 'active' AND $2 = ANY(domains)
		ORDER BY created_at DESC
		LIMIT 1`, clientID, domainName))
}

func (r *EnterpriseSSORepo) UpdateConnection(ctx context.Context, connection *domain.EnterpriseSSOConnection) error {
	oidcJSON, err := json.Marshal(connection.OIDC)
	if err != nil {
		return err
	}
	samlJSON, err := json.Marshal(connection.SAML)
	if err != nil {
		return err
	}
	mappingJSON, err := json.Marshal(connection.AttributeMapping)
	if err != nil {
		return err
	}

	_, err = r.db.ExecContext(ctx, `
		UPDATE enterprise_sso_connections
		SET organization_id = $3,
		    name = $4,
		    slug = $5,
		    provider = $6,
		    protocol = $7,
		    status = $8,
		    domains = $9,
		    enforce_for_domains = $10,
		    oidc_config = $11,
		    saml_config = $12,
		    attribute_mapping = $13,
		    last_login_at = $14,
		    last_error_at = $15,
		    last_error = $16,
		    metadata_refreshed_at = $17,
		    updated_at = $18
		WHERE client_id = $1 AND id = $2`,
		connection.ClientID, connection.ID, nullString(connection.OrganizationID), connection.Name, connection.Slug,
		connection.Provider, connection.Protocol, connection.Status, pq.Array(connection.Domains), connection.EnforceForDomains,
		oidcJSON, samlJSON, mappingJSON, connection.LastLoginAt, connection.LastErrorAt, connection.LastError,
		connection.MetadataRefreshedAt, connection.UpdatedAt,
	)
	return err
}

func (r *EnterpriseSSORepo) DeactivateConnection(ctx context.Context, clientID, connectionID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE enterprise_sso_connections
		SET status = 'inactive', updated_at = NOW()
		WHERE client_id = $1 AND id = $2`, clientID, connectionID)
	return err
}

func (r *EnterpriseSSORepo) MarkConnectionLogin(ctx context.Context, clientID, connectionID string, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE enterprise_sso_connections
		SET last_login_at = $3, last_error_at = NULL, last_error = '', updated_at = NOW()
		WHERE client_id = $1 AND id = $2`, clientID, connectionID, at)
	return err
}

func (r *EnterpriseSSORepo) MarkConnectionError(ctx context.Context, clientID, connectionID, message string, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE enterprise_sso_connections
		SET last_error_at = $3, last_error = $4, updated_at = NOW()
		WHERE client_id = $1 AND id = $2`, clientID, connectionID, at, message)
	return err
}

func (r *EnterpriseSSORepo) FindIdentity(ctx context.Context, clientID, connectionID, externalID string) (*domain.EnterpriseSSOIdentity, error) {
	var identity domain.EnterpriseSSOIdentity
	err := r.db.QueryRowContext(ctx, `
		SELECT id, client_id, connection_id, user_id, external_id, email, raw_profile, last_login_at, created_at, updated_at
		FROM enterprise_sso_identities
		WHERE client_id = $1 AND connection_id = $2 AND external_id = $3`,
		clientID, connectionID, externalID,
	).Scan(
		&identity.ID, &identity.ClientID, &identity.ConnectionID, &identity.UserID,
		&identity.ExternalID, &identity.Email, &identity.RawProfile, &identity.LastLoginAt,
		&identity.CreatedAt, &identity.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &identity, nil
}

func (r *EnterpriseSSORepo) UpsertIdentity(ctx context.Context, identity *domain.EnterpriseSSOIdentity) error {
	if identity.ID == "" {
		identity.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if identity.CreatedAt.IsZero() {
		identity.CreatedAt = now
	}
	identity.UpdatedAt = now
	identity.LastLoginAt = now

	rawProfile := identity.RawProfile
	if len(rawProfile) == 0 {
		rawProfile = []byte("{}")
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO enterprise_sso_identities
			(id, client_id, connection_id, user_id, external_id, email, raw_profile, last_login_at, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (connection_id, external_id)
		DO UPDATE SET
			user_id = EXCLUDED.user_id,
			email = EXCLUDED.email,
			raw_profile = EXCLUDED.raw_profile,
			last_login_at = EXCLUDED.last_login_at,
			updated_at = EXCLUDED.updated_at`,
		identity.ID, identity.ClientID, identity.ConnectionID, identity.UserID, identity.ExternalID,
		identity.Email, rawProfile, identity.LastLoginAt, identity.CreatedAt, identity.UpdatedAt,
	)
	return err
}

type enterpriseSSOScanner interface {
	Scan(dest ...interface{}) error
}

func scanEnterpriseSSOConnection(row enterpriseSSOScanner) (*domain.EnterpriseSSOConnection, error) {
	var connection domain.EnterpriseSSOConnection
	var domains []string
	var oidcJSON, samlJSON, mappingJSON []byte
	var organizationID, provider sql.NullString
	var lastLoginAt, lastErrorAt, metadataRefreshedAt sql.NullTime

	err := row.Scan(
		&connection.ID, &connection.ClientID, &organizationID, &connection.Name, &connection.Slug, &provider,
		&connection.Protocol, &connection.Status, pq.Array(&domains), &connection.EnforceForDomains,
		&oidcJSON, &samlJSON, &mappingJSON, &lastLoginAt, &lastErrorAt, &connection.LastError,
		&metadataRefreshedAt, &connection.CreatedAt, &connection.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	connection.Domains = domains
	if organizationID.Valid {
		connection.OrganizationID = organizationID.String
	}
	if provider.Valid {
		connection.Provider = provider.String
	}
	if lastLoginAt.Valid {
		connection.LastLoginAt = &lastLoginAt.Time
	}
	if lastErrorAt.Valid {
		connection.LastErrorAt = &lastErrorAt.Time
	}
	if metadataRefreshedAt.Valid {
		connection.MetadataRefreshedAt = &metadataRefreshedAt.Time
	}
	if len(oidcJSON) > 0 {
		_ = json.Unmarshal(oidcJSON, &connection.OIDC)
	}
	if len(samlJSON) > 0 {
		_ = json.Unmarshal(samlJSON, &connection.SAML)
	}
	if len(mappingJSON) > 0 {
		_ = json.Unmarshal(mappingJSON, &connection.AttributeMapping)
	}
	if connection.AttributeMapping == nil {
		connection.AttributeMapping = map[string]string{}
	}
	return &connection, nil
}

func nullString(value string) sql.NullString {
	value = strings.TrimSpace(value)
	return sql.NullString{String: value, Valid: value != ""}
}
