package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/lib/pq"
)

type SCIMRepo struct {
	db *sql.DB
}

func NewSCIMRepo(db *sql.DB) *SCIMRepo {
	return &SCIMRepo{db: db}
}

func (r *SCIMRepo) CreateDirectory(ctx context.Context, directory *domain.SCIMDirectory) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO scim_directories
			(id, client_id, organization_id, name, provider, status, token_hash, token_prefix, domains,
			 last_sync_at, last_error_at, last_error, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		directory.ID, directory.ClientID, nullString(directory.OrganizationID), directory.Name, directory.Provider, directory.Status,
		directory.TokenHash, directory.TokenPrefix, pq.Array(directory.Domains), directory.LastSyncAt, directory.LastErrorAt,
		directory.LastError, directory.CreatedAt, directory.UpdatedAt,
	)
	return err
}

func (r *SCIMRepo) ListDirectories(ctx context.Context, clientID string) ([]*domain.SCIMDirectory, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, organization_id, name, provider, status, token_hash, token_prefix, domains,
		       last_sync_at, last_error_at, last_error, created_at, updated_at
		FROM scim_directories
		WHERE client_id = $1
		ORDER BY created_at DESC`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.SCIMDirectory
	for rows.Next() {
		directory, err := scanSCIMDirectory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, directory)
	}
	return out, rows.Err()
}

func (r *SCIMRepo) ListDirectoriesForOrganization(ctx context.Context, clientID, organizationID string) ([]*domain.SCIMDirectory, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, organization_id, name, provider, status, token_hash, token_prefix, domains,
		       last_sync_at, last_error_at, last_error, created_at, updated_at
		FROM scim_directories
		WHERE client_id = $1 AND organization_id = $2
		ORDER BY created_at DESC`, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.SCIMDirectory
	for rows.Next() {
		directory, err := scanSCIMDirectory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, directory)
	}
	return out, rows.Err()
}

func (r *SCIMRepo) GetDirectory(ctx context.Context, clientID, directoryID string) (*domain.SCIMDirectory, error) {
	return scanSCIMDirectory(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, organization_id, name, provider, status, token_hash, token_prefix, domains,
		       last_sync_at, last_error_at, last_error, created_at, updated_at
		FROM scim_directories
		WHERE client_id = $1 AND id = $2`, clientID, directoryID))
}

func (r *SCIMRepo) GetDirectoryByID(ctx context.Context, directoryID string) (*domain.SCIMDirectory, error) {
	return scanSCIMDirectory(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, organization_id, name, provider, status, token_hash, token_prefix, domains,
		       last_sync_at, last_error_at, last_error, created_at, updated_at
		FROM scim_directories
		WHERE id = $1`, directoryID))
}

func (r *SCIMRepo) GetDirectoryByTokenHash(ctx context.Context, tokenHash string) (*domain.SCIMDirectory, error) {
	return scanSCIMDirectory(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, organization_id, name, provider, status, token_hash, token_prefix, domains,
		       last_sync_at, last_error_at, last_error, created_at, updated_at
		FROM scim_directories
		WHERE token_hash = $1`, tokenHash))
}

func (r *SCIMRepo) UpdateDirectory(ctx context.Context, directory *domain.SCIMDirectory) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE scim_directories
		SET organization_id = $3, name = $4, provider = $5, status = $6, token_hash = $7, token_prefix = $8,
		    domains = $9, last_sync_at = $10, last_error_at = $11, last_error = $12, updated_at = $13
		WHERE client_id = $1 AND id = $2`,
		directory.ClientID, directory.ID, nullString(directory.OrganizationID), directory.Name, directory.Provider,
		directory.Status, directory.TokenHash, directory.TokenPrefix, pq.Array(directory.Domains), directory.LastSyncAt,
		directory.LastErrorAt, directory.LastError, directory.UpdatedAt,
	)
	return err
}

func (r *SCIMRepo) MarkDirectorySync(ctx context.Context, clientID, directoryID string, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE scim_directories
		SET last_sync_at = $3, last_error_at = NULL, last_error = '', updated_at = NOW()
		WHERE client_id = $1 AND id = $2`, clientID, directoryID, at)
	return err
}

func (r *SCIMRepo) MarkDirectoryError(ctx context.Context, clientID, directoryID, message string, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE scim_directories
		SET last_error_at = $3, last_error = $4, updated_at = NOW()
		WHERE client_id = $1 AND id = $2`, clientID, directoryID, at, message)
	return err
}

func (r *SCIMRepo) UpsertUser(ctx context.Context, user *domain.SCIMUser) error {
	raw := user.RawResource
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO scim_users (id, client_id, directory_id, user_id, external_id, user_name, active, raw_resource, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (directory_id, external_id)
		DO UPDATE SET user_id = EXCLUDED.user_id,
		              user_name = EXCLUDED.user_name,
		              active = EXCLUDED.active,
		              raw_resource = EXCLUDED.raw_resource,
		              updated_at = EXCLUDED.updated_at`,
		user.ID, user.ClientID, user.DirectoryID, user.UserID, user.ExternalID, user.UserName,
		user.Active, raw, user.CreatedAt, user.UpdatedAt,
	)
	return err
}

func (r *SCIMRepo) ListUsers(ctx context.Context, clientID, directoryID string) ([]*domain.SCIMUser, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, directory_id, user_id, external_id, user_name, active, raw_resource, created_at, updated_at
		FROM scim_users
		WHERE client_id = $1 AND directory_id = $2
		ORDER BY user_name`, clientID, directoryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.SCIMUser
	for rows.Next() {
		user, err := scanSCIMUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, user)
	}
	return out, rows.Err()
}

func (r *SCIMRepo) GetUser(ctx context.Context, clientID, directoryID, scimUserID string) (*domain.SCIMUser, error) {
	return scanSCIMUser(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, directory_id, user_id, external_id, user_name, active, raw_resource, created_at, updated_at
		FROM scim_users
		WHERE client_id = $1 AND directory_id = $2 AND id = $3`, clientID, directoryID, scimUserID))
}

func (r *SCIMRepo) GetUserByExternalID(ctx context.Context, clientID, directoryID, externalID string) (*domain.SCIMUser, error) {
	return scanSCIMUser(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, directory_id, user_id, external_id, user_name, active, raw_resource, created_at, updated_at
		FROM scim_users
		WHERE client_id = $1 AND directory_id = $2 AND external_id = $3`, clientID, directoryID, externalID))
}

func (r *SCIMRepo) DeleteUser(ctx context.Context, clientID, directoryID, scimUserID string) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM scim_users WHERE client_id = $1 AND directory_id = $2 AND id = $3`,
		clientID, directoryID, scimUserID)
	return err
}

func (r *SCIMRepo) UpsertGroup(ctx context.Context, group *domain.SCIMGroup) error {
	raw := group.RawResource
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO scim_groups (id, client_id, directory_id, external_id, display_name, members, raw_resource, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (directory_id, external_id)
		DO UPDATE SET display_name = EXCLUDED.display_name,
		              members = EXCLUDED.members,
		              raw_resource = EXCLUDED.raw_resource,
		              updated_at = EXCLUDED.updated_at`,
		group.ID, group.ClientID, group.DirectoryID, group.ExternalID, group.DisplayName,
		pq.Array(group.Members), raw, group.CreatedAt, group.UpdatedAt,
	)
	return err
}

func (r *SCIMRepo) ListGroups(ctx context.Context, clientID, directoryID string) ([]*domain.SCIMGroup, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, directory_id, external_id, display_name, members, raw_resource, created_at, updated_at
		FROM scim_groups
		WHERE client_id = $1 AND directory_id = $2
		ORDER BY display_name`, clientID, directoryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.SCIMGroup
	for rows.Next() {
		group, err := scanSCIMGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, group)
	}
	return out, rows.Err()
}

func (r *SCIMRepo) GetGroup(ctx context.Context, clientID, directoryID, scimGroupID string) (*domain.SCIMGroup, error) {
	return scanSCIMGroup(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, directory_id, external_id, display_name, members, raw_resource, created_at, updated_at
		FROM scim_groups
		WHERE client_id = $1 AND directory_id = $2 AND id = $3`, clientID, directoryID, scimGroupID))
}

func (r *SCIMRepo) GetGroupByExternalID(ctx context.Context, clientID, directoryID, externalID string) (*domain.SCIMGroup, error) {
	return scanSCIMGroup(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, directory_id, external_id, display_name, members, raw_resource, created_at, updated_at
		FROM scim_groups
		WHERE client_id = $1 AND directory_id = $2 AND external_id = $3`, clientID, directoryID, externalID))
}

func (r *SCIMRepo) DeleteGroup(ctx context.Context, clientID, directoryID, scimGroupID string) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM scim_groups WHERE client_id = $1 AND directory_id = $2 AND id = $3`,
		clientID, directoryID, scimGroupID)
	return err
}

func scanSCIMDirectory(row enterpriseSSOScanner) (*domain.SCIMDirectory, error) {
	var directory domain.SCIMDirectory
	var domains []string
	var organizationID, provider sql.NullString
	var lastSyncAt, lastErrorAt sql.NullTime
	err := row.Scan(&directory.ID, &directory.ClientID, &organizationID, &directory.Name, &provider, &directory.Status, &directory.TokenHash,
		&directory.TokenPrefix, pq.Array(&domains), &lastSyncAt, &lastErrorAt, &directory.LastError, &directory.CreatedAt, &directory.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	directory.Domains = domains
	if organizationID.Valid {
		directory.OrganizationID = organizationID.String
	}
	if provider.Valid {
		directory.Provider = provider.String
	}
	if lastSyncAt.Valid {
		directory.LastSyncAt = &lastSyncAt.Time
	}
	if lastErrorAt.Valid {
		directory.LastErrorAt = &lastErrorAt.Time
	}
	return &directory, nil
}

func scanSCIMUser(row enterpriseSSOScanner) (*domain.SCIMUser, error) {
	var user domain.SCIMUser
	err := row.Scan(&user.ID, &user.ClientID, &user.DirectoryID, &user.UserID, &user.ExternalID,
		&user.UserName, &user.Active, &user.RawResource, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func scanSCIMGroup(row enterpriseSSOScanner) (*domain.SCIMGroup, error) {
	var group domain.SCIMGroup
	var members []string
	err := row.Scan(&group.ID, &group.ClientID, &group.DirectoryID, &group.ExternalID,
		&group.DisplayName, pq.Array(&members), &group.RawResource, &group.CreatedAt, &group.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	group.Members = members
	return &group, nil
}
