package postgres

import (
	"context"
	"database/sql"

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
		INSERT INTO scim_directories (id, client_id, name, status, token_hash, token_prefix, domains, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		directory.ID, directory.ClientID, directory.Name, directory.Status, directory.TokenHash,
		directory.TokenPrefix, pq.Array(directory.Domains), directory.CreatedAt, directory.UpdatedAt,
	)
	return err
}

func (r *SCIMRepo) ListDirectories(ctx context.Context, clientID string) ([]*domain.SCIMDirectory, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, name, status, token_hash, token_prefix, domains, created_at, updated_at
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

func (r *SCIMRepo) GetDirectory(ctx context.Context, clientID, directoryID string) (*domain.SCIMDirectory, error) {
	return scanSCIMDirectory(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, name, status, token_hash, token_prefix, domains, created_at, updated_at
		FROM scim_directories
		WHERE client_id = $1 AND id = $2`, clientID, directoryID))
}

func (r *SCIMRepo) GetDirectoryByID(ctx context.Context, directoryID string) (*domain.SCIMDirectory, error) {
	return scanSCIMDirectory(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, name, status, token_hash, token_prefix, domains, created_at, updated_at
		FROM scim_directories
		WHERE id = $1`, directoryID))
}

func (r *SCIMRepo) GetDirectoryByTokenHash(ctx context.Context, tokenHash string) (*domain.SCIMDirectory, error) {
	return scanSCIMDirectory(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, name, status, token_hash, token_prefix, domains, created_at, updated_at
		FROM scim_directories
		WHERE token_hash = $1`, tokenHash))
}

func (r *SCIMRepo) UpdateDirectory(ctx context.Context, directory *domain.SCIMDirectory) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE scim_directories
		SET name = $3, status = $4, token_hash = $5, token_prefix = $6, domains = $7, updated_at = $8
		WHERE client_id = $1 AND id = $2`,
		directory.ClientID, directory.ID, directory.Name, directory.Status, directory.TokenHash,
		directory.TokenPrefix, pq.Array(directory.Domains), directory.UpdatedAt,
	)
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
	err := row.Scan(&directory.ID, &directory.ClientID, &directory.Name, &directory.Status, &directory.TokenHash,
		&directory.TokenPrefix, pq.Array(&domains), &directory.CreatedAt, &directory.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	directory.Domains = domains
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
