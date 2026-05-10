package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/lib/pq"
)

type AdminRepo struct {
	db *sql.DB
}

func NewAdminRepo(db *sql.DB) *AdminRepo {
	return &AdminRepo{db: db}
}

func (r *AdminRepo) Create(ctx context.Context, admin *domain.AdminUser) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO admin_users (
			id, email, display_name, password_hash, roles, scope_type, scope_client_id,
			scope_organization_id, mfa_required, totp_secret, totp_enabled, sso_provider,
			sso_subject, status, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, '')::uuid, NULLIF($8, '')::uuid,
			$9, $10, $11, $12, $13, $14, $15, $16)`,
		admin.ID,
		admin.Email,
		admin.DisplayName,
		admin.PasswordHash,
		pq.Array(admin.Roles),
		admin.ScopeType,
		admin.ScopeClientID,
		admin.ScopeOrganizationID,
		admin.MFARequired,
		admin.TOTPSecret,
		admin.TOTPEnabled,
		admin.SSOProvider,
		admin.SSOSubject,
		admin.Status,
		admin.CreatedAt,
		admin.UpdatedAt,
	)
	return err
}

func (r *AdminRepo) GetByID(ctx context.Context, id string) (*domain.AdminUser, error) {
	return r.scanAdmin(r.db.QueryRowContext(ctx, adminSelectQuery()+` WHERE id = $1`, id))
}

func (r *AdminRepo) GetByEmail(ctx context.Context, email string) (*domain.AdminUser, error) {
	return r.scanAdmin(r.db.QueryRowContext(ctx, adminSelectQuery()+` WHERE LOWER(email) = LOWER($1)`, email))
}

func (r *AdminRepo) GetBySSOIdentity(ctx context.Context, provider, subject string) (*domain.AdminUser, error) {
	return r.scanAdmin(r.db.QueryRowContext(ctx, adminSelectQuery()+`
		WHERE LOWER(sso_provider) = LOWER($1) AND sso_subject = $2`, provider, subject))
}

func (r *AdminRepo) List(ctx context.Context) ([]*domain.AdminUser, error) {
	rows, err := r.db.QueryContext(ctx, adminSelectQuery()+` ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	admins := make([]*domain.AdminUser, 0)
	for rows.Next() {
		admin, err := scanAdminRows(rows)
		if err != nil {
			return nil, err
		}
		admins = append(admins, admin)
	}
	return admins, rows.Err()
}

func (r *AdminRepo) UpdateLastLogin(ctx context.Context, id string, atTime time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE admin_users SET last_login_at = $1, updated_at = NOW() WHERE id = $2`,
		atTime,
		id,
	)
	return err
}

func (r *AdminRepo) scanAdmin(row *sql.Row) (*domain.AdminUser, error) {
	admin, err := scanAdminRow(row)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	return admin, err
}

func adminSelectQuery() string {
	return `
		SELECT id, email, display_name, password_hash, roles, scope_type,
			COALESCE(scope_client_id::text, ''), COALESCE(scope_organization_id::text, ''),
			mfa_required, totp_secret, totp_enabled, sso_provider, sso_subject, status,
			last_login_at, created_at, updated_at
		FROM admin_users`
}

type adminScanner interface {
	Scan(dest ...interface{}) error
}

func scanAdminRow(scanner adminScanner) (*domain.AdminUser, error) {
	var admin domain.AdminUser
	var lastLogin sql.NullTime
	if err := scanner.Scan(
		&admin.ID,
		&admin.Email,
		&admin.DisplayName,
		&admin.PasswordHash,
		pq.Array(&admin.Roles),
		&admin.ScopeType,
		&admin.ScopeClientID,
		&admin.ScopeOrganizationID,
		&admin.MFARequired,
		&admin.TOTPSecret,
		&admin.TOTPEnabled,
		&admin.SSOProvider,
		&admin.SSOSubject,
		&admin.Status,
		&lastLogin,
		&admin.CreatedAt,
		&admin.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if lastLogin.Valid {
		admin.LastLoginAt = &lastLogin.Time
	}
	return &admin, nil
}

func scanAdminRows(rows *sql.Rows) (*domain.AdminUser, error) {
	return scanAdminRow(rows)
}
