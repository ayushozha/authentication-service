package postgres

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
)

type UserRepo struct {
	db *sql.DB
}

func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) Create(ctx context.Context, clientID, email, passwordHash, displayName string) (*domain.User, error) {
	u := &domain.User{
		ID:            uuid.NewString(),
		ClientID:      clientID,
		Email:         strings.ToLower(email),
		EmailVerified: false,
		PasswordHash:  &passwordHash,
		DisplayName:   displayName,
		Role:          "user",
		Status:        "active",
		TOTPEnabled:   false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (id, client_id, email, email_verified, password_hash, display_name, avatar_url, timezone, locale, role, status, totp_enabled, totp_secret, last_login_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		u.ID, u.ClientID, u.Email, u.EmailVerified, u.PasswordHash,
		u.DisplayName, u.AvatarURL, u.Timezone, u.Locale,
		u.Role, u.Status, u.TOTPEnabled, u.TOTPSecret,
		u.LastLoginAt, u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			return nil, domain.ErrDuplicateEmail
		}
		return nil, err
	}
	return u, nil
}

func (r *UserRepo) CreateOAuth(ctx context.Context, clientID, email, displayName, avatarURL string) (*domain.User, error) {
	u := &domain.User{
		ID:            uuid.NewString(),
		ClientID:      clientID,
		Email:         strings.ToLower(email),
		EmailVerified: true,
		DisplayName:   displayName,
		AvatarURL:     avatarURL,
		Role:          "user",
		Status:        "active",
		TOTPEnabled:   false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (id, client_id, email, email_verified, password_hash, display_name, avatar_url, timezone, locale, role, status, totp_enabled, totp_secret, last_login_at, created_at, updated_at)
		VALUES ($1, $2, $3, TRUE, NULL, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		u.ID, u.ClientID, u.Email,
		u.DisplayName, u.AvatarURL, u.Timezone, u.Locale,
		u.Role, u.Status, u.TOTPEnabled, u.TOTPSecret,
		u.LastLoginAt, u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			return nil, domain.ErrDuplicateEmail
		}
		return nil, err
	}
	return u, nil
}

func (r *UserRepo) GetByEmail(ctx context.Context, clientID, email string) (*domain.User, error) {
	return r.scanUser(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, email, email_verified, password_hash, display_name, avatar_url, timezone, locale, role, status, totp_enabled, totp_secret, last_login_at, created_at, updated_at
		FROM users
		WHERE client_id = $1 AND LOWER(email) = $2 AND status != 'deleted'`,
		clientID, strings.ToLower(email),
	))
}

func (r *UserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	return r.scanUser(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, email, email_verified, password_hash, display_name, avatar_url, timezone, locale, role, status, totp_enabled, totp_secret, last_login_at, created_at, updated_at
		FROM users
		WHERE id = $1 AND status != 'deleted'`, id,
	))
}

func (r *UserRepo) UpdateLastLogin(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1`, userID)
	return err
}

func (r *UserRepo) VerifyEmail(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET email_verified = TRUE, updated_at = NOW() WHERE id = $1`, userID)
	return err
}

func (r *UserRepo) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`,
		passwordHash, userID)
	return err
}

func (r *UserRepo) UpdateProfile(ctx context.Context, userID, displayName, timezone string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET display_name = $1, timezone = $2, updated_at = NOW() WHERE id = $3`,
		displayName, timezone, userID)
	return err
}

func (r *UserRepo) UpdateStatus(ctx context.Context, userID, status string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET status = $1, updated_at = NOW() WHERE id = $2`,
		status, userID)
	return err
}

func (r *UserRepo) SetTOTPSecret(ctx context.Context, userID, secret string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET totp_secret = $1, updated_at = NOW() WHERE id = $2`,
		secret, userID)
	return err
}

func (r *UserRepo) EnableTOTP(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET totp_enabled = TRUE, updated_at = NOW() WHERE id = $1`, userID)
	return err
}

func (r *UserRepo) DisableTOTP(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET totp_enabled = FALSE, totp_secret = NULL, updated_at = NOW() WHERE id = $1`, userID)
	return err
}

func (r *UserRepo) scanUser(row *sql.Row) (*domain.User, error) {
	var u domain.User
	err := row.Scan(
		&u.ID, &u.ClientID, &u.Email, &u.EmailVerified,
		&u.PasswordHash, &u.DisplayName, &u.AvatarURL,
		&u.Timezone, &u.Locale, &u.Role, &u.Status,
		&u.TOTPEnabled, &u.TOTPSecret, &u.LastLoginAt,
		&u.CreatedAt, &u.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}
