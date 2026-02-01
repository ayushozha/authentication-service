package postgres

import (
	"context"
	"database/sql"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
)

type OAuthRepo struct {
	db *sql.DB
}

func NewOAuthRepo(db *sql.DB) *OAuthRepo {
	return &OAuthRepo{db: db}
}

func (r *OAuthRepo) FindByProvider(ctx context.Context, clientID, provider, providerUserID string) (*domain.OAuthAccount, error) {
	var a domain.OAuthAccount
	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, client_id, provider, provider_user_id, email, access_token, refresh_token, raw_profile, created_at, updated_at
		FROM oauth_accounts
		WHERE client_id = $1 AND provider = $2 AND provider_user_id = $3`,
		clientID, provider, providerUserID,
	).Scan(
		&a.ID, &a.UserID, &a.ClientID, &a.Provider, &a.ProviderUserID,
		&a.Email, &a.AccessToken, &a.RefreshToken, &a.RawProfile,
		&a.CreatedAt, &a.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (r *OAuthRepo) Link(ctx context.Context, userID, clientID, provider, providerUserID, email, accessToken, refreshToken string, rawProfile []byte) error {
	id := uuid.NewString()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO oauth_accounts (id, user_id, client_id, provider, provider_user_id, email, access_token, refresh_token, raw_profile, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
		ON CONFLICT (client_id, provider, provider_user_id)
		DO UPDATE SET access_token = EXCLUDED.access_token, refresh_token = EXCLUDED.refresh_token, raw_profile = EXCLUDED.raw_profile, email = EXCLUDED.email, updated_at = NOW()`,
		id, userID, clientID, provider, providerUserID, email, accessToken, refreshToken, rawProfile,
	)
	return err
}
