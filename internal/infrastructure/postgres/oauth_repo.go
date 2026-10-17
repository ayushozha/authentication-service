package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

type OAuthRepo struct {
	db *sql.DB
}

// CreateProviderSubjectAccount rolls back the user insert if linking fails.
// It never queries email to select an existing identity and never upserts a link.
func (r *OAuthRepo) CreateProviderSubjectAccount(ctx context.Context, clientID, provider, providerUserID, email, displayName, avatarURL, accessToken, refreshToken string, rawProfile []byte) (*domain.User, error) {
	now := time.Now().UTC()
	u := &domain.User{ID: uuid.NewString(), ClientID: clientID, Email: strings.ToLower(email), EmailVerified: true,
		DisplayName: displayName, AvatarURL: avatarURL, Timezone: "UTC", Locale: "en", Role: "user", Status: "active", CreatedAt: now, UpdatedAt: now}
	err := r.db.QueryRowContext(ctx, `
		WITH created_user AS (
			INSERT INTO users (id, client_id, email, email_verified, display_name, avatar_url)
			VALUES ($1, $2, $3, TRUE, $4, $5) RETURNING id
		), linked AS (
			INSERT INTO oauth_accounts (id, user_id, client_id, provider, provider_user_id, email, access_token, refresh_token, raw_profile)
			SELECT $6, id, $2, $7, $8, $3, $9, $10, $11 FROM created_user
			RETURNING user_id
		) SELECT user_id::text FROM linked`, u.ID, clientID, u.Email, displayName, avatarURL,
		uuid.NewString(), provider, providerUserID, accessToken, refreshToken, string(rawProfile)).Scan(&u.ID)
	if err != nil {
		var constraint *pq.Error
		if errors.As(err, &constraint) && constraint.Code == "23505" && constraint.Constraint == "idx_users_client_email" {
			return nil, domain.ErrDuplicateEmail
		}
		return nil, err
	}
	return u, nil
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
