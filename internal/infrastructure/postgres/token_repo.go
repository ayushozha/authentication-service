package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
)

type TokenRepo struct {
	db *sql.DB
}

func NewTokenRepo(db *sql.DB) *TokenRepo {
	return &TokenRepo{db: db}
}

func (r *TokenRepo) Create(ctx context.Context, userID, tokenType string, ttl time.Duration) (string, error) {
	rawToken, err := generateToken(32)
	if err != nil {
		return "", err
	}
	tokenHash := hashToken(rawToken)

	// Invalidate old unused tokens of the same type for this user
	_, err = r.db.ExecContext(ctx, `
		UPDATE verification_tokens
		SET used_at = NOW()
		WHERE user_id = $1 AND token_type = $2 AND used_at IS NULL`,
		userID, tokenType,
	)
	if err != nil {
		return "", err
	}

	id := uuid.NewString()
	expiresAt := time.Now().Add(ttl)

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO verification_tokens (id, user_id, token_hash, token_type, expires_at, used_at, created_at)
		VALUES ($1, $2, $3, $4, $5, NULL, NOW())`,
		id, userID, tokenHash, tokenType, expiresAt,
	)
	if err != nil {
		return "", err
	}
	return rawToken, nil
}

func (r *TokenRepo) Validate(ctx context.Context, rawToken, tokenType string) (string, error) {
	tokenHash := hashToken(rawToken)

	var userID, tokenID string
	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id FROM verification_tokens
		WHERE token_hash = $1 AND token_type = $2 AND used_at IS NULL AND expires_at > NOW()`,
		tokenHash, tokenType,
	).Scan(&tokenID, &userID)
	if err == sql.ErrNoRows {
		return "", domain.ErrInvalidToken
	}
	if err != nil {
		return "", err
	}

	// Mark as used
	_, err = r.db.ExecContext(ctx, `
		UPDATE verification_tokens SET used_at = NOW() WHERE id = $1`, tokenID)
	if err != nil {
		return "", err
	}

	return userID, nil
}
