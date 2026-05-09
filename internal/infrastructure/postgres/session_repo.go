package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
)

type SessionRepo struct {
	db *sql.DB
}

func NewSessionRepo(db *sql.DB) *SessionRepo {
	return &SessionRepo{db: db}
}

func generateToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (r *SessionRepo) Create(ctx context.Context, userID, clientID, ip, ua string, ttl time.Duration) (string, error) {
	rawToken, err := generateToken(32)
	if err != nil {
		return "", err
	}
	tokenHash := hashToken(rawToken)
	id := uuid.NewString()
	expiresAt := time.Now().Add(ttl)

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, client_id, refresh_token, user_agent, ip_address, expires_at, revoked, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, NOW())`,
		id, userID, clientID, tokenHash, ua, ip, expiresAt,
	)
	if err != nil {
		return "", err
	}
	return rawToken, nil
}

func (r *SessionRepo) Validate(ctx context.Context, clientID, rawToken string) (string, string, error) {
	tokenHash := hashToken(rawToken)

	var userID, sessionID string
	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id FROM sessions
		WHERE client_id = $1 AND refresh_token = $2 AND revoked = FALSE AND expires_at > NOW()`,
		clientID, tokenHash,
	).Scan(&sessionID, &userID)
	if err == sql.ErrNoRows {
		return "", "", domain.ErrInvalidToken
	}
	if err != nil {
		return "", "", err
	}
	return userID, sessionID, nil
}

func (r *SessionRepo) ListForUser(ctx context.Context, clientID, userID string) ([]*domain.Session, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, user_id, client_id, refresh_token, user_agent, ip_address, expires_at, revoked, created_at
		FROM sessions
		WHERE client_id = $1 AND user_id = $2 AND revoked = FALSE AND expires_at > NOW()
		ORDER BY created_at DESC`,
		clientID, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := []*domain.Session{}
	for rows.Next() {
		session := &domain.Session{}
		if err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.ClientID,
			&session.RefreshToken,
			&session.UserAgent,
			&session.IPAddress,
			&session.ExpiresAt,
			&session.Revoked,
			&session.CreatedAt,
		); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (r *SessionRepo) Revoke(ctx context.Context, sessionID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE sessions SET revoked = TRUE WHERE id = $1`, sessionID)
	return err
}

func (r *SessionRepo) RevokeByToken(ctx context.Context, clientID, rawToken string) error {
	tokenHash := hashToken(rawToken)
	_, err := r.db.ExecContext(ctx, `
		UPDATE sessions SET revoked = TRUE WHERE client_id = $1 AND refresh_token = $2`, clientID, tokenHash)
	return err
}

func (r *SessionRepo) RevokeForUser(ctx context.Context, clientID, userID, sessionID string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE sessions
		SET revoked = TRUE
		WHERE client_id = $1 AND user_id = $2 AND id = $3 AND revoked = FALSE`,
		clientID, userID, sessionID,
	)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (r *SessionRepo) RevokeAllForUser(ctx context.Context, clientID, userID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE sessions SET revoked = TRUE WHERE client_id = $1 AND user_id = $2 AND revoked = FALSE`, clientID, userID)
	return err
}
