package postgres

import (
	"context"
	"database/sql"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type SigningKeyRepo struct {
	db *sql.DB
}

func NewSigningKeyRepo(db *sql.DB) *SigningKeyRepo {
	return &SigningKeyRepo{db: db}
}

func (r *SigningKeyRepo) Create(ctx context.Context, key *domain.SigningKey) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO client_signing_keys (id, client_id, kid, alg, public_key_pem, private_key_pem, status, created_at, rotated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		key.ID, key.ClientID, key.KID, key.Algorithm, key.PublicKeyPEM, key.PrivateKeyPEM, key.Status, key.CreatedAt, key.RotatedAt,
	)
	return err
}

func (r *SigningKeyRepo) GetActiveByClient(ctx context.Context, clientID string) (*domain.SigningKey, error) {
	return r.scanSigningKey(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, kid, alg, public_key_pem, private_key_pem, status, created_at, rotated_at
		FROM client_signing_keys
		WHERE client_id = $1 AND status = 'active'
		ORDER BY created_at DESC
		LIMIT 1`, clientID))
}

func (r *SigningKeyRepo) GetByClientAndKID(ctx context.Context, clientID, kid string) (*domain.SigningKey, error) {
	return r.scanSigningKey(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, kid, alg, public_key_pem, private_key_pem, status, created_at, rotated_at
		FROM client_signing_keys
		WHERE client_id = $1 AND kid = $2
		LIMIT 1`, clientID, kid))
}

func (r *SigningKeyRepo) ListActive(ctx context.Context) ([]*domain.SigningKey, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, kid, alg, public_key_pem, private_key_pem, status, created_at, rotated_at
		FROM client_signing_keys
		WHERE status = 'active'
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]*domain.SigningKey, 0)
	for rows.Next() {
		key := &domain.SigningKey{}
		if err := rows.Scan(
			&key.ID, &key.ClientID, &key.KID, &key.Algorithm,
			&key.PublicKeyPEM, &key.PrivateKeyPEM, &key.Status,
			&key.CreatedAt, &key.RotatedAt,
		); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (r *SigningKeyRepo) ListActiveByClient(ctx context.Context, clientID string) ([]*domain.SigningKey, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, kid, alg, public_key_pem, private_key_pem, status, created_at, rotated_at
		FROM client_signing_keys
		WHERE client_id = $1 AND status = 'active'
		ORDER BY created_at DESC`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]*domain.SigningKey, 0)
	for rows.Next() {
		key := &domain.SigningKey{}
		if err := rows.Scan(
			&key.ID, &key.ClientID, &key.KID, &key.Algorithm,
			&key.PublicKeyPEM, &key.PrivateKeyPEM, &key.Status,
			&key.CreatedAt, &key.RotatedAt,
		); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (r *SigningKeyRepo) scanSigningKey(row *sql.Row) (*domain.SigningKey, error) {
	key := &domain.SigningKey{}
	err := row.Scan(
		&key.ID, &key.ClientID, &key.KID, &key.Algorithm,
		&key.PublicKeyPEM, &key.PrivateKeyPEM, &key.Status,
		&key.CreatedAt, &key.RotatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if key.CreatedAt.IsZero() {
		key.CreatedAt = time.Now().UTC()
	}
	return key, nil
}
