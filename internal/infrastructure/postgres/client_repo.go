package postgres

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/lib/pq"
)

type ClientRepo struct {
	db *sql.DB
}

func NewClientRepo(db *sql.DB) *ClientRepo {
	return &ClientRepo{db: db}
}

func (r *ClientRepo) Create(ctx context.Context, client *domain.Client) error {
	settingsJSON, err := json.Marshal(client.Settings)
	if err != nil {
		return err
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO clients (id, name, slug, jwt_secret, allowed_origins, webhook_url, settings, status, api_key_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		client.ID, client.Name, client.Slug, client.JWTSecret,
		pq.Array(client.AllowedOrigins), client.WebhookURL,
		settingsJSON, client.Status, client.APIKeyHash,
		client.CreatedAt, client.UpdatedAt,
	)
	return err
}

func (r *ClientRepo) GetByID(ctx context.Context, id string) (*domain.Client, error) {
	return r.scanClient(r.db.QueryRowContext(ctx, `
		SELECT id, name, slug, jwt_secret, allowed_origins, webhook_url, settings, status, api_key_hash, created_at, updated_at
		FROM clients WHERE id = $1`, id))
}

func (r *ClientRepo) GetBySlug(ctx context.Context, slug string) (*domain.Client, error) {
	return r.scanClient(r.db.QueryRowContext(ctx, `
		SELECT id, name, slug, jwt_secret, allowed_origins, webhook_url, settings, status, api_key_hash, created_at, updated_at
		FROM clients WHERE slug = $1`, slug))
}

func (r *ClientRepo) GetByAPIKeyHash(ctx context.Context, hash string) (*domain.Client, error) {
	return r.scanClient(r.db.QueryRowContext(ctx, `
		SELECT id, name, slug, jwt_secret, allowed_origins, webhook_url, settings, status, api_key_hash, created_at, updated_at
		FROM clients WHERE api_key_hash = $1 AND status = 'active'`, hash))
}

func (r *ClientRepo) List(ctx context.Context) ([]*domain.Client, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, slug, jwt_secret, allowed_origins, webhook_url, settings, status, api_key_hash, created_at, updated_at
		FROM clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []*domain.Client
	for rows.Next() {
		c, err := r.scanClientFromRow(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func (r *ClientRepo) Update(ctx context.Context, client *domain.Client) error {
	settingsJSON, err := json.Marshal(client.Settings)
	if err != nil {
		return err
	}

	result, err := r.db.ExecContext(ctx, `
		UPDATE clients
		SET name = $1, allowed_origins = $2, webhook_url = $3, settings = $4, status = $5, updated_at = NOW()
		WHERE id = $6`,
		client.Name, pq.Array(client.AllowedOrigins), client.WebhookURL,
		settingsJSON, client.Status, client.ID,
	)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (r *ClientRepo) UpdateJWTSecret(ctx context.Context, id, newSecret string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE clients SET jwt_secret = $1, updated_at = NOW() WHERE id = $2`,
		newSecret, id,
	)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (r *ClientRepo) UpdateAPIKeyHash(ctx context.Context, id, newHash string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE clients SET api_key_hash = $1, updated_at = NOW() WHERE id = $2`,
		newHash, id,
	)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (r *ClientRepo) scanClient(row *sql.Row) (*domain.Client, error) {
	var c domain.Client
	var settingsJSON []byte

	err := row.Scan(
		&c.ID, &c.Name, &c.Slug, &c.JWTSecret,
		pq.Array(&c.AllowedOrigins), &c.WebhookURL,
		&settingsJSON, &c.Status, &c.APIKeyHash,
		&c.CreatedAt, &c.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if settingsJSON != nil {
		if err := json.Unmarshal(settingsJSON, &c.Settings); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func (r *ClientRepo) scanClientFromRow(row rowScanner) (*domain.Client, error) {
	var c domain.Client
	var settingsJSON []byte

	err := row.Scan(
		&c.ID, &c.Name, &c.Slug, &c.JWTSecret,
		pq.Array(&c.AllowedOrigins), &c.WebhookURL,
		&settingsJSON, &c.Status, &c.APIKeyHash,
		&c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if settingsJSON != nil {
		if err := json.Unmarshal(settingsJSON, &c.Settings); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

func checkRowsAffected(result sql.Result) error {
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}
