package postgres

import (
	"context"
	"database/sql"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type ClientOAuthConfigRepo struct {
	db *sql.DB
}

func NewClientOAuthConfigRepo(db *sql.DB) *ClientOAuthConfigRepo {
	return &ClientOAuthConfigRepo{db: db}
}

const clientOAuthConfigCols = `client_id, provider, client_id_plain,
	client_secret_ciphertext, client_secret_nonce, secret_last_four,
	scopes, enabled, created_at, updated_at`

func scanOAuthConfig(s interface {
	Scan(dest ...any) error
}) (*domain.ClientOAuthConfig, error) {
	var cfg domain.ClientOAuthConfig
	var ciphertext, nonce []byte
	if err := s.Scan(
		&cfg.ClientID, &cfg.Provider, &cfg.ClientIDPlain,
		&ciphertext, &nonce, &cfg.SecretLastFour,
		&cfg.Scopes, &cfg.Enabled, &cfg.CreatedAt, &cfg.UpdatedAt,
	); err != nil {
		return nil, err
	}
	cfg.ClientSecretCiphertext = ciphertext
	cfg.ClientSecretNonce = nonce
	return &cfg, nil
}

func (r *ClientOAuthConfigRepo) Get(ctx context.Context, clientID, provider string) (*domain.ClientOAuthConfig, error) {
	if clientID == "" || provider == "" {
		return nil, nil
	}
	row := r.db.QueryRowContext(ctx,
		`SELECT `+clientOAuthConfigCols+` FROM client_oauth_configs WHERE client_id = $1 AND provider = $2`,
		clientID, provider)
	cfg, err := scanOAuthConfig(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func (r *ClientOAuthConfigRepo) List(ctx context.Context, clientID string) ([]*domain.ClientOAuthConfig, error) {
	if clientID == "" {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+clientOAuthConfigCols+` FROM client_oauth_configs WHERE client_id = $1 ORDER BY provider`,
		clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []*domain.ClientOAuthConfig
	for rows.Next() {
		cfg, err := scanOAuthConfig(rows)
		if err != nil {
			return nil, err
		}
		configs = append(configs, cfg)
	}
	return configs, rows.Err()
}

func (r *ClientOAuthConfigRepo) Upsert(ctx context.Context, cfg *domain.ClientOAuthConfig) error {
	if cfg == nil || cfg.ClientID == "" || cfg.Provider == "" {
		return domain.ErrInvalidOAuthConfig
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO client_oauth_configs (
			client_id, provider, client_id_plain,
			client_secret_ciphertext, client_secret_nonce, secret_last_four,
			scopes, enabled, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		ON CONFLICT (client_id, provider) DO UPDATE SET
			client_id_plain = EXCLUDED.client_id_plain,
			client_secret_ciphertext = EXCLUDED.client_secret_ciphertext,
			client_secret_nonce = EXCLUDED.client_secret_nonce,
			secret_last_four = EXCLUDED.secret_last_four,
			scopes = EXCLUDED.scopes,
			enabled = EXCLUDED.enabled,
			updated_at = NOW()`,
		cfg.ClientID, cfg.Provider, cfg.ClientIDPlain,
		cfg.ClientSecretCiphertext, cfg.ClientSecretNonce, cfg.SecretLastFour,
		cfg.Scopes, cfg.Enabled,
	)
	return err
}

func (r *ClientOAuthConfigRepo) Delete(ctx context.Context, clientID, provider string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM client_oauth_configs WHERE client_id = $1 AND provider = $2`,
		clientID, provider)
	return err
}
