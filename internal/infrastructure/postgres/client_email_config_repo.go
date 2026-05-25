package postgres

import (
	"context"
	"database/sql"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type ClientEmailConfigRepo struct {
	db *sql.DB
}

func NewClientEmailConfigRepo(db *sql.DB) *ClientEmailConfigRepo {
	return &ClientEmailConfigRepo{db: db}
}

func (r *ClientEmailConfigRepo) Get(ctx context.Context, clientID string) (*domain.ClientEmailConfig, error) {
	if clientID == "" {
		return nil, nil
	}
	row := r.db.QueryRowContext(ctx, `
		SELECT client_id, provider, api_key_ciphertext, api_key_nonce, api_key_last_four,
		       from_address, from_name, reply_to,
		       reset_password_url_template, verify_email_url_template, magic_link_url_template,
		       created_at, updated_at
		FROM client_email_configs WHERE client_id = $1`, clientID)
	var cfg domain.ClientEmailConfig
	var ciphertext, nonce []byte
	err := row.Scan(
		&cfg.ClientID, &cfg.Provider, &ciphertext, &nonce, &cfg.APIKeyLastFour,
		&cfg.FromAddress, &cfg.FromName, &cfg.ReplyTo,
		&cfg.ResetPasswordURLTemplate, &cfg.VerifyEmailURLTemplate, &cfg.MagicLinkURLTemplate,
		&cfg.CreatedAt, &cfg.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cfg.APIKeyCiphertext = ciphertext
	cfg.APIKeyNonce = nonce
	return &cfg, nil
}

func (r *ClientEmailConfigRepo) Upsert(ctx context.Context, cfg *domain.ClientEmailConfig) error {
	if cfg == nil || cfg.ClientID == "" {
		return domain.ErrInvalidEmailConfig
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO client_email_configs (
			client_id, provider, api_key_ciphertext, api_key_nonce, api_key_last_four,
			from_address, from_name, reply_to,
			reset_password_url_template, verify_email_url_template, magic_link_url_template,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
		ON CONFLICT (client_id) DO UPDATE SET
			provider = EXCLUDED.provider,
			api_key_ciphertext = EXCLUDED.api_key_ciphertext,
			api_key_nonce = EXCLUDED.api_key_nonce,
			api_key_last_four = EXCLUDED.api_key_last_four,
			from_address = EXCLUDED.from_address,
			from_name = EXCLUDED.from_name,
			reply_to = EXCLUDED.reply_to,
			reset_password_url_template = EXCLUDED.reset_password_url_template,
			verify_email_url_template = EXCLUDED.verify_email_url_template,
			magic_link_url_template = EXCLUDED.magic_link_url_template,
			updated_at = NOW()`,
		cfg.ClientID, cfg.Provider, cfg.APIKeyCiphertext, cfg.APIKeyNonce, cfg.APIKeyLastFour,
		cfg.FromAddress, cfg.FromName, cfg.ReplyTo,
		cfg.ResetPasswordURLTemplate, cfg.VerifyEmailURLTemplate, cfg.MagicLinkURLTemplate,
	)
	return err
}

func (r *ClientEmailConfigRepo) Delete(ctx context.Context, clientID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM client_email_configs WHERE client_id = $1`, clientID)
	return err
}
