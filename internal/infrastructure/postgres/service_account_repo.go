package postgres

import (
	"context"
	"database/sql"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/lib/pq"
)

type ServiceAccountRepo struct {
	db *sql.DB
}

func NewServiceAccountRepo(db *sql.DB) *ServiceAccountRepo {
	return &ServiceAccountRepo{db: db}
}

func (r *ServiceAccountRepo) CreateServiceAccount(ctx context.Context, account *domain.ServiceAccount) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO service_accounts (id, client_id, name, description, scopes, status, last_used_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		account.ID, account.ClientID, account.Name, account.Description, pq.Array(account.Scopes),
		account.Status, account.LastUsedAt, account.CreatedAt, account.UpdatedAt,
	)
	return err
}

func (r *ServiceAccountRepo) ListServiceAccounts(ctx context.Context, clientID string) ([]*domain.ServiceAccount, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, name, description, scopes, status, last_used_at, created_at, updated_at
		FROM service_accounts
		WHERE client_id = $1
		ORDER BY created_at DESC`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accounts := make([]*domain.ServiceAccount, 0)
	for rows.Next() {
		account, err := scanServiceAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

func (r *ServiceAccountRepo) GetServiceAccount(ctx context.Context, clientID, serviceAccountID string) (*domain.ServiceAccount, error) {
	return scanServiceAccount(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, name, description, scopes, status, last_used_at, created_at, updated_at
		FROM service_accounts
		WHERE client_id = $1 AND id = $2`, clientID, serviceAccountID))
}

func (r *ServiceAccountRepo) UpdateServiceAccount(ctx context.Context, account *domain.ServiceAccount) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE service_accounts
		SET name = $1, description = $2, scopes = $3, status = $4, updated_at = NOW()
		WHERE client_id = $5 AND id = $6`,
		account.Name, account.Description, pq.Array(account.Scopes), account.Status, account.ClientID, account.ID,
	)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (r *ServiceAccountRepo) UpdateServiceAccountLastUsed(ctx context.Context, serviceAccountID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE service_accounts SET last_used_at = NOW(), updated_at = NOW() WHERE id = $1`, serviceAccountID)
	return err
}

func (r *ServiceAccountRepo) CreateServiceAccountKey(ctx context.Context, key *domain.ServiceAccountKey) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO service_account_keys (
			id, client_id, service_account_id, name, key_prefix, secret_hash, scopes, status,
			last_used_at, expires_at, revoked_at, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		key.ID, key.ClientID, key.ServiceAccountID, key.Name, key.KeyPrefix, key.SecretHash,
		pq.Array(key.Scopes), key.Status, key.LastUsedAt, key.ExpiresAt, key.RevokedAt, key.CreatedAt, key.UpdatedAt,
	)
	return err
}

func (r *ServiceAccountRepo) ListServiceAccountKeys(ctx context.Context, clientID, serviceAccountID string) ([]*domain.ServiceAccountKey, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, service_account_id, name, key_prefix, secret_hash, scopes, status,
			last_used_at, expires_at, revoked_at, created_at, updated_at
		FROM service_account_keys
		WHERE client_id = $1 AND service_account_id = $2
		ORDER BY created_at DESC`, clientID, serviceAccountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]*domain.ServiceAccountKey, 0)
	for rows.Next() {
		key, err := scanServiceAccountKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (r *ServiceAccountRepo) GetServiceAccountKey(ctx context.Context, clientID, serviceAccountID, keyID string) (*domain.ServiceAccountKey, error) {
	return scanServiceAccountKey(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, service_account_id, name, key_prefix, secret_hash, scopes, status,
			last_used_at, expires_at, revoked_at, created_at, updated_at
		FROM service_account_keys
		WHERE client_id = $1 AND service_account_id = $2 AND id = $3`, clientID, serviceAccountID, keyID))
}

func (r *ServiceAccountRepo) GetServiceAccountKeyBySecretHash(ctx context.Context, serviceAccountID, secretHash string) (*domain.ServiceAccountKey, error) {
	return scanServiceAccountKey(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, service_account_id, name, key_prefix, secret_hash, scopes, status,
			last_used_at, expires_at, revoked_at, created_at, updated_at
		FROM service_account_keys
		WHERE service_account_id = $1 AND secret_hash = $2`, serviceAccountID, secretHash))
}

func (r *ServiceAccountRepo) UpdateServiceAccountKeyLastUsed(ctx context.Context, keyID string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE service_account_keys SET last_used_at = NOW(), updated_at = NOW() WHERE id = $1`, keyID)
	return err
}

func (r *ServiceAccountRepo) RevokeServiceAccountKey(ctx context.Context, clientID, serviceAccountID, keyID string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE service_account_keys
		SET status = 'revoked', revoked_at = NOW(), updated_at = NOW()
		WHERE client_id = $1 AND service_account_id = $2 AND id = $3 AND status != 'revoked'`,
		clientID, serviceAccountID, keyID,
	)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func scanServiceAccount(row rowScanner) (*domain.ServiceAccount, error) {
	var account domain.ServiceAccount
	var lastUsedAt sql.NullTime
	err := row.Scan(
		&account.ID, &account.ClientID, &account.Name, &account.Description,
		pq.Array(&account.Scopes), &account.Status, &lastUsedAt, &account.CreatedAt, &account.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if lastUsedAt.Valid {
		account.LastUsedAt = &lastUsedAt.Time
	}
	return &account, nil
}

func scanServiceAccountKey(row rowScanner) (*domain.ServiceAccountKey, error) {
	var key domain.ServiceAccountKey
	var lastUsedAt sql.NullTime
	var expiresAt sql.NullTime
	var revokedAt sql.NullTime
	err := row.Scan(
		&key.ID, &key.ClientID, &key.ServiceAccountID, &key.Name, &key.KeyPrefix,
		&key.SecretHash, pq.Array(&key.Scopes), &key.Status, &lastUsedAt, &expiresAt,
		&revokedAt, &key.CreatedAt, &key.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Time
	}
	if expiresAt.Valid {
		key.ExpiresAt = &expiresAt.Time
	}
	if revokedAt.Valid {
		key.RevokedAt = &revokedAt.Time
	}
	return &key, nil
}
