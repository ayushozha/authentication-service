package postgres

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

type RecoveryCodeRepo struct {
	db *sql.DB
}

func NewRecoveryCodeRepo(db *sql.DB) *RecoveryCodeRepo {
	return &RecoveryCodeRepo{db: db}
}

func (r *RecoveryCodeRepo) ReplaceForUser(ctx context.Context, userID string, codeHashes []string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	for _, hash := range codeHashes {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO mfa_recovery_codes (id, user_id, code_hash, used_at, created_at)
			VALUES ($1, $2, $3, NULL, NOW())`,
			uuid.NewString(), userID, hash,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *RecoveryCodeRepo) CountUnused(ctx context.Context, userID string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`,
		userID,
	).Scan(&count)
	return count, err
}

func (r *RecoveryCodeRepo) MarkUsedByHash(ctx context.Context, userID, codeHash string) (bool, error) {
	var id string
	err := r.db.QueryRowContext(ctx, `
		UPDATE mfa_recovery_codes
		SET used_at = NOW()
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
		RETURNING id`,
		userID, codeHash,
	).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
