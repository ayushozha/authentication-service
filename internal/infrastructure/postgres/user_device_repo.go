package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type UserDeviceRepo struct {
	db *sql.DB
}

func NewUserDeviceRepo(db *sql.DB) *UserDeviceRepo {
	return &UserDeviceRepo{db: db}
}

func (r *UserDeviceRepo) Upsert(ctx context.Context, device *domain.UserDevice) error {
	metadataJSON, err := json.Marshal(device.Metadata)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO user_devices (
			id, client_id, user_id, fingerprint, name, user_agent, ip_address,
			trusted, remembered, trust_expires_at, last_seen_at, metadata, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (client_id, user_id, fingerprint)
		DO UPDATE SET
			name = CASE WHEN EXCLUDED.name <> 'Device' THEN EXCLUDED.name ELSE user_devices.name END,
			user_agent = EXCLUDED.user_agent,
			ip_address = EXCLUDED.ip_address,
			trusted = user_devices.trusted OR EXCLUDED.trusted,
			remembered = user_devices.remembered OR EXCLUDED.remembered,
			trust_expires_at = COALESCE(EXCLUDED.trust_expires_at, user_devices.trust_expires_at),
			last_seen_at = EXCLUDED.last_seen_at,
			metadata = CASE WHEN EXCLUDED.metadata = '{}'::jsonb THEN user_devices.metadata ELSE EXCLUDED.metadata END,
			updated_at = NOW()`,
		device.ID,
		device.ClientID,
		device.UserID,
		device.Fingerprint,
		device.Name,
		device.UserAgent,
		device.IPAddress,
		device.Trusted,
		device.Remembered,
		device.TrustExpiresAt,
		device.LastSeenAt,
		metadataJSON,
		device.CreatedAt,
		device.UpdatedAt,
	)
	return err
}

func (r *UserDeviceRepo) GetByFingerprint(ctx context.Context, clientID, userID, fingerprint string) (*domain.UserDevice, error) {
	return scanUserDevice(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, user_id, fingerprint, name, user_agent, ip_address,
			trusted, remembered, trust_expires_at, last_seen_at, metadata, created_at, updated_at
		FROM user_devices
		WHERE client_id = $1 AND user_id = $2 AND fingerprint = $3`,
		clientID, userID, fingerprint,
	))
}

func (r *UserDeviceRepo) GetForUser(ctx context.Context, clientID, userID, deviceID string) (*domain.UserDevice, error) {
	return scanUserDevice(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, user_id, fingerprint, name, user_agent, ip_address,
			trusted, remembered, trust_expires_at, last_seen_at, metadata, created_at, updated_at
		FROM user_devices
		WHERE client_id = $1 AND user_id = $2 AND id = $3`,
		clientID, userID, deviceID,
	))
}

func (r *UserDeviceRepo) ListForUser(ctx context.Context, clientID, userID string) ([]*domain.UserDevice, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, user_id, fingerprint, name, user_agent, ip_address,
			trusted, remembered, trust_expires_at, last_seen_at, metadata, created_at, updated_at
		FROM user_devices
		WHERE client_id = $1 AND user_id = $2
		ORDER BY last_seen_at DESC, created_at DESC`,
		clientID, userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := make([]*domain.UserDevice, 0)
	for rows.Next() {
		device, err := scanUserDeviceRows(rows)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (r *UserDeviceRepo) Trust(ctx context.Context, clientID, userID, deviceID, name string, trusted bool, expiresAt *time.Time) (*domain.UserDevice, error) {
	if name == "" {
		_, err := r.db.ExecContext(ctx, `
			UPDATE user_devices
			SET trusted = $1, remembered = $1, trust_expires_at = $2, updated_at = NOW()
			WHERE client_id = $3 AND user_id = $4 AND id = $5`,
			trusted, expiresAt, clientID, userID, deviceID,
		)
		if err != nil {
			return nil, err
		}
		return r.GetForUser(ctx, clientID, userID, deviceID)
	}
	_, err := r.db.ExecContext(ctx, `
		UPDATE user_devices
		SET name = $1, trusted = $2, remembered = $2, trust_expires_at = $3, updated_at = NOW()
		WHERE client_id = $4 AND user_id = $5 AND id = $6`,
		name, trusted, expiresAt, clientID, userID, deviceID,
	)
	if err != nil {
		return nil, err
	}
	return r.GetForUser(ctx, clientID, userID, deviceID)
}

func (r *UserDeviceRepo) Delete(ctx context.Context, clientID, userID, deviceID string) error {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM user_devices
		WHERE client_id = $1 AND user_id = $2 AND id = $3`,
		clientID, userID, deviceID,
	)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

type userDeviceScanner interface {
	Scan(dest ...interface{}) error
}

func scanUserDevice(scanner userDeviceScanner) (*domain.UserDevice, error) {
	device, err := scanUserDeviceRow(scanner)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	return device, err
}

func scanUserDeviceRows(rows *sql.Rows) (*domain.UserDevice, error) {
	return scanUserDeviceRow(rows)
}

func scanUserDeviceRow(scanner userDeviceScanner) (*domain.UserDevice, error) {
	var device domain.UserDevice
	var trustExpiresAt sql.NullTime
	var metadataJSON []byte
	if err := scanner.Scan(
		&device.ID,
		&device.ClientID,
		&device.UserID,
		&device.Fingerprint,
		&device.Name,
		&device.UserAgent,
		&device.IPAddress,
		&device.Trusted,
		&device.Remembered,
		&trustExpiresAt,
		&device.LastSeenAt,
		&metadataJSON,
		&device.CreatedAt,
		&device.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if trustExpiresAt.Valid {
		device.TrustExpiresAt = &trustExpiresAt.Time
	}
	if len(metadataJSON) > 0 {
		_ = json.Unmarshal(metadataJSON, &device.Metadata)
	}
	if device.Metadata == nil {
		device.Metadata = map[string]interface{}{}
	}
	return &device, nil
}
