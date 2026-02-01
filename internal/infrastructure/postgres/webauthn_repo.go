package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

type WebAuthnRepo struct {
	db *sql.DB
}

func NewWebAuthnRepo(db *sql.DB) *WebAuthnRepo {
	return &WebAuthnRepo{db: db}
}

func (r *WebAuthnRepo) Save(ctx context.Context, userID string, cred *webauthn.Credential, friendlyName string) error {
	id := uuid.NewString()

	transports := make([]string, len(cred.Transport))
	for i, t := range cred.Transport {
		transports[i] = string(t)
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, attestation_type, transport, aaguid, sign_count, friendly_name, backed_up, last_used_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, NOW())`,
		id, userID, cred.ID, cred.PublicKey,
		cred.AttestationType, pqTextArrayLiteral(transports),
		cred.Authenticator.AAGUID, cred.Authenticator.SignCount,
		friendlyName, cred.Flags.BackupState,
	)
	return err
}

func (r *WebAuthnRepo) GetByUser(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT credential_id, public_key, attestation_type, transport, aaguid, sign_count, backed_up
		FROM webauthn_credentials
		WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []webauthn.Credential
	for rows.Next() {
		var c webauthn.Credential
		var transportStrs []string

		err := rows.Scan(
			&c.ID, &c.PublicKey, &c.AttestationType,
			pqTextArray(&transportStrs),
			&c.Authenticator.AAGUID, &c.Authenticator.SignCount,
			&c.Flags.BackupState,
		)
		if err != nil {
			return nil, err
		}

		c.Transport = make([]protocol.AuthenticatorTransport, len(transportStrs))
		for i, t := range transportStrs {
			c.Transport[i] = protocol.AuthenticatorTransport(t)
		}

		creds = append(creds, c)
	}
	return creds, rows.Err()
}

func (r *WebAuthnRepo) UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE webauthn_credentials SET sign_count = $1, last_used_at = NOW() WHERE credential_id = $2`,
		signCount, credentialID)
	return err
}

func (r *WebAuthnRepo) ListByUser(ctx context.Context, userID string) ([]domain.WebAuthnCredential, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, user_id, credential_id, public_key, attestation_type, transport, aaguid, sign_count, friendly_name, backed_up, last_used_at, created_at
		FROM webauthn_credentials
		WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []domain.WebAuthnCredential
	for rows.Next() {
		var c domain.WebAuthnCredential
		err := rows.Scan(
			&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey,
			&c.AttestationType, pqTextArray(&c.Transport),
			&c.AAGUID, &c.SignCount, &c.FriendlyName,
			&c.BackedUp, &c.LastUsedAt, &c.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

func (r *WebAuthnRepo) GetUserIDByCredentialID(ctx context.Context, credentialID []byte) (string, error) {
	var userID string
	err := r.db.QueryRowContext(ctx, `
		SELECT user_id FROM webauthn_credentials WHERE credential_id = $1`,
		credentialID,
	).Scan(&userID)
	if err == sql.ErrNoRows {
		return "", domain.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return userID, nil
}

func (r *WebAuthnRepo) DeleteByID(ctx context.Context, id, userID string) error {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2`,
		id, userID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

// pqTextArray returns a scanner for PostgreSQL text[] columns.
func pqTextArray(dst *[]string) interface{} {
	return &pgTextArray{dst}
}

type pgTextArray struct {
	dst *[]string
}

func (a *pgTextArray) Scan(src interface{}) error {
	if src == nil {
		*a.dst = nil
		return nil
	}
	var raw string
	switch v := src.(type) {
	case []byte:
		raw = string(v)
	case string:
		raw = v
	default:
		return fmt.Errorf("unsupported type for text[]: %T", src)
	}
	if len(raw) < 2 || raw[0] != '{' || raw[len(raw)-1] != '}' {
		*a.dst = nil
		return nil
	}
	inner := raw[1 : len(raw)-1]
	if inner == "" {
		*a.dst = nil
		return nil
	}
	*a.dst = splitPGArray(inner)
	return nil
}

func splitPGArray(s string) []string {
	var result []string
	var current string
	inQuotes := false
	for _, c := range s {
		switch {
		case c == '"' && !inQuotes:
			inQuotes = true
		case c == '"' && inQuotes:
			inQuotes = false
		case c == ',' && !inQuotes:
			result = append(result, current)
			current = ""
		default:
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// pqTextArrayLiteral formats a string slice as a PostgreSQL text array literal.
func pqTextArrayLiteral(vals []string) string {
	if len(vals) == 0 {
		return "{}"
	}
	s := "{"
	for i, v := range vals {
		if i > 0 {
			s += ","
		}
		s += "\"" + v + "\""
	}
	s += "}"
	return s
}
