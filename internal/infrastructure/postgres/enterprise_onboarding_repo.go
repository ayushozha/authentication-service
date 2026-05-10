package postgres

import (
	"context"
	"database/sql"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type EnterpriseOnboardingRepo struct {
	db *sql.DB
}

func NewEnterpriseOnboardingRepo(db *sql.DB) *EnterpriseOnboardingRepo {
	return &EnterpriseOnboardingRepo{db: db}
}

func (r *EnterpriseOnboardingRepo) CreateDomainVerification(ctx context.Context, verification *domain.EnterpriseDomainVerification) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO enterprise_domain_verifications
			(id, client_id, organization_id, domain, status, txt_name, txt_value, last_error,
			 verified_at, last_checked_at, created_at, updated_at)
		VALUES
			($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		verification.ID, verification.ClientID, verification.OrganizationID, verification.Domain,
		verification.Status, verification.TXTName, verification.TXTValue, verification.LastError,
		verification.VerifiedAt, verification.LastCheckedAt, verification.CreatedAt, verification.UpdatedAt,
	)
	return err
}

func (r *EnterpriseOnboardingRepo) ListDomainVerifications(ctx context.Context, clientID, organizationID string) ([]*domain.EnterpriseDomainVerification, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, organization_id, domain, status, txt_name, txt_value, last_error,
		       verified_at, last_checked_at, created_at, updated_at
		FROM enterprise_domain_verifications
		WHERE client_id = $1 AND organization_id = $2
		ORDER BY domain`, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*domain.EnterpriseDomainVerification{}
	for rows.Next() {
		verification, err := scanEnterpriseDomainVerification(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, verification)
	}
	return out, rows.Err()
}

func (r *EnterpriseOnboardingRepo) GetDomainVerification(ctx context.Context, clientID, organizationID, verificationID string) (*domain.EnterpriseDomainVerification, error) {
	return scanEnterpriseDomainVerification(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, organization_id, domain, status, txt_name, txt_value, last_error,
		       verified_at, last_checked_at, created_at, updated_at
		FROM enterprise_domain_verifications
		WHERE client_id = $1 AND organization_id = $2 AND id = $3`, clientID, organizationID, verificationID))
}

func (r *EnterpriseOnboardingRepo) GetDomainVerificationByDomain(ctx context.Context, clientID, organizationID, domainName string) (*domain.EnterpriseDomainVerification, error) {
	return scanEnterpriseDomainVerification(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, organization_id, domain, status, txt_name, txt_value, last_error,
		       verified_at, last_checked_at, created_at, updated_at
		FROM enterprise_domain_verifications
		WHERE client_id = $1 AND organization_id = $2 AND domain = $3`, clientID, organizationID, domainName))
}

func (r *EnterpriseOnboardingRepo) UpdateDomainVerification(ctx context.Context, verification *domain.EnterpriseDomainVerification) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE enterprise_domain_verifications
		SET status = $4, txt_name = $5, txt_value = $6, last_error = $7,
		    verified_at = $8, last_checked_at = $9, updated_at = $10
		WHERE client_id = $1 AND organization_id = $2 AND id = $3`,
		verification.ClientID, verification.OrganizationID, verification.ID, verification.Status,
		verification.TXTName, verification.TXTValue, verification.LastError, verification.VerifiedAt,
		verification.LastCheckedAt, verification.UpdatedAt,
	)
	return err
}

func scanEnterpriseDomainVerification(row enterpriseSSOScanner) (*domain.EnterpriseDomainVerification, error) {
	var verification domain.EnterpriseDomainVerification
	var verifiedAt, lastCheckedAt sql.NullTime
	err := row.Scan(
		&verification.ID,
		&verification.ClientID,
		&verification.OrganizationID,
		&verification.Domain,
		&verification.Status,
		&verification.TXTName,
		&verification.TXTValue,
		&verification.LastError,
		&verifiedAt,
		&lastCheckedAt,
		&verification.CreatedAt,
		&verification.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if verifiedAt.Valid {
		verification.VerifiedAt = &verifiedAt.Time
	}
	if lastCheckedAt.Valid {
		verification.LastCheckedAt = &lastCheckedAt.Time
	}
	return &verification, nil
}
