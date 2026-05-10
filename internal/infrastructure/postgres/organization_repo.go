package postgres

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/lib/pq"
)

type OrganizationRepo struct {
	db *sql.DB
}

func NewOrganizationRepo(db *sql.DB) *OrganizationRepo {
	return &OrganizationRepo{db: db}
}

func (r *OrganizationRepo) CreateOrganization(ctx context.Context, org *domain.Organization, owner *domain.OrganizationMembership) error {
	metadataJSON, err := json.Marshal(org.Metadata)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO organizations (id, client_id, name, slug, metadata, created_by_user_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		org.ID, org.ClientID, org.Name, org.Slug, metadataJSON, org.CreatedByUserID, org.CreatedAt, org.UpdatedAt,
	)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO organization_memberships (id, client_id, organization_id, user_id, role, permissions, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		owner.ID, owner.ClientID, owner.OrganizationID, owner.UserID, owner.Role, pq.Array(owner.Permissions), owner.Status, owner.CreatedAt, owner.UpdatedAt,
	)
	if err != nil {
		return err
	}
	err = tx.Commit()
	return err
}

func (r *OrganizationRepo) UpdateOrganization(ctx context.Context, org *domain.Organization) error {
	metadataJSON, err := json.Marshal(org.Metadata)
	if err != nil {
		return err
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE organizations
		SET name = $1, slug = $2, metadata = $3, updated_at = NOW()
		WHERE client_id = $4 AND id = $5`,
		org.Name, org.Slug, metadataJSON, org.ClientID, org.ID,
	)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (r *OrganizationRepo) GetOrganization(ctx context.Context, clientID, organizationID string) (*domain.Organization, error) {
	return scanOrganization(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, name, slug, metadata, created_by_user_id, created_at, updated_at
		FROM organizations
		WHERE client_id = $1 AND id = $2`, clientID, organizationID))
}

func (r *OrganizationRepo) ListOrganizationsForUser(ctx context.Context, clientID, userID string) ([]domain.OrganizationMembershipDetails, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT
			o.id, o.client_id, o.name, o.slug, o.metadata, o.created_by_user_id, o.created_at, o.updated_at,
			m.id, m.client_id, m.organization_id, m.user_id, m.role, m.permissions, m.status, m.created_at, m.updated_at
		FROM organizations o
		JOIN organization_memberships m ON m.organization_id = o.id
		WHERE o.client_id = $1 AND m.client_id = $1 AND m.user_id = $2 AND m.status = 'active'
		ORDER BY o.name ASC, o.created_at ASC`, clientID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]domain.OrganizationMembershipDetails, 0)
	for rows.Next() {
		org, membership, err := scanOrganizationAndMembership(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, domain.OrganizationMembershipDetails{Organization: org, Membership: membership})
	}
	return out, rows.Err()
}

func (r *OrganizationRepo) GetMembership(ctx context.Context, clientID, organizationID, userID string) (*domain.OrganizationMembership, error) {
	return scanMembership(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, organization_id, user_id, role, permissions, status, created_at, updated_at
		FROM organization_memberships
		WHERE client_id = $1 AND organization_id = $2 AND user_id = $3 AND status = 'active'`,
		clientID, organizationID, userID,
	))
}

func (r *OrganizationRepo) ListMemberships(ctx context.Context, clientID, organizationID string) ([]*domain.OrganizationMembership, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, organization_id, user_id, role, permissions, status, created_at, updated_at
		FROM organization_memberships
		WHERE client_id = $1 AND organization_id = $2 AND status = 'active'
		ORDER BY created_at ASC`, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*domain.OrganizationMembership, 0)
	for rows.Next() {
		membership, err := scanMembership(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, membership)
	}
	return out, rows.Err()
}

func (r *OrganizationRepo) UpsertMembership(ctx context.Context, membership *domain.OrganizationMembership) error {
	return r.db.QueryRowContext(ctx, `
		INSERT INTO organization_memberships (id, client_id, organization_id, user_id, role, permissions, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, $8)
		ON CONFLICT (organization_id, user_id)
		DO UPDATE SET role = EXCLUDED.role, permissions = EXCLUDED.permissions, status = 'active', updated_at = NOW()
		RETURNING id, created_at, updated_at`,
		membership.ID, membership.ClientID, membership.OrganizationID, membership.UserID,
		membership.Role, pq.Array(membership.Permissions), membership.CreatedAt, membership.UpdatedAt,
	).Scan(&membership.ID, &membership.CreatedAt, &membership.UpdatedAt)
}

func (r *OrganizationRepo) UpdateMembership(ctx context.Context, membership *domain.OrganizationMembership) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE organization_memberships
		SET role = $1, permissions = $2, updated_at = NOW()
		WHERE client_id = $3 AND organization_id = $4 AND user_id = $5 AND status = 'active'`,
		membership.Role, pq.Array(membership.Permissions), membership.ClientID, membership.OrganizationID, membership.UserID,
	)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (r *OrganizationRepo) DeleteMembership(ctx context.Context, clientID, organizationID, userID string) error {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM organization_memberships
		WHERE client_id = $1 AND organization_id = $2 AND user_id = $3`,
		clientID, organizationID, userID,
	)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (r *OrganizationRepo) CreateInvitation(ctx context.Context, invitation *domain.OrganizationInvitation) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO organization_invitations (
			id, client_id, organization_id, email, role, permissions, token_hash, status,
			invited_by_user_id, expires_at, accepted_at, revoked_at, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		invitation.ID, invitation.ClientID, invitation.OrganizationID, invitation.Email,
		invitation.Role, pq.Array(invitation.Permissions), invitation.TokenHash, invitation.Status,
		invitation.InvitedByUserID, invitation.ExpiresAt, invitation.AcceptedAt, invitation.RevokedAt,
		invitation.CreatedAt, invitation.UpdatedAt,
	)
	return err
}

func (r *OrganizationRepo) ListInvitations(ctx context.Context, clientID, organizationID string) ([]*domain.OrganizationInvitation, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, organization_id, email, role, permissions, token_hash, status,
			invited_by_user_id, expires_at, accepted_at, revoked_at, created_at, updated_at
		FROM organization_invitations
		WHERE client_id = $1 AND organization_id = $2
		ORDER BY created_at DESC`, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*domain.OrganizationInvitation, 0)
	for rows.Next() {
		invitation, err := scanInvitation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, invitation)
	}
	return out, rows.Err()
}

func (r *OrganizationRepo) GetInvitation(ctx context.Context, clientID, organizationID, invitationID string) (*domain.OrganizationInvitation, error) {
	return scanInvitation(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, organization_id, email, role, permissions, token_hash, status,
			invited_by_user_id, expires_at, accepted_at, revoked_at, created_at, updated_at
		FROM organization_invitations
		WHERE client_id = $1 AND organization_id = $2 AND id = $3`, clientID, organizationID, invitationID))
}

func (r *OrganizationRepo) GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*domain.OrganizationInvitation, error) {
	return scanInvitation(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, organization_id, email, role, permissions, token_hash, status,
			invited_by_user_id, expires_at, accepted_at, revoked_at, created_at, updated_at
		FROM organization_invitations
		WHERE token_hash = $1`, tokenHash))
}

func (r *OrganizationRepo) MarkInvitationAccepted(ctx context.Context, invitationID, userID string) error {
	_ = userID
	result, err := r.db.ExecContext(ctx, `
		UPDATE organization_invitations
		SET status = 'accepted', accepted_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND status = 'pending'`, invitationID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (r *OrganizationRepo) RevokeInvitation(ctx context.Context, clientID, organizationID, invitationID string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE organization_invitations
		SET status = 'revoked', revoked_at = NOW(), updated_at = NOW()
		WHERE client_id = $1 AND organization_id = $2 AND id = $3 AND status = 'pending'`,
		clientID, organizationID, invitationID,
	)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (r *OrganizationRepo) GetAuthorizationPolicy(ctx context.Context, clientID, organizationID string) (*domain.OrganizationAuthorizationPolicy, error) {
	return scanAuthorizationPolicy(r.db.QueryRowContext(ctx, `
		SELECT client_id, organization_id, version, description, resources, permissions, roles, created_at, updated_at
		FROM organization_authorization_policies
		WHERE client_id = $1 AND organization_id = $2`, clientID, organizationID))
}

func (r *OrganizationRepo) UpsertAuthorizationPolicy(ctx context.Context, policy *domain.OrganizationAuthorizationPolicy) error {
	resourcesJSON, err := json.Marshal(policy.Resources)
	if err != nil {
		return err
	}
	permissionsJSON, err := json.Marshal(policy.Permissions)
	if err != nil {
		return err
	}
	rolesJSON, err := json.Marshal(policy.Roles)
	if err != nil {
		return err
	}
	return r.db.QueryRowContext(ctx, `
		INSERT INTO organization_authorization_policies (
			client_id, organization_id, version, description, resources, permissions, roles, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (organization_id)
		DO UPDATE SET version = EXCLUDED.version,
		              description = EXCLUDED.description,
		              resources = EXCLUDED.resources,
		              permissions = EXCLUDED.permissions,
		              roles = EXCLUDED.roles,
		              updated_at = EXCLUDED.updated_at
		RETURNING created_at, updated_at`,
		policy.ClientID, policy.OrganizationID, policy.Version, policy.Description,
		resourcesJSON, permissionsJSON, rolesJSON, policy.CreatedAt, policy.UpdatedAt,
	).Scan(&policy.CreatedAt, &policy.UpdatedAt)
}

func (r *OrganizationRepo) ListGroupMappings(ctx context.Context, clientID, organizationID string) ([]*domain.OrganizationGroupMapping, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, organization_id, source, source_id, group_name, role, permissions, description, created_at, updated_at
		FROM organization_group_mappings
		WHERE client_id = $1 AND organization_id = $2
		ORDER BY source, group_name`, clientID, organizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*domain.OrganizationGroupMapping, 0)
	for rows.Next() {
		mapping, err := scanGroupMapping(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, mapping)
	}
	return out, rows.Err()
}

func (r *OrganizationRepo) GetGroupMapping(ctx context.Context, clientID, organizationID, mappingID string) (*domain.OrganizationGroupMapping, error) {
	return scanGroupMapping(r.db.QueryRowContext(ctx, `
		SELECT id, client_id, organization_id, source, source_id, group_name, role, permissions, description, created_at, updated_at
		FROM organization_group_mappings
		WHERE client_id = $1 AND organization_id = $2 AND id = $3`, clientID, organizationID, mappingID))
}

func (r *OrganizationRepo) UpsertGroupMapping(ctx context.Context, mapping *domain.OrganizationGroupMapping) error {
	return r.db.QueryRowContext(ctx, `
		INSERT INTO organization_group_mappings (
			id, client_id, organization_id, source, source_id, group_name, role, permissions, description, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (organization_id, source, source_id, group_name)
		DO UPDATE SET role = EXCLUDED.role,
		              permissions = EXCLUDED.permissions,
		              description = EXCLUDED.description,
		              updated_at = EXCLUDED.updated_at
		RETURNING id, created_at, updated_at`,
		mapping.ID, mapping.ClientID, mapping.OrganizationID, mapping.Source, mapping.SourceID,
		mapping.Group, mapping.Role, pq.Array(mapping.Permissions), mapping.Description,
		mapping.CreatedAt, mapping.UpdatedAt,
	).Scan(&mapping.ID, &mapping.CreatedAt, &mapping.UpdatedAt)
}

func (r *OrganizationRepo) DeleteGroupMapping(ctx context.Context, clientID, organizationID, mappingID string) error {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM organization_group_mappings
		WHERE client_id = $1 AND organization_id = $2 AND id = $3`, clientID, organizationID, mappingID)
	if err != nil {
		return err
	}
	return checkRowsAffected(result)
}

func (r *OrganizationRepo) ListGroupMappingsForSource(ctx context.Context, clientID, source, sourceID string, groups []string) ([]*domain.OrganizationGroupMapping, error) {
	if len(groups) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, client_id, organization_id, source, source_id, group_name, role, permissions, description, created_at, updated_at
		FROM organization_group_mappings
		WHERE client_id = $1
		  AND source = $2
		  AND (source_id = $3 OR source_id = '')
		  AND group_name = ANY($4)
		ORDER BY organization_id, group_name`, clientID, source, sourceID, pq.Array(groups))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]*domain.OrganizationGroupMapping, 0)
	for rows.Next() {
		mapping, err := scanGroupMapping(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, mapping)
	}
	return out, rows.Err()
}

func scanOrganization(row rowScanner) (*domain.Organization, error) {
	var org domain.Organization
	var metadataJSON []byte
	var createdBy sql.NullString
	err := row.Scan(
		&org.ID, &org.ClientID, &org.Name, &org.Slug, &metadataJSON,
		&createdBy, &org.CreatedAt, &org.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if createdBy.Valid {
		org.CreatedByUserID = &createdBy.String
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &org.Metadata); err != nil {
			return nil, err
		}
	}
	if org.Metadata == nil {
		org.Metadata = map[string]interface{}{}
	}
	return &org, nil
}

func scanMembership(row rowScanner) (*domain.OrganizationMembership, error) {
	var membership domain.OrganizationMembership
	err := row.Scan(
		&membership.ID, &membership.ClientID, &membership.OrganizationID,
		&membership.UserID, &membership.Role, pq.Array(&membership.Permissions),
		&membership.Status, &membership.CreatedAt, &membership.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &membership, nil
}

func scanInvitation(row rowScanner) (*domain.OrganizationInvitation, error) {
	var invitation domain.OrganizationInvitation
	var invitedBy sql.NullString
	var acceptedAt sql.NullTime
	var revokedAt sql.NullTime
	err := row.Scan(
		&invitation.ID, &invitation.ClientID, &invitation.OrganizationID,
		&invitation.Email, &invitation.Role, pq.Array(&invitation.Permissions),
		&invitation.TokenHash, &invitation.Status, &invitedBy,
		&invitation.ExpiresAt, &acceptedAt, &revokedAt,
		&invitation.CreatedAt, &invitation.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if invitedBy.Valid {
		invitation.InvitedByUserID = &invitedBy.String
	}
	if acceptedAt.Valid {
		invitation.AcceptedAt = &acceptedAt.Time
	}
	if revokedAt.Valid {
		invitation.RevokedAt = &revokedAt.Time
	}
	return &invitation, nil
}

func scanOrganizationAndMembership(row rowScanner) (*domain.Organization, *domain.OrganizationMembership, error) {
	var org domain.Organization
	var membership domain.OrganizationMembership
	var metadataJSON []byte
	var createdBy sql.NullString
	err := row.Scan(
		&org.ID, &org.ClientID, &org.Name, &org.Slug, &metadataJSON,
		&createdBy, &org.CreatedAt, &org.UpdatedAt,
		&membership.ID, &membership.ClientID, &membership.OrganizationID,
		&membership.UserID, &membership.Role, pq.Array(&membership.Permissions),
		&membership.Status, &membership.CreatedAt, &membership.UpdatedAt,
	)
	if err != nil {
		return nil, nil, err
	}
	if createdBy.Valid {
		org.CreatedByUserID = &createdBy.String
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &org.Metadata); err != nil {
			return nil, nil, err
		}
	}
	if org.Metadata == nil {
		org.Metadata = map[string]interface{}{}
	}
	return &org, &membership, nil
}

func scanAuthorizationPolicy(row rowScanner) (*domain.OrganizationAuthorizationPolicy, error) {
	var policy domain.OrganizationAuthorizationPolicy
	var resourcesJSON, permissionsJSON, rolesJSON []byte
	err := row.Scan(
		&policy.ClientID, &policy.OrganizationID, &policy.Version, &policy.Description,
		&resourcesJSON, &permissionsJSON, &rolesJSON, &policy.CreatedAt, &policy.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(resourcesJSON) > 0 {
		if err := json.Unmarshal(resourcesJSON, &policy.Resources); err != nil {
			return nil, err
		}
	}
	if len(permissionsJSON) > 0 {
		if err := json.Unmarshal(permissionsJSON, &policy.Permissions); err != nil {
			return nil, err
		}
	}
	if len(rolesJSON) > 0 {
		if err := json.Unmarshal(rolesJSON, &policy.Roles); err != nil {
			return nil, err
		}
	}
	return &policy, nil
}

func scanGroupMapping(row rowScanner) (*domain.OrganizationGroupMapping, error) {
	var mapping domain.OrganizationGroupMapping
	err := row.Scan(
		&mapping.ID, &mapping.ClientID, &mapping.OrganizationID, &mapping.Source,
		&mapping.SourceID, &mapping.Group, &mapping.Role, pq.Array(&mapping.Permissions),
		&mapping.Description, &mapping.CreatedAt, &mapping.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &mapping, nil
}
