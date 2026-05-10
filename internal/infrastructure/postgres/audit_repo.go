package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

const (
	defaultAuditRetentionDays = 2555
	auditHashAlgorithm        = "sha256:v1"
)

type AuditRepo struct {
	db            *sql.DB
	retentionDays int
	sink          domain.AuditEventSink
}

type AuditRepoOption func(*AuditRepo)

func WithAuditRetentionDays(days int) AuditRepoOption {
	return func(r *AuditRepo) {
		if days > 0 {
			r.retentionDays = days
		}
	}
}

func WithAuditEventSink(sink domain.AuditEventSink) AuditRepoOption {
	return func(r *AuditRepo) {
		r.sink = sink
	}
}

func NewAuditRepo(db *sql.DB, opts ...AuditRepoOption) *AuditRepo {
	repo := &AuditRepo{
		db:            db,
		retentionDays: defaultAuditRetentionDays,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(repo)
		}
	}
	return repo
}

func (r *AuditRepo) Log(ctx context.Context, clientID string, userID *string, eventType, ip, ua string, metadata map[string]interface{}) {
	actorID := ""
	if userID != nil {
		actorID = *userID
	}
	event := &domain.AuditEvent{
		ClientID:  strings.TrimSpace(clientID),
		UserID:    cloneAuditUserID(userID),
		EventType: strings.TrimSpace(eventType),
		ActorType: "user",
		ActorID:   actorID,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  cloneAuditMap(metadata),
	}
	if err := r.insertEvent(ctx, event); err != nil {
		log.Printf("audit: failed to log event %s: %v", eventType, err)
	}
}

func (r *AuditRepo) LogAdmin(ctx context.Context, event *domain.AuditEvent) {
	if event == nil {
		return
	}
	cp := cloneAuditEvent(event)
	if cp.ActorType == "" {
		cp.ActorType = domain.AdminActorTypeUser
	}
	if err := r.insertEvent(ctx, cp); err != nil {
		log.Printf("audit: failed to log admin event %s: %v", event.EventType, err)
	}
}

func (r *AuditRepo) List(ctx context.Context, filter domain.AuditEventFilter) ([]*domain.AuditEvent, error) {
	where := make([]string, 0, 12)
	args := make([]interface{}, 0, 12)
	addFilter := func(column, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		args = append(args, value)
		where = append(where, column+" = $"+strconv.Itoa(len(args)))
	}

	addFilter("client_id", filter.ClientID)
	addFilter("user_id", filter.UserID)
	addFilter("event_type", filter.EventType)
	addFilter("actor_type", filter.ActorType)
	addFilter("actor_id", filter.ActorID)
	addFilter("target_type", filter.TargetType)
	addFilter("target_id", filter.TargetID)
	addFilter("request_id", filter.RequestID)
	if !filter.From.IsZero() {
		args = append(args, filter.From)
		where = append(where, "created_at >= $"+strconv.Itoa(len(args)))
	}
	if !filter.To.IsZero() {
		args = append(args, filter.To)
		where = append(where, "created_at <= $"+strconv.Itoa(len(args)))
	}
	if filter.LegalHold != nil {
		args = append(args, *filter.LegalHold)
		where = append(where, "legal_hold = $"+strconv.Itoa(len(args)))
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 10000 {
		limit = 10000
	}

	query := auditSelectQuery() + ` FROM login_audit_log`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, limit)
	query += " ORDER BY created_at DESC, id DESC LIMIT $" + strconv.Itoa(len(args))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAuditEventRows(rows)
}

func (r *AuditRepo) SetLegalHold(ctx context.Context, req domain.AuditLegalHoldRequest) (*domain.AuditLegalHoldResult, error) {
	if len(req.EventIDs) == 0 {
		return nil, domain.ErrInvalidRequest
	}
	args := make([]interface{}, 0, len(req.EventIDs)+3)
	placeholders := make([]string, 0, len(req.EventIDs))
	for _, id := range req.EventIDs {
		if id <= 0 {
			continue
		}
		args = append(args, id)
		placeholders = append(placeholders, "$"+strconv.Itoa(len(args)))
	}
	if len(placeholders) == 0 {
		return nil, domain.ErrInvalidRequest
	}
	args = append(args, req.LegalHold, strings.TrimSpace(req.Reason))
	legalHoldPos := len(args) - 1
	reasonPos := len(args)
	result, err := r.db.ExecContext(ctx, `
		UPDATE login_audit_log
		SET legal_hold = $`+strconv.Itoa(legalHoldPos)+`,
			legal_hold_reason = CASE WHEN $`+strconv.Itoa(legalHoldPos)+` THEN $`+strconv.Itoa(reasonPos)+` ELSE '' END,
			legal_hold_at = CASE WHEN $`+strconv.Itoa(legalHoldPos)+` THEN NOW() ELSE NULL END
		WHERE id IN (`+strings.Join(placeholders, ", ")+`)`,
		args...,
	)
	if err != nil {
		return nil, err
	}
	updated, _ := result.RowsAffected()
	return &domain.AuditLegalHoldResult{Updated: updated}, nil
}

func (r *AuditRepo) PurgeExpired(ctx context.Context, req domain.AuditRetentionPurgeRequest) (*domain.AuditRetentionPurgeResult, error) {
	before := req.Before
	if before.IsZero() {
		before = time.Now().UTC()
	}
	var matched int64
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM login_audit_log
		WHERE legal_hold = FALSE
			AND retention_until IS NOT NULL
			AND retention_until <= $1`,
		before,
	).Scan(&matched); err != nil {
		return nil, err
	}
	if req.DryRun {
		return &domain.AuditRetentionPurgeResult{Matched: matched, DryRun: true}, nil
	}
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM login_audit_log
		WHERE legal_hold = FALSE
			AND retention_until IS NOT NULL
			AND retention_until <= $1`,
		before,
	)
	if err != nil {
		return nil, err
	}
	deleted, _ := result.RowsAffected()
	return &domain.AuditRetentionPurgeResult{Matched: matched, Deleted: deleted}, nil
}

func (r *AuditRepo) VerifyChain(ctx context.Context, filter domain.AuditEventFilter) (*domain.AuditChainVerification, error) {
	scope := auditChainScope(filter.ClientID)
	limit := filter.Limit
	if limit <= 0 {
		limit = 10000
	}
	if limit > 100000 {
		limit = 100000
	}
	rows, err := r.db.QueryContext(ctx, auditSelectQuery()+`
		FROM login_audit_log
		WHERE chain_scope = $1
		ORDER BY id ASC
		LIMIT $2`,
		scope,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events, err := scanAuditEventRows(rows)
	if err != nil {
		return nil, err
	}

	result := &domain.AuditChainVerification{
		Scope:   scope,
		Valid:   true,
		Checked: len(events),
	}
	var previousHash string
	for _, event := range events {
		if event.EventHash == "" {
			result.LegacyUnhashed++
			continue
		}
		if result.FirstEventID == 0 {
			result.FirstEventID = event.ID
			if event.PreviousHash != "" {
				result.StartsWithAnchorHash = true
			}
		}
		result.LastEventID = event.ID
		expectedHash := computeAuditEventHash(event)
		if expectedHash != event.EventHash {
			result.Valid = false
			result.Failures = append(result.Failures, domain.AuditChainFailure{
				EventID:  event.ID,
				Problem:  "event_hash_mismatch",
				Expected: expectedHash,
				Actual:   event.EventHash,
			})
		}
		if previousHash != "" && event.PreviousHash != previousHash {
			result.Valid = false
			result.Failures = append(result.Failures, domain.AuditChainFailure{
				EventID:  event.ID,
				Problem:  "previous_hash_mismatch",
				Expected: previousHash,
				Actual:   event.PreviousHash,
			})
		}
		previousHash = event.EventHash
		result.LastHash = event.EventHash
	}
	return result, nil
}

func (r *AuditRepo) insertEvent(ctx context.Context, event *domain.AuditEvent) error {
	normalizeAuditEvent(event, r.retentionDays)
	metadataJSON := marshalAuditMap(event.Metadata)
	beforeJSON := marshalAuditMap(event.BeforeMetadata)
	afterJSON := marshalAuditMap(event.AfterMetadata)
	userID := ""
	if event.UserID != nil {
		userID = *event.UserID
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, event.ChainScope); err != nil {
		return err
	}
	var previous sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT event_hash
		FROM login_audit_log
		WHERE chain_scope = $1 AND event_hash <> ''
		ORDER BY id DESC
		LIMIT 1`,
		event.ChainScope,
	).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if previous.Valid {
		event.PreviousHash = previous.String
	}

	var retentionUntil sql.NullTime
	if event.RetentionUntil != nil {
		retentionUntil = sql.NullTime{Time: *event.RetentionUntil, Valid: true}
	}
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO login_audit_log (
			client_id, user_id, event_type, actor_type, actor_id, actor_email,
			target_type, target_id, request_id, ip_address, user_agent, metadata,
			before_metadata, after_metadata, created_at, retention_until, legal_hold,
			legal_hold_reason, legal_hold_at, chain_scope, previous_hash, hash_algorithm
		)
		VALUES (
			NULLIF($1, '')::uuid, NULLIF($2, '')::uuid, $3, $4, $5, $6, $7, $8, $9,
			$10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
		)
		RETURNING id, created_at, retention_until`,
		event.ClientID,
		userID,
		event.EventType,
		event.ActorType,
		event.ActorID,
		event.ActorEmail,
		event.TargetType,
		event.TargetID,
		event.RequestID,
		event.IPAddress,
		event.UserAgent,
		metadataJSON,
		beforeJSON,
		afterJSON,
		event.CreatedAt,
		retentionUntil,
		event.LegalHold,
		event.LegalHoldReason,
		event.LegalHoldAt,
		event.ChainScope,
		event.PreviousHash,
		event.HashAlgorithm,
	).Scan(&event.ID, &event.CreatedAt, &retentionUntil); err != nil {
		return err
	}
	if retentionUntil.Valid {
		retentionAt := retentionUntil.Time.UTC()
		event.RetentionUntil = &retentionAt
	}
	event.EventHash = computeAuditEventHash(event)
	if _, err := tx.ExecContext(ctx, `
		UPDATE login_audit_log
		SET event_hash = $1
		WHERE id = $2`,
		event.EventHash,
		event.ID,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if r.sink != nil {
		go r.sink.PublishAuditEvent(context.Background(), cloneAuditEvent(event))
	}
	return nil
}

func auditSelectQuery() string {
	return `
		SELECT id, COALESCE(client_id::text, ''), user_id, event_type,
			actor_type, actor_id, actor_email, target_type, target_id, request_id,
			ip_address, user_agent, metadata, before_metadata, after_metadata, created_at,
			retention_until, legal_hold, legal_hold_reason, legal_hold_at, chain_scope,
			previous_hash, event_hash, hash_algorithm`
}

func scanAuditEventRows(rows *sql.Rows) ([]*domain.AuditEvent, error) {
	events := make([]*domain.AuditEvent, 0)
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

type auditEventScanner interface {
	Scan(dest ...interface{}) error
}

func scanAuditEvent(scanner auditEventScanner) (*domain.AuditEvent, error) {
	var event domain.AuditEvent
	var userID sql.NullString
	var metadata []byte
	var beforeMetadata []byte
	var afterMetadata []byte
	var retentionUntil sql.NullTime
	var legalHoldAt sql.NullTime
	if err := scanner.Scan(
		&event.ID,
		&event.ClientID,
		&userID,
		&event.EventType,
		&event.ActorType,
		&event.ActorID,
		&event.ActorEmail,
		&event.TargetType,
		&event.TargetID,
		&event.RequestID,
		&event.IPAddress,
		&event.UserAgent,
		&metadata,
		&beforeMetadata,
		&afterMetadata,
		&event.CreatedAt,
		&retentionUntil,
		&event.LegalHold,
		&event.LegalHoldReason,
		&legalHoldAt,
		&event.ChainScope,
		&event.PreviousHash,
		&event.EventHash,
		&event.HashAlgorithm,
	); err != nil {
		return nil, err
	}
	if userID.Valid {
		event.UserID = &userID.String
	}
	if retentionUntil.Valid {
		t := retentionUntil.Time.UTC()
		event.RetentionUntil = &t
	}
	if legalHoldAt.Valid {
		t := legalHoldAt.Time.UTC()
		event.LegalHoldAt = &t
	}
	event.CreatedAt = event.CreatedAt.UTC()
	event.Metadata = unmarshalAuditMap(metadata)
	event.BeforeMetadata = unmarshalAuditMap(beforeMetadata)
	event.AfterMetadata = unmarshalAuditMap(afterMetadata)
	return &event, nil
}

func normalizeAuditEvent(event *domain.AuditEvent, retentionDays int) {
	event.ClientID = strings.TrimSpace(event.ClientID)
	event.EventType = strings.TrimSpace(event.EventType)
	event.ActorType = strings.TrimSpace(event.ActorType)
	if event.ActorType == "" {
		if event.UserID != nil {
			event.ActorType = "user"
		} else {
			event.ActorType = "system"
		}
	}
	event.ActorID = strings.TrimSpace(event.ActorID)
	event.ActorEmail = strings.TrimSpace(event.ActorEmail)
	event.TargetType = strings.TrimSpace(event.TargetType)
	event.TargetID = strings.TrimSpace(event.TargetID)
	event.RequestID = strings.TrimSpace(event.RequestID)
	event.Metadata = cloneAuditMap(event.Metadata)
	event.BeforeMetadata = cloneAuditMap(event.BeforeMetadata)
	event.AfterMetadata = cloneAuditMap(event.AfterMetadata)
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	} else {
		event.CreatedAt = event.CreatedAt.UTC()
	}
	if event.RetentionUntil == nil && retentionDays > 0 {
		retentionUntil := event.CreatedAt.Add(time.Duration(retentionDays) * 24 * time.Hour)
		event.RetentionUntil = &retentionUntil
	}
	if event.RetentionUntil != nil {
		retentionUntil := event.RetentionUntil.UTC()
		event.RetentionUntil = &retentionUntil
	}
	event.ChainScope = auditChainScope(event.ClientID)
	event.HashAlgorithm = auditHashAlgorithm
	if event.LegalHoldAt != nil {
		legalHoldAt := event.LegalHoldAt.UTC()
		event.LegalHoldAt = &legalHoldAt
	}
	if !event.LegalHold {
		event.LegalHoldReason = ""
		event.LegalHoldAt = nil
	}
}

func computeAuditEventHash(event *domain.AuditEvent) string {
	userID := ""
	if event.UserID != nil {
		userID = *event.UserID
	}
	retentionUntil := ""
	if event.RetentionUntil != nil {
		retentionUntil = event.RetentionUntil.UTC().Format(time.RFC3339Nano)
	}
	canonical := map[string]interface{}{
		"id":              event.ID,
		"client_id":       event.ClientID,
		"user_id":         userID,
		"event_type":      event.EventType,
		"actor_type":      event.ActorType,
		"actor_id":        event.ActorID,
		"actor_email":     event.ActorEmail,
		"target_type":     event.TargetType,
		"target_id":       event.TargetID,
		"request_id":      event.RequestID,
		"ip_address":      event.IPAddress,
		"user_agent":      event.UserAgent,
		"metadata":        cloneAuditMap(event.Metadata),
		"before_metadata": cloneAuditMap(event.BeforeMetadata),
		"after_metadata":  cloneAuditMap(event.AfterMetadata),
		"created_at":      event.CreatedAt.UTC().Format(time.RFC3339Nano),
		"retention_until": retentionUntil,
		"chain_scope":     event.ChainScope,
		"previous_hash":   event.PreviousHash,
		"hash_algorithm":  event.HashAlgorithm,
	}
	raw, _ := json.Marshal(canonical)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func auditChainScope(clientID string) string {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return "global"
	}
	return clientID
}

func marshalAuditMap(value map[string]interface{}) []byte {
	raw, err := json.Marshal(cloneAuditMap(value))
	if err != nil {
		log.Printf("audit: failed to marshal metadata: %v", err)
		return []byte("{}")
	}
	return raw
}

func unmarshalAuditMap(raw []byte) map[string]interface{} {
	out := map[string]interface{}{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]interface{}{}
	}
	return out
}

func cloneAuditMap(value map[string]interface{}) map[string]interface{} {
	if len(value) == 0 {
		return map[string]interface{}{}
	}
	clone := make(map[string]interface{}, len(value))
	for key, item := range value {
		clone[key] = item
	}
	return clone
}

func cloneAuditUserID(userID *string) *string {
	if userID == nil {
		return nil
	}
	value := strings.TrimSpace(*userID)
	if value == "" {
		return nil
	}
	return &value
}

func cloneAuditEvent(event *domain.AuditEvent) *domain.AuditEvent {
	if event == nil {
		return nil
	}
	cp := *event
	cp.UserID = cloneAuditUserID(event.UserID)
	cp.Metadata = cloneAuditMap(event.Metadata)
	cp.BeforeMetadata = cloneAuditMap(event.BeforeMetadata)
	cp.AfterMetadata = cloneAuditMap(event.AfterMetadata)
	if event.RetentionUntil != nil {
		t := event.RetentionUntil.UTC()
		cp.RetentionUntil = &t
	}
	if event.LegalHoldAt != nil {
		t := event.LegalHoldAt.UTC()
		cp.LegalHoldAt = &t
	}
	return &cp
}
