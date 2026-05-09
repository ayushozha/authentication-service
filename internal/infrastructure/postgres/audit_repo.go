package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"strconv"
	"strings"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type AuditRepo struct {
	db *sql.DB
}

func NewAuditRepo(db *sql.DB) *AuditRepo {
	return &AuditRepo{db: db}
}

func (r *AuditRepo) Log(ctx context.Context, clientID string, userID *string, eventType, ip, ua string, metadata map[string]interface{}) {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		log.Printf("audit: failed to marshal metadata: %v", err)
		metadataJSON = []byte("{}")
	}

	_, err = r.db.ExecContext(ctx, `
		INSERT INTO login_audit_log (client_id, user_id, event_type, ip_address, user_agent, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
		clientID, userID, eventType, ip, ua, metadataJSON,
	)
	if err != nil {
		log.Printf("audit: failed to log event %s: %v", eventType, err)
	}
}

func (r *AuditRepo) List(ctx context.Context, filter domain.AuditEventFilter) ([]*domain.AuditEvent, error) {
	where := make([]string, 0, 3)
	args := make([]interface{}, 0, 4)
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

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	query := `
		SELECT id, client_id, user_id, event_type, ip_address, user_agent, metadata, created_at
		FROM login_audit_log`
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

	events := make([]*domain.AuditEvent, 0)
	for rows.Next() {
		var event domain.AuditEvent
		var userID sql.NullString
		var metadata []byte
		if err := rows.Scan(
			&event.ID,
			&event.ClientID,
			&userID,
			&event.EventType,
			&event.IPAddress,
			&event.UserAgent,
			&metadata,
			&event.CreatedAt,
		); err != nil {
			return nil, err
		}
		if userID.Valid {
			event.UserID = &userID.String
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
				event.Metadata = map[string]interface{}{}
			}
		}
		if event.Metadata == nil {
			event.Metadata = map[string]interface{}{}
		}
		events = append(events, &event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}
