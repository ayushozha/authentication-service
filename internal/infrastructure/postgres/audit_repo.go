package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
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
		INSERT INTO audit_events (client_id, user_id, event_type, ip_address, user_agent, metadata, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
		clientID, userID, eventType, ip, ua, metadataJSON,
	)
	if err != nil {
		log.Printf("audit: failed to log event %s: %v", eventType, err)
	}
}
