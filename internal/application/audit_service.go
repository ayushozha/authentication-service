package application

import (
	"context"
	"strings"

	"github.com/Ayush10/authentication-service/internal/domain"
)

const (
	defaultAuditEventLimit = 50
	maxAuditEventLimit     = 500
)

type AuditEventRepository interface {
	Log(ctx context.Context, clientID string, userID *string, eventType, ip, ua string, metadata map[string]interface{})
	List(ctx context.Context, filter domain.AuditEventFilter) ([]*domain.AuditEvent, error)
}

type AuditService struct {
	events AuditEventRepository
}

func NewAuditService(events AuditEventRepository) *AuditService {
	return &AuditService{events: events}
}

func (s *AuditService) ListEvents(ctx context.Context, filter domain.AuditEventFilter) ([]*domain.AuditEvent, error) {
	filter.ClientID = strings.TrimSpace(filter.ClientID)
	filter.UserID = strings.TrimSpace(filter.UserID)
	filter.EventType = strings.TrimSpace(filter.EventType)
	if filter.Limit <= 0 {
		filter.Limit = defaultAuditEventLimit
	}
	if filter.Limit > maxAuditEventLimit {
		filter.Limit = maxAuditEventLimit
	}
	return s.events.List(ctx, filter)
}
