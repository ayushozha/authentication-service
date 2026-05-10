package application

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

const (
	defaultAuditEventLimit = 50
	maxAuditEventLimit     = 10000
)

type AuditEventRepository interface {
	Log(ctx context.Context, clientID string, userID *string, eventType, ip, ua string, metadata map[string]interface{})
	List(ctx context.Context, filter domain.AuditEventFilter) ([]*domain.AuditEvent, error)
}

type AuditLegalHoldRepository interface {
	SetLegalHold(ctx context.Context, req domain.AuditLegalHoldRequest) (*domain.AuditLegalHoldResult, error)
}

type AuditRetentionRepository interface {
	PurgeExpired(ctx context.Context, req domain.AuditRetentionPurgeRequest) (*domain.AuditRetentionPurgeResult, error)
}

type AuditChainRepository interface {
	VerifyChain(ctx context.Context, filter domain.AuditEventFilter) (*domain.AuditChainVerification, error)
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
	filter.ActorType = strings.TrimSpace(filter.ActorType)
	filter.ActorID = strings.TrimSpace(filter.ActorID)
	filter.TargetType = strings.TrimSpace(filter.TargetType)
	filter.TargetID = strings.TrimSpace(filter.TargetID)
	filter.RequestID = strings.TrimSpace(filter.RequestID)
	if filter.Limit <= 0 {
		filter.Limit = defaultAuditEventLimit
	}
	if filter.Limit > maxAuditEventLimit {
		filter.Limit = maxAuditEventLimit
	}
	return s.events.List(ctx, filter)
}

func (s *AuditService) SetLegalHold(ctx context.Context, req domain.AuditLegalHoldRequest) (*domain.AuditLegalHoldResult, error) {
	if len(req.EventIDs) == 0 {
		return nil, domain.ErrInvalidRequest
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.LegalHold && req.Reason == "" {
		return nil, errors.New("reason is required when enabling legal hold")
	}
	repo, ok := s.events.(AuditLegalHoldRepository)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return repo.SetLegalHold(ctx, req)
}

func (s *AuditService) PurgeExpired(ctx context.Context, req domain.AuditRetentionPurgeRequest) (*domain.AuditRetentionPurgeResult, error) {
	if req.Before.IsZero() {
		req.Before = time.Now().UTC()
	}
	repo, ok := s.events.(AuditRetentionRepository)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return repo.PurgeExpired(ctx, req)
}

func (s *AuditService) VerifyChain(ctx context.Context, filter domain.AuditEventFilter) (*domain.AuditChainVerification, error) {
	filter.ClientID = strings.TrimSpace(filter.ClientID)
	if filter.Limit <= 0 {
		filter.Limit = maxAuditEventLimit
	}
	repo, ok := s.events.(AuditChainRepository)
	if !ok {
		return nil, domain.ErrNotFound
	}
	return repo.VerifyChain(ctx, filter)
}
