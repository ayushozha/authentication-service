package domain

import (
	"context"
	"time"
)

type AuditEvent struct {
	ID              int64                  `json:"id"`
	ClientID        string                 `json:"client_id,omitempty"`
	UserID          *string                `json:"user_id,omitempty"`
	EventType       string                 `json:"event_type"`
	ActorType       string                 `json:"actor_type,omitempty"`
	ActorID         string                 `json:"actor_id,omitempty"`
	ActorEmail      string                 `json:"actor_email,omitempty"`
	TargetType      string                 `json:"target_type,omitempty"`
	TargetID        string                 `json:"target_id,omitempty"`
	RequestID       string                 `json:"request_id,omitempty"`
	IPAddress       string                 `json:"ip_address"`
	UserAgent       string                 `json:"user_agent"`
	Metadata        map[string]interface{} `json:"metadata"`
	BeforeMetadata  map[string]interface{} `json:"before_metadata,omitempty"`
	AfterMetadata   map[string]interface{} `json:"after_metadata,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	RetentionUntil  *time.Time             `json:"retention_until,omitempty"`
	LegalHold       bool                   `json:"legal_hold"`
	LegalHoldReason string                 `json:"legal_hold_reason,omitempty"`
	LegalHoldAt     *time.Time             `json:"legal_hold_at,omitempty"`
	ChainScope      string                 `json:"chain_scope,omitempty"`
	PreviousHash    string                 `json:"previous_hash,omitempty"`
	EventHash       string                 `json:"event_hash,omitempty"`
	HashAlgorithm   string                 `json:"hash_algorithm,omitempty"`
}

type AuditEventFilter struct {
	ClientID   string
	UserID     string
	EventType  string
	ActorType  string
	ActorID    string
	TargetType string
	TargetID   string
	RequestID  string
	From       time.Time
	To         time.Time
	LegalHold  *bool
	Limit      int
}

type AuditLegalHoldRequest struct {
	EventIDs  []int64 `json:"event_ids"`
	LegalHold bool    `json:"legal_hold"`
	Reason    string  `json:"reason"`
}

type AuditLegalHoldResult struct {
	Updated int64 `json:"updated"`
}

type AuditRetentionPurgeRequest struct {
	Before time.Time `json:"before"`
	DryRun bool      `json:"dry_run"`
}

type AuditRetentionPurgeResult struct {
	Matched int64 `json:"matched"`
	Deleted int64 `json:"deleted"`
	DryRun  bool  `json:"dry_run"`
}

type AuditChainVerification struct {
	Scope                string              `json:"scope"`
	Checked              int                 `json:"checked"`
	Valid                bool                `json:"valid"`
	LegacyUnhashed       int                 `json:"legacy_unhashed"`
	StartsWithAnchorHash bool                `json:"starts_with_anchor_hash"`
	FirstEventID         int64               `json:"first_event_id,omitempty"`
	LastEventID          int64               `json:"last_event_id,omitempty"`
	LastHash             string              `json:"last_hash,omitempty"`
	Failures             []AuditChainFailure `json:"failures,omitempty"`
}

type AuditChainFailure struct {
	EventID  int64  `json:"event_id"`
	Problem  string `json:"problem"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
}

type AuditEventSink interface {
	PublishAuditEvent(ctx context.Context, event *AuditEvent)
}
