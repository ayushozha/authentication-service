package application

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
	"github.com/google/uuid"
)

type WebhookAuditRepository struct {
	next       AuditRepository
	clients    ClientRepository
	secret     string
	attempts   int
	timeout    time.Duration
	httpClient *http.Client
	sleep      func(time.Duration)
}

type WebhookAuditPayload struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	CreatedAt time.Time         `json:"created_at"`
	Data      domain.AuditEvent `json:"data"`
}

func NewWebhookAuditRepository(next AuditRepository, clients ClientRepository, secret string, attempts int, timeout time.Duration) *WebhookAuditRepository {
	if attempts <= 0 {
		attempts = 3
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &WebhookAuditRepository{
		next:       next,
		clients:    clients,
		secret:     strings.TrimSpace(secret),
		attempts:   attempts,
		timeout:    timeout,
		httpClient: &http.Client{Timeout: timeout},
		sleep:      time.Sleep,
	}
}

func (r *WebhookAuditRepository) Log(ctx context.Context, clientID string, userID *string, eventType, ip, ua string, metadata map[string]interface{}) {
	if r.next != nil {
		r.next.Log(ctx, clientID, userID, eventType, ip, ua, metadata)
	}
	if r.clients == nil || r.secret == "" {
		return
	}
	now := time.Now().UTC()
	event := domain.AuditEvent{
		ID:        now.UnixNano(),
		ClientID:  clientID,
		UserID:    userID,
		EventType: eventType,
		IPAddress: ip,
		UserAgent: ua,
		Metadata:  cloneAuditMetadata(metadata),
		CreatedAt: now,
	}
	go r.deliver(context.Background(), event)
}

func cloneAuditMetadata(metadata map[string]interface{}) map[string]interface{} {
	if len(metadata) == 0 {
		return map[string]interface{}{}
	}
	clone := make(map[string]interface{}, len(metadata))
	for key, value := range metadata {
		clone[key] = value
	}
	return clone
}

func (r *WebhookAuditRepository) deliver(ctx context.Context, event domain.AuditEvent) {
	client, err := r.clients.GetByID(ctx, event.ClientID)
	if err != nil || client == nil || strings.TrimSpace(client.WebhookURL) == "" {
		return
	}
	payload := WebhookAuditPayload{
		ID:        uuid.NewString(),
		Type:      "audit.event",
		CreatedAt: time.Now().UTC(),
		Data:      event,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	for attempt := 1; attempt <= r.attempts; attempt++ {
		if r.post(ctx, client.WebhookURL, payload.ID, body) {
			return
		}
		if attempt < r.attempts && r.sleep != nil {
			r.sleep(time.Duration(attempt) * 200 * time.Millisecond)
		}
	}
}

func (r *WebhookAuditRepository) post(ctx context.Context, webhookURL, deliveryID string, body []byte) bool {
	reqCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return false
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AuthService-Webhooks/1.0")
	req.Header.Set("X-AuthService-Event", "audit.event")
	req.Header.Set("X-AuthService-Delivery", deliveryID)
	req.Header.Set("X-AuthService-Timestamp", timestamp)
	req.Header.Set("X-AuthService-Signature", SignWebhookPayload(r.secret, timestamp, body))

	res, err := r.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode >= 200 && res.StatusCode < 300
}

func SignWebhookPayload(secret, timestamp string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(payload)
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

func VerifyWebhookSignature(secret, timestamp, signature string, payload []byte) bool {
	expected := SignWebhookPayload(secret, timestamp, payload)
	return hmac.Equal([]byte(expected), []byte(signature))
}
