package application

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

func TestWebhookAuditRepositorySignsAndRetriesAuditEvents(t *testing.T) {
	received := make(chan WebhookAuditPayload, 1)
	var attempts atomic.Int32
	var signatureOK atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)
		body, _ := io.ReadAll(r.Body)
		signatureOK.Store(VerifyWebhookSignature("webhook-secret", r.Header.Get("X-AuthService-Timestamp"), r.Header.Get("X-AuthService-Signature"), body))
		if attempt == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var payload WebhookAuditPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode webhook payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- payload
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	base := &recordingAuditRepo{}
	clients := &webhookClientRepo{client: &domain.Client{ID: "client-1", WebhookURL: server.URL}}
	repo := NewWebhookAuditRepository(base, clients, "webhook-secret", 3, time.Second)
	repo.sleep = func(time.Duration) {}

	userID := "user-1"
	repo.Log(context.Background(), "client-1", &userID, "login_success", "203.0.113.10", "test-agent", map[string]interface{}{"method": "email"})

	select {
	case payload := <-received:
		if !signatureOK.Load() {
			t.Fatal("webhook signature did not verify")
		}
		if attempts.Load() != 2 {
			t.Fatalf("expected retry after first failure, got %d attempts", attempts.Load())
		}
		if payload.Type != "audit.event" || payload.Data.ClientID != "client-1" || payload.Data.EventType != "login_success" {
			t.Fatalf("unexpected payload: %+v", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for webhook delivery")
	}
	if base.count.Load() != 1 {
		t.Fatalf("base audit repo should be called once, got %d", base.count.Load())
	}
}

type recordingAuditRepo struct {
	count atomic.Int32
}

func (r *recordingAuditRepo) Log(ctx context.Context, clientID string, userID *string, eventType, ip, ua string, metadata map[string]interface{}) {
	r.count.Add(1)
}

type webhookClientRepo struct {
	mu     sync.Mutex
	client *domain.Client
}

func (r *webhookClientRepo) Create(ctx context.Context, client *domain.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.client = client
	return nil
}

func (r *webhookClientRepo) GetByID(ctx context.Context, id string) (*domain.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.client == nil || r.client.ID != id {
		return nil, domain.ErrNotFound
	}
	return r.client, nil
}

func (r *webhookClientRepo) GetBySlug(ctx context.Context, slug string) (*domain.Client, error) {
	return nil, domain.ErrNotFound
}

func (r *webhookClientRepo) GetByAPIKeyHash(ctx context.Context, hash string) (*domain.Client, error) {
	return nil, domain.ErrNotFound
}

func (r *webhookClientRepo) List(ctx context.Context) ([]*domain.Client, error) {
	return nil, nil
}

func (r *webhookClientRepo) Update(ctx context.Context, client *domain.Client) error {
	return nil
}

func (r *webhookClientRepo) UpdateJWTSecret(ctx context.Context, id, newSecret string) error {
	return nil
}

func (r *webhookClientRepo) UpdateAPIKeyHash(ctx context.Context, id, newHash string) error {
	return nil
}
