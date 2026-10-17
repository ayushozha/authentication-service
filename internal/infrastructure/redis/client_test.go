package redis

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// Exercises the production Redis Lua primitive; no in-memory implementation can
// establish its atomic behavior. Only a dedicated local test Redis is intended.
func TestGetDelConsumesAtomically(t *testing.T) {
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("TEST_REDIS_URL is not set")
	}
	client, err := NewClient(redisURL, fmt.Sprintf("auth-binding-test:%d:", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.client.Close() })
	ctx := context.Background()
	if err := client.Set(ctx, "code", "single-use-value", time.Minute); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Del(ctx, "code") })
	var wg sync.WaitGroup
	results := make(chan string, 16)
	for range 16 {
		wg.Go(func() {
			value, err := client.GetDel(ctx, "code")
			if err == nil {
				results <- value
			}
		})
	}
	wg.Wait()
	close(results)
	winners := 0
	for value := range results {
		if value != "single-use-value" {
			t.Fatalf("unexpected consumed value %q", value)
		}
		winners++
	}
	if winners != 1 {
		t.Fatalf("Redis consumption winners=%d, want 1", winners)
	}
	if _, err := client.GetDel(ctx, "code"); err == nil {
		t.Fatal("replayed Redis key succeeded")
	}
}
