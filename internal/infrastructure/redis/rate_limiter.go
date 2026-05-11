package redis

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

type RateLimiter struct {
	rdb *Client
}

func NewRateLimiter(rdb *Client) *RateLimiter {
	return &RateLimiter{rdb: rdb}
}

// failOpen reports whether the rate limiter should allow requests when Redis
// is unavailable. Defaults to false (fail closed). Set
// `RATE_LIMITER_FAIL_OPEN=true` only for local development.
func failOpen() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("RATE_LIMITER_FAIL_OPEN")), "true")
}

// Allow returns whether `key` is under `limit` over `window`. When Redis is
// unavailable, this fails CLOSED (denies the request) unless
// `RATE_LIMITER_FAIL_OPEN=true` is set explicitly. Failing open allows
// attackers to bypass throttling and account lockout by triggering a Redis
// outage.
func (rl *RateLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, int64, error) {
	if rl.rdb == nil {
		if failOpen() {
			return true, limit, nil
		}
		return false, 0, fmt.Errorf("rate limiter unavailable: redis not configured")
	}

	count, err := rl.rdb.Incr(ctx, key)
	if err != nil {
		if failOpen() {
			return true, limit, fmt.Errorf("rate limit incr (fail-open): %w", err)
		}
		return false, 0, fmt.Errorf("rate limit incr: %w", err)
	}

	if count == 1 {
		_ = rl.rdb.Expire(ctx, key, window)
	}

	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	return count <= limit, remaining, nil
}

func (rl *RateLimiter) IsLocked(ctx context.Context, email string) bool {
	if rl.rdb == nil {
		return false
	}
	exists, _ := rl.rdb.Exists(ctx, "lockout:"+email)
	return exists
}

func (rl *RateLimiter) RecordFailedLogin(ctx context.Context, email string) {
	if rl.rdb == nil {
		return
	}
	key := "login_fail:" + email
	count, err := rl.rdb.Incr(ctx, key)
	if err != nil {
		return
	}
	if count == 1 {
		_ = rl.rdb.Expire(ctx, key, 15*time.Minute)
	}
	if count >= 5 {
		_ = rl.rdb.Set(ctx, "lockout:"+email, "1", 30*time.Minute)
		_ = rl.rdb.Del(ctx, key)
	}
}

func (rl *RateLimiter) ClearFailedLogins(ctx context.Context, email string) {
	if rl.rdb == nil {
		return
	}
	_ = rl.rdb.Del(ctx, "login_fail:"+email)
	_ = rl.rdb.Del(ctx, "lockout:"+email)
}
