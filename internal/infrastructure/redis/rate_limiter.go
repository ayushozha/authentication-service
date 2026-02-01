package redis

import (
	"context"
	"fmt"
	"time"
)

type RateLimiter struct {
	rdb *Client
}

func NewRateLimiter(rdb *Client) *RateLimiter {
	return &RateLimiter{rdb: rdb}
}

func (rl *RateLimiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (bool, int64, error) {
	if rl.rdb == nil {
		return true, limit, nil
	}

	count, err := rl.rdb.Incr(ctx, key)
	if err != nil {
		return true, limit, fmt.Errorf("rate limit incr: %w", err)
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
