package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

type Client struct {
	client *goredis.Client
	prefix string
}

func NewClient(redisURL, prefix string) (*Client, error) {
	if redisURL == "" {
		return nil, nil
	}

	opts, err := goredis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}

	client := goredis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return &Client{client: client, prefix: prefix}, nil
}

func (r *Client) key(parts ...string) string {
	result := r.prefix
	for _, p := range parts {
		result += p
	}
	return result
}

func (r *Client) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return r.client.Set(ctx, r.key(key), value, ttl).Err()
}

func (r *Client) Get(ctx context.Context, key string) (string, error) {
	return r.client.Get(ctx, r.key(key)).Result()
}

func (r *Client) Del(ctx context.Context, key string) error {
	return r.client.Del(ctx, r.key(key)).Err()
}

func (r *Client) Incr(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, r.key(key)).Result()
}

func (r *Client) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return r.client.Expire(ctx, r.key(key), ttl).Err()
}

func (r *Client) Exists(ctx context.Context, key string) (bool, error) {
	val, err := r.client.Exists(ctx, r.key(key)).Result()
	return val > 0, err
}

func (r *Client) Ping(ctx context.Context) error {
	if r == nil || r.client == nil {
		return fmt.Errorf("redis not configured")
	}
	return r.client.Ping(ctx).Err()
}
