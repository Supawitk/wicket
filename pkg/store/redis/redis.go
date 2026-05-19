// Package redis implements the store.Store interface against a Redis or
// Redis-compatible server (Dragonfly, Valkey, KeyDB).
package redis

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Supawitk/wicket/pkg/store"
)

type Config struct {
	Addr     string
	Password string
	DB       int
}

type Store struct {
	c *redis.Client
}

func New(cfg Config) *Store {
	c := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	return &Store{c: c}
}

// FromClient wraps an existing go-redis client. Useful when callers want to
// share a client across components.
func FromClient(c *redis.Client) *Store { return &Store{c: c} }

func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	v, err := s.c.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.c.Set(ctx, key, value, ttl).Err()
}

func (s *Store) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	ok, err := s.c.SetNX(ctx, key, value, ttl).Result()
	if err != nil {
		return err
	}
	if !ok {
		return store.ErrExists
	}
	return nil
}

func (s *Store) Delete(ctx context.Context, key string) error {
	return s.c.Del(ctx, key).Err()
}

func (s *Store) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	n, err := s.c.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if ttl > 0 && n == 1 {
		// Only set the expiry on creation to preserve the rolling window.
		if err := s.c.Expire(ctx, key, ttl).Err(); err != nil {
			return 0, err
		}
	}
	return n, nil
}

func (s *Store) Close() error {
	return s.c.Close()
}
