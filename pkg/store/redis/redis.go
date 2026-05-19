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

// incrExpireScript atomically increments key and, on the creating call,
// sets the TTL in a single round trip. Doing this as two commands (INCR
// then EXPIRE) is racy: a process crash or connection drop between them
// leaves the counter without a TTL, turning a rolling-window rate limit
// into an all-time counter. Running both inside a single Redis script
// makes the pair indivisible on the server side.
var incrExpireScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if tonumber(ARGV[1]) > 0 and n == 1 then
    redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return n
`)

func (s *Store) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		// No TTL requested: a plain INCR is sufficient and avoids the
		// script-load round trip on cold caches.
		n, err := s.c.Incr(ctx, key).Result()
		if err != nil {
			return 0, err
		}
		return n, nil
	}
	res, err := incrExpireScript.Run(ctx, s.c, []string{key}, ttl.Milliseconds()).Result()
	if err != nil {
		return 0, err
	}
	n, ok := res.(int64)
	if !ok {
		return 0, errors.New("redis: incr script returned non-integer")
	}
	return n, nil
}

func (s *Store) Close() error {
	return s.c.Close()
}
