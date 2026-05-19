// Package store defines the key-value abstraction Wicket uses for transient
// state: issued challenges, identity nullifiers, rate-limit counters, and
// queue tickets.
//
// Implementations must be safe for concurrent use. The in-memory backend in
// pkg/store/memory is the reference implementation and is used by all tests.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("store: key not found")
	ErrExists   = errors.New("store: key already exists")
)

type Store interface {
	Get(ctx context.Context, key string) ([]byte, error)

	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) error

	Delete(ctx context.Context, key string) error

	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)

	Close() error
}
