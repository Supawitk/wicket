// Package degrading wraps a primary store with an in-memory fallback so
// requests keep flowing if the primary backend fails. When a primary
// operation returns an unexpected error (i.e. anything other than
// store.ErrNotFound or store.ErrExists), the wrapper marks itself degraded
// and routes subsequent calls to the fallback until a periodic health
// probe finds the primary healthy again.
package degrading

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/Supawitk/wicket/pkg/store"
)

type Store struct {
	primary  store.Store
	fallback store.Store
	degraded atomic.Bool
	probe    time.Duration
	now      func() time.Time
	lastSwap atomic.Int64
}

type Config struct {
	ProbeEvery time.Duration
	Now        func() time.Time
}

func New(primary, fallback store.Store, cfg Config) *Store {
	probe := cfg.ProbeEvery
	if probe <= 0 {
		probe = 5 * time.Second
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Store{
		primary:  primary,
		fallback: fallback,
		probe:    probe,
		now:      now,
	}
}

// Degraded reports whether the wrapper is currently routing to the
// fallback. Useful as a Prometheus gauge.
func (s *Store) Degraded() bool { return s.degraded.Load() }

func (s *Store) shouldTryPrimary() bool {
	if !s.degraded.Load() {
		return true
	}
	return s.now().UnixNano()-s.lastSwap.Load() > s.probe.Nanoseconds()
}

func benign(err error) bool {
	return errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExists)
}

func (s *Store) markHealthy() {
	if s.degraded.CompareAndSwap(true, false) {
		s.lastSwap.Store(s.now().UnixNano())
	}
}

func (s *Store) markDegraded() {
	if s.degraded.CompareAndSwap(false, true) {
		s.lastSwap.Store(s.now().UnixNano())
	}
}

func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	if s.shouldTryPrimary() {
		v, err := s.primary.Get(ctx, key)
		if err == nil || benign(err) {
			s.markHealthy()
			return v, err
		}
		s.markDegraded()
	}
	return s.fallback.Get(ctx, key)
}

func (s *Store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if s.shouldTryPrimary() {
		err := s.primary.Set(ctx, key, value, ttl)
		if err == nil || benign(err) {
			s.markHealthy()
			return err
		}
		s.markDegraded()
	}
	return s.fallback.Set(ctx, key, value, ttl)
}

func (s *Store) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if s.shouldTryPrimary() {
		err := s.primary.SetNX(ctx, key, value, ttl)
		if err == nil || benign(err) {
			s.markHealthy()
			return err
		}
		s.markDegraded()
	}
	return s.fallback.SetNX(ctx, key, value, ttl)
}

func (s *Store) Delete(ctx context.Context, key string) error {
	if s.shouldTryPrimary() {
		err := s.primary.Delete(ctx, key)
		if err == nil || benign(err) {
			s.markHealthy()
			return err
		}
		s.markDegraded()
	}
	return s.fallback.Delete(ctx, key)
}

func (s *Store) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	if s.shouldTryPrimary() {
		n, err := s.primary.Incr(ctx, key, ttl)
		if err == nil || benign(err) {
			s.markHealthy()
			return n, err
		}
		s.markDegraded()
	}
	return s.fallback.Incr(ctx, key, ttl)
}

func (s *Store) Close() error {
	err1 := s.primary.Close()
	err2 := s.fallback.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
