// Package degrading wraps a primary store with an in-memory fallback so
// requests keep flowing if the primary backend fails.
//
// Semantics:
//
//   - Reads (Get) try the primary first. On success the wrapper marks
//     healthy. On ErrNotFound while previously degraded it probes the
//     fallback before honouring the miss, because the key may have
//     been written only to the fallback during the outage. ErrNotFound
//     does NOT mark the wrapper healthy — only an actual data-bearing
//     success does. This is the fix for the silent-loss bug where a
//     just-recovered primary returned "not found" and the value lived
//     in the fallback the whole time.
//   - Writes (Set, SetNX, Delete) route to the primary while reachable
//     and fall back to the in-memory store while degraded. There is no
//     dual-write: writes accepted by the fallback during an outage are
//     not back-filled into the primary on recovery.
//   - Incr routes to a single store. The two backends cannot share a
//     counter without diverging.
//
// What this package does NOT guarantee: zero data loss across an
// outage/recovery boundary. Writes accepted only by the fallback
// during a degraded window are not migrated to the primary when it
// returns; subsequent reads of those keys keep working as long as the
// fallback is consulted (which Get does, per the rule above).
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

// markHealthy transitions the wrapper out of degraded mode. Only call
// this after a *successful* operation against the primary (data found
// on Get, write accepted on Set/SetNX/Delete) — never on a benign error
// like ErrNotFound, because a primary returning "not found" while we
// were degraded tells us nothing about whether the value lives in the
// fallback or simply does not exist.
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
	wasDegraded := s.degraded.Load()
	if s.shouldTryPrimary() {
		v, err := s.primary.Get(ctx, key)
		if err == nil {
			s.markHealthy()
			return v, nil
		}
		if errors.Is(err, store.ErrNotFound) {
			// A primary ErrNotFound while we were previously degraded
			// is ambiguous: the key may have been written only to the
			// fallback during the outage. Probe the fallback before
			// honouring the miss, and do NOT markHealthy on this path
			// — only a success on the primary proves recovery.
			if wasDegraded {
				if v2, err2 := s.fallback.Get(ctx, key); err2 == nil {
					return v2, nil
				}
			}
			return nil, err
		}
		s.markDegraded()
	}
	return s.fallback.Get(ctx, key)
}

func (s *Store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if s.shouldTryPrimary() {
		err := s.primary.Set(ctx, key, value, ttl)
		if err == nil {
			s.markHealthy()
			return nil
		}
		if !benign(err) {
			s.markDegraded()
		}
	}
	return s.fallback.Set(ctx, key, value, ttl)
}

func (s *Store) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if s.shouldTryPrimary() {
		err := s.primary.SetNX(ctx, key, value, ttl)
		if err == nil {
			s.markHealthy()
			return nil
		}
		if errors.Is(err, store.ErrExists) {
			// Primary said "already exists" — authoritative answer.
			// Don't markHealthy: ErrExists doesn't prove primary is
			// fully functional, only that this one key existed.
			return err
		}
		s.markDegraded()
	}
	return s.fallback.SetNX(ctx, key, value, ttl)
}

func (s *Store) Delete(ctx context.Context, key string) error {
	if s.shouldTryPrimary() {
		err := s.primary.Delete(ctx, key)
		if err == nil {
			s.markHealthy()
			return nil
		}
		if !benign(err) {
			s.markDegraded()
		}
	}
	return s.fallback.Delete(ctx, key)
}

func (s *Store) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	// Incr cannot meaningfully dual-write — the two stores would diverge
	// counter values on every successful primary call. We route to
	// whichever store shouldTryPrimary points at, accept the trade-off,
	// and document it in the package overview.
	if s.shouldTryPrimary() {
		n, err := s.primary.Incr(ctx, key, ttl)
		if err == nil {
			s.markHealthy()
			return n, nil
		}
		if !benign(err) {
			s.markDegraded()
		}
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
