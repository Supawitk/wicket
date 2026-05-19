// Package memory provides an in-memory store backend. It is the default
// when no external store is configured, and is the backend used by every
// unit test in the project.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/Supawitk/wicket/pkg/store"
)

type entry struct {
	value     []byte
	expiresAt time.Time
}

func (e entry) expired(now time.Time) bool {
	return !e.expiresAt.IsZero() && now.After(e.expiresAt)
}

type Store struct {
	mu     sync.Mutex
	data   map[string]entry
	now    func() time.Time
	stopCh chan struct{}
}

type Option func(*Store)

// WithClock injects a deterministic clock. Intended for tests.
func WithClock(now func() time.Time) Option {
	return func(s *Store) { s.now = now }
}

func New(opts ...Option) *Store {
	s := &Store{
		data:   make(map[string]entry),
		now:    time.Now,
		stopCh: make(chan struct{}),
	}
	for _, o := range opts {
		o(s)
	}
	go s.janitor(time.Minute)
	return s
}

func (s *Store) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if e.expired(s.now()) {
		delete(s.data, key)
		return nil, store.ErrNotFound
	}
	out := make([]byte, len(e.value))
	copy(out, e.value)
	return out, nil
}

func (s *Store) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	buf := make([]byte, len(value))
	copy(buf, value)
	s.data[key] = entry{value: buf, expiresAt: s.expiry(ttl)}
	return nil
}

func (s *Store) SetNX(_ context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.data[key]; ok && !e.expired(s.now()) {
		return store.ErrExists
	}
	buf := make([]byte, len(value))
	copy(buf, value)
	s.data[key] = entry{value: buf, expiresAt: s.expiry(ttl)}
	return nil
}

func (s *Store) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *Store) Incr(_ context.Context, key string, ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[key]
	var n int64
	if ok && !e.expired(s.now()) {
		// little-endian int64 in 8 bytes
		if len(e.value) == 8 {
			n = int64(e.value[0]) |
				int64(e.value[1])<<8 |
				int64(e.value[2])<<16 |
				int64(e.value[3])<<24 |
				int64(e.value[4])<<32 |
				int64(e.value[5])<<40 |
				int64(e.value[6])<<48 |
				int64(e.value[7])<<56
		}
	}
	n++
	buf := make([]byte, 8)
	u := uint64(n)
	buf[0] = byte(u)
	buf[1] = byte(u >> 8)
	buf[2] = byte(u >> 16)
	buf[3] = byte(u >> 24)
	buf[4] = byte(u >> 32)
	buf[5] = byte(u >> 40)
	buf[6] = byte(u >> 48)
	buf[7] = byte(u >> 56)
	s.data[key] = entry{value: buf, expiresAt: s.expiry(ttl)}
	return n, nil
}

func (s *Store) Close() error {
	close(s.stopCh)
	return nil
}

func (s *Store) expiry(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return s.now().Add(ttl)
}

func (s *Store) janitor(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			s.sweep()
		}
	}
}

func (s *Store) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, e := range s.data {
		if e.expired(now) {
			delete(s.data, k)
		}
	}
}
