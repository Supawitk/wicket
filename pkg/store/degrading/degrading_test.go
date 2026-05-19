package degrading

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Supawitk/wicket/pkg/store"
	"github.com/Supawitk/wicket/pkg/store/memory"
)

// flakyStore is a memory store that returns an injected error for a window.
type flakyStore struct {
	inner *memory.Store
	fail  atomic.Bool
}

func newFlaky() *flakyStore { return &flakyStore{inner: memory.New()} }

func (f *flakyStore) shouldFail() error {
	if f.fail.Load() {
		return errors.New("boom")
	}
	return nil
}

func (f *flakyStore) Get(ctx context.Context, k string) ([]byte, error) {
	if err := f.shouldFail(); err != nil {
		return nil, err
	}
	return f.inner.Get(ctx, k)
}
func (f *flakyStore) Set(ctx context.Context, k string, v []byte, ttl time.Duration) error {
	if err := f.shouldFail(); err != nil {
		return err
	}
	return f.inner.Set(ctx, k, v, ttl)
}
func (f *flakyStore) SetNX(ctx context.Context, k string, v []byte, ttl time.Duration) error {
	if err := f.shouldFail(); err != nil {
		return err
	}
	return f.inner.SetNX(ctx, k, v, ttl)
}
func (f *flakyStore) Delete(ctx context.Context, k string) error {
	if err := f.shouldFail(); err != nil {
		return err
	}
	return f.inner.Delete(ctx, k)
}
func (f *flakyStore) Incr(ctx context.Context, k string, ttl time.Duration) (int64, error) {
	if err := f.shouldFail(); err != nil {
		return 0, err
	}
	return f.inner.Incr(ctx, k, ttl)
}
func (f *flakyStore) Close() error { return f.inner.Close() }

func TestPassThroughWhenHealthy(t *testing.T) {
	primary := newFlaky()
	fallback := memory.New()
	t.Cleanup(func() { _ = fallback.Close() })
	s := New(primary, fallback, Config{})

	ctx := context.Background()
	if err := s.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get(ctx, "k")
	if err != nil || string(got) != "v" {
		t.Fatalf("Get: %v %q", err, got)
	}
	if s.Degraded() {
		t.Fatal("Degraded() true with healthy primary")
	}
	// Fallback should not have the value because primary handled it.
	if _, err := fallback.Get(ctx, "k"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("fallback should not see write: %v", err)
	}
}

func TestErrorFlipsToFallback(t *testing.T) {
	primary := newFlaky()
	fallback := memory.New()
	t.Cleanup(func() { _ = fallback.Close() })
	now := time.Unix(0, 0)
	s := New(primary, fallback, Config{ProbeEvery: time.Hour, Now: func() time.Time { return now }})

	ctx := context.Background()
	primary.fail.Store(true)
	if err := s.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatalf("Set should succeed via fallback: %v", err)
	}
	if !s.Degraded() {
		t.Fatal("Degraded() false after primary error")
	}

	got, err := s.Get(ctx, "k")
	if err != nil || string(got) != "v" {
		t.Fatalf("subsequent Get on fallback failed: %v %q", err, got)
	}
}

func TestRecoversAfterProbe(t *testing.T) {
	primary := newFlaky()
	fallback := memory.New()
	t.Cleanup(func() { _ = fallback.Close() })
	now := time.Unix(0, 0)
	s := New(primary, fallback, Config{ProbeEvery: 5 * time.Second, Now: func() time.Time { return now }})

	ctx := context.Background()
	primary.fail.Store(true)
	_ = s.Set(ctx, "k", []byte("v"), 0)
	if !s.Degraded() {
		t.Fatal("should be degraded")
	}

	primary.fail.Store(false)
	now = now.Add(6 * time.Second)
	if err := s.Set(ctx, "k2", []byte("v2"), 0); err != nil {
		t.Fatalf("Set after recovery: %v", err)
	}
	if s.Degraded() {
		t.Fatal("Degraded() true after successful primary probe")
	}
	// k2 should be in primary now
	if _, err := primary.Get(ctx, "k2"); err != nil {
		t.Fatalf("primary missing k2: %v", err)
	}
}

func TestNotFoundDoesNotTrip(t *testing.T) {
	primary := newFlaky()
	fallback := memory.New()
	t.Cleanup(func() { _ = fallback.Close() })
	s := New(primary, fallback, Config{})

	_, err := s.Get(context.Background(), "missing")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v want ErrNotFound", err)
	}
	if s.Degraded() {
		t.Fatal("ErrNotFound tripped degraded mode")
	}
}

func TestExistsDoesNotTrip(t *testing.T) {
	primary := newFlaky()
	fallback := memory.New()
	t.Cleanup(func() { _ = fallback.Close() })
	s := New(primary, fallback, Config{})

	ctx := context.Background()
	_ = s.SetNX(ctx, "k", []byte("v"), 0)
	err := s.SetNX(ctx, "k", []byte("v"), 0)
	if !errors.Is(err, store.ErrExists) {
		t.Fatalf("got %v want ErrExists", err)
	}
	if s.Degraded() {
		t.Fatal("ErrExists tripped degraded mode")
	}
}

func TestIncrFallbackWorks(t *testing.T) {
	primary := newFlaky()
	fallback := memory.New()
	t.Cleanup(func() { _ = fallback.Close() })
	s := New(primary, fallback, Config{ProbeEvery: time.Hour, Now: func() time.Time { return time.Unix(0, 0) }})

	primary.fail.Store(true)
	n, err := s.Incr(context.Background(), "c", 0)
	if err != nil || n != 1 {
		t.Fatalf("Incr fallback: n=%d err=%v", n, err)
	}
}

func TestDeleteFallbackWorks(t *testing.T) {
	primary := newFlaky()
	fallback := memory.New()
	t.Cleanup(func() { _ = fallback.Close() })
	s := New(primary, fallback, Config{ProbeEvery: time.Hour, Now: func() time.Time { return time.Unix(0, 0) }})

	ctx := context.Background()
	primary.fail.Store(true)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}
