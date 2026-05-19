package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Supawitk/wicket/pkg/store"
)

func TestSetGet(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })

	ctx := context.Background()
	if err := s.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "v" {
		t.Fatalf("got %q want %q", got, "v")
	}
}

func TestGetMissing(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.Get(context.Background(), "missing")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v want ErrNotFound", err)
	}
}

func TestTTLExpiry(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	now := time.Unix(0, 0)
	s.now = func() time.Time { return now }

	ctx := context.Background()
	if err := s.Set(ctx, "k", []byte("v"), 10*time.Second); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if _, err := s.Get(ctx, "k"); err != nil {
		t.Fatalf("Get before expiry: %v", err)
	}

	now = now.Add(11 * time.Second)
	if _, err := s.Get(ctx, "k"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after expiry got %v want ErrNotFound", err)
	}
}

func TestSetNX(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })

	ctx := context.Background()
	if err := s.SetNX(ctx, "k", []byte("first"), 0); err != nil {
		t.Fatalf("SetNX first: %v", err)
	}
	if err := s.SetNX(ctx, "k", []byte("second"), 0); !errors.Is(err, store.ErrExists) {
		t.Fatalf("SetNX second: got %v want ErrExists", err)
	}
	got, _ := s.Get(ctx, "k")
	if string(got) != "first" {
		t.Fatalf("value overwritten: got %q want %q", got, "first")
	}
}

func TestSetNXAfterExpiry(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	now := time.Unix(0, 0)
	s.now = func() time.Time { return now }

	ctx := context.Background()
	_ = s.SetNX(ctx, "k", []byte("first"), time.Second)
	now = now.Add(2 * time.Second)
	if err := s.SetNX(ctx, "k", []byte("second"), 0); err != nil {
		t.Fatalf("SetNX after expiry: %v", err)
	}
	got, _ := s.Get(ctx, "k")
	if string(got) != "second" {
		t.Fatalf("got %q want %q", got, "second")
	}
}

func TestDelete(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	_ = s.Set(ctx, "k", []byte("v"), 0)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "k"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v want ErrNotFound", err)
	}
}

func TestIncr(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	for i := int64(1); i <= 5; i++ {
		n, err := s.Incr(ctx, "c", 0)
		if err != nil {
			t.Fatalf("Incr: %v", err)
		}
		if n != i {
			t.Fatalf("Incr at step %d got %d", i, n)
		}
	}
}

func TestIncrTTL(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	now := time.Unix(0, 0)
	s.now = func() time.Time { return now }

	ctx := context.Background()
	_, _ = s.Incr(ctx, "c", time.Second)
	_, _ = s.Incr(ctx, "c", time.Second)
	now = now.Add(2 * time.Second)
	n, _ := s.Incr(ctx, "c", time.Second)
	if n != 1 {
		t.Fatalf("Incr after expiry got %d want 1", n)
	}
}

func TestConcurrentIncr(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	const N = 100
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, _ = s.Incr(ctx, "c", 0)
		}()
	}
	wg.Wait()

	v, err := s.Get(ctx, "c")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(v) != 8 {
		t.Fatalf("counter encoding wrong length: %d", len(v))
	}
}

func TestGetReturnsCopy(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	_ = s.Set(ctx, "k", []byte("hello"), 0)
	got, _ := s.Get(ctx, "k")
	got[0] = 'X'
	again, _ := s.Get(ctx, "k")
	if string(again) != "hello" {
		t.Fatalf("internal state mutated: %q", again)
	}
}
