package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/Supawitk/wicket/pkg/store"
)

func newTestStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	c := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return FromClient(c), mr
}

func TestSetGet(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "v" {
		t.Fatalf("got %q", got)
	}
}

func TestGetMissing(t *testing.T) {
	s, _ := newTestStore(t)
	_, err := s.Get(context.Background(), "missing")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v want ErrNotFound", err)
	}
}

func TestTTLExpiry(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	if err := s.Set(ctx, "k", []byte("v"), 10*time.Second); err != nil {
		t.Fatalf("Set: %v", err)
	}
	mr.FastForward(11 * time.Second)
	if _, err := s.Get(ctx, "k"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after expiry got %v", err)
	}
}

func TestSetNX(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.SetNX(ctx, "k", []byte("first"), 0); err != nil {
		t.Fatalf("first SetNX: %v", err)
	}
	if err := s.SetNX(ctx, "k", []byte("second"), 0); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second SetNX: got %v want ErrExists", err)
	}
}

func TestDelete(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	_ = s.Set(ctx, "k", []byte("v"), 0)
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "k"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestIncr(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for i := int64(1); i <= 4; i++ {
		n, err := s.Incr(ctx, "c", 0)
		if err != nil {
			t.Fatalf("Incr: %v", err)
		}
		if n != i {
			t.Fatalf("Incr i=%d got %d", i, n)
		}
	}
}

func TestIncrTTLAppliesOnce(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	_, _ = s.Incr(ctx, "c", 10*time.Second)
	_, _ = s.Incr(ctx, "c", 10*time.Second)
	mr.FastForward(11 * time.Second)
	n, _ := s.Incr(ctx, "c", 10*time.Second)
	if n != 1 {
		t.Fatalf("after expiry got %d want 1", n)
	}
}

func TestClose(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
