//go:build integration

// Run with: REDIS_ADDR=localhost:6379 go test -tags=integration ./pkg/store/redis/...
//
// Skips silently if REDIS_ADDR is not set, so CI and ordinary `go test`
// runs are unaffected. The default miniredis-based suite covers the same
// surface; this file exists to confirm behaviour against a real Redis
// server (or any Redis-protocol-compatible engine such as Dragonfly,
// Valkey, or KeyDB) before tagging a release.
package redis

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/Supawitk/wicket/pkg/store"
)

func newIntegrationStore(t *testing.T) *Store {
	t.Helper()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		t.Skip("REDIS_ADDR not set; skipping real-Redis integration test")
	}
	c := goredis.NewClient(&goredis.Options{Addr: addr})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		t.Skipf("redis at %s not reachable: %v", addr, err)
	}
	t.Cleanup(func() {
		// Best-effort cleanup of keys this test wrote.
		_ = c.FlushDB(context.Background()).Err()
		_ = c.Close()
	})
	return FromClient(c)
}

func TestIntegrationSetGetDelete(t *testing.T) {
	s := newIntegrationStore(t)
	ctx := context.Background()

	if err := s.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get(ctx, "k")
	if err != nil || string(got) != "v" {
		t.Fatalf("Get: %v %q", err, got)
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "k"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after Delete got %v want ErrNotFound", err)
	}
}

func TestIntegrationSetNXExists(t *testing.T) {
	s := newIntegrationStore(t)
	ctx := context.Background()

	if err := s.SetNX(ctx, "nx", []byte("1"), time.Minute); err != nil {
		t.Fatalf("first SetNX: %v", err)
	}
	if err := s.SetNX(ctx, "nx", []byte("2"), time.Minute); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second SetNX got %v want ErrExists", err)
	}
}

func TestIntegrationIncr(t *testing.T) {
	s := newIntegrationStore(t)
	ctx := context.Background()

	n, err := s.Incr(ctx, "ctr", time.Minute)
	if err != nil || n != 1 {
		t.Fatalf("first Incr: n=%d err=%v", n, err)
	}
	n, err = s.Incr(ctx, "ctr", time.Minute)
	if err != nil || n != 2 {
		t.Fatalf("second Incr: n=%d err=%v", n, err)
	}
}

func TestIntegrationTTLExpiry(t *testing.T) {
	s := newIntegrationStore(t)
	ctx := context.Background()

	if err := s.Set(ctx, "ttl", []byte("v"), 50*time.Millisecond); err != nil {
		t.Fatalf("Set: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if _, err := s.Get(ctx, "ttl"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after TTL got %v want ErrNotFound", err)
	}
}
