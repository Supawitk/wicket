package ratelimit

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBurstAllowed(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Config{Rate: 1, Burst: 5, Now: func() time.Time { return now }})
	for i := 0; i < 5; i++ {
		if !l.Allow("k") {
			t.Fatalf("denied at i=%d, expected burst of 5", i)
		}
	}
	if l.Allow("k") {
		t.Fatal("allowed beyond burst")
	}
}

func TestRefill(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Config{Rate: 2, Burst: 2, Now: func() time.Time { return now }})
	if !l.Allow("k") || !l.Allow("k") {
		t.Fatal("initial burst denied")
	}
	if l.Allow("k") {
		t.Fatal("third allowed without refill")
	}
	now = now.Add(time.Second) // 2 tokens refill
	if !l.Allow("k") || !l.Allow("k") {
		t.Fatal("after refill denied")
	}
	if l.Allow("k") {
		t.Fatal("over-refill")
	}
}

func TestKeysIndependent(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Config{Rate: 1, Burst: 1, Now: func() time.Time { return now }})
	if !l.Allow("a") {
		t.Fatal("a denied")
	}
	if !l.Allow("b") {
		t.Fatal("b denied")
	}
	if l.Allow("a") {
		t.Fatal("a allowed twice")
	}
	if l.Allow("b") {
		t.Fatal("b allowed twice")
	}
}

func TestBurstCap(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Config{Rate: 10, Burst: 3, Now: func() time.Time { return now }})
	_ = l.Allow("k") // consume 1, leaving 2
	now = now.Add(10 * time.Second)
	allowed := 0
	for i := 0; i < 10; i++ {
		if l.Allow("k") {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("burst not capped: %d", allowed)
	}
}

func TestSize(t *testing.T) {
	l := New(Config{Rate: 1, Burst: 1})
	l.Allow("a")
	l.Allow("b")
	l.Allow("c")
	if got := l.Size(); got != 3 {
		t.Fatalf("Size = %d want 3", got)
	}
}

// TestEvictsIdleBuckets is the regression test for the unbounded-map
// memory leak: without eviction, a service hit by rotating IPv6 / spoofed
// IPs accumulates buckets forever and OOMs. After IdleTTL elapses, idle
// buckets must be removed; active ones must be preserved.
func TestEvictsIdleBuckets(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Config{
		Rate:          1,
		Burst:         1,
		IdleTTL:       time.Minute,
		SweepInterval: 30 * time.Second,
		Now:           func() time.Time { return now },
	})

	// 1000 distinct keys touched once.
	for i := 0; i < 1000; i++ {
		l.Allow(fmt.Sprintf("k-%d", i))
	}
	if got := l.Size(); got != 1000 {
		t.Fatalf("after 1000 keys Size=%d want 1000", got)
	}

	// Advance past IdleTTL, then trigger a sweep with one more call.
	now = now.Add(2 * time.Minute)
	l.Allow("trigger")

	if got := l.Size(); got != 1 {
		t.Fatalf("after eviction Size=%d want 1 (only the trigger key)", got)
	}
}

// TestEvictionPreservesActiveKeys ensures the sweep is selective: keys
// that were touched recently must survive even when stale neighbours get
// evicted.
func TestEvictionPreservesActiveKeys(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Config{
		Rate:          1,
		Burst:         1,
		IdleTTL:       time.Minute,
		SweepInterval: 30 * time.Second,
		Now:           func() time.Time { return now },
	})

	l.Allow("stale-a")
	l.Allow("stale-b")
	now = now.Add(30 * time.Second)
	l.Allow("fresh-a") // halfway through IdleTTL
	now = now.Add(31 * time.Second)
	// stale-* are now older than IdleTTL; fresh-a is not. Sweep fires.
	l.Allow("fresh-b")

	if got := l.Size(); got != 2 {
		t.Fatalf("Size=%d want 2 (fresh-a, fresh-b)", got)
	}
}

// TestMillionUniqueKeysEvict is the regression test for the
// rotating-IP / spoofed-IP memory exhaustion: after one million distinct
// keys touch the limiter once each and the IdleTTL elapses, the map must
// drop back to a near-empty steady state. The earlier failure mode was a
// 100MB resident set held permanently with no eviction path.
func TestMillionUniqueKeysEvict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1M-key sweep test in -short mode")
	}
	now := time.Unix(0, 0)
	l := New(Config{
		Rate:          1,
		Burst:         1,
		IdleTTL:       time.Minute,
		SweepInterval: 30 * time.Second,
		Now:           func() time.Time { return now },
	})

	const N = 1_000_000
	for i := 0; i < N; i++ {
		l.Allow(fmt.Sprintf("ip-%d", i))
	}
	if got := l.Size(); got != N {
		t.Fatalf("after %d keys Size=%d want %d", N, got, N)
	}

	now = now.Add(2 * time.Minute)
	l.Allow("trigger")
	if got := l.Size(); got != 1 {
		t.Fatalf("after sweep Size=%d want 1", got)
	}
}

// TestEvictionDisabled confirms IdleTTL<0 turns the sweep off entirely so
// callers with a bounded key set keep the previous (leak-but-fast) shape.
func TestEvictionDisabled(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(Config{
		Rate:    1,
		Burst:   1,
		IdleTTL: -1,
		Now:     func() time.Time { return now },
	})
	for i := 0; i < 100; i++ {
		l.Allow(fmt.Sprintf("k-%d", i))
	}
	now = now.Add(24 * time.Hour)
	l.Allow("trigger")
	if got := l.Size(); got != 101 {
		t.Fatalf("Size=%d want 101 (eviction disabled)", got)
	}
}

// TestConcurrentAllowSameKey hammers Allow on one key from many goroutines.
// With -race this catches any unsynchronised access to the shared bucket.
// The total allowed must equal the burst exactly: no double-grants, no
// lost tokens. The clock is frozen to remove refill from the equation.
func TestConcurrentAllowSameKey(t *testing.T) {
	const goroutines = 1000
	const burst = 100

	now := time.Unix(0, 0)
	l := New(Config{Rate: 1, Burst: burst, Now: func() time.Time { return now }})

	var allowed int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			if l.Allow("k") {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if allowed != burst {
		t.Fatalf("allowed=%d, want exactly %d (burst)", allowed, burst)
	}
}

// TestConcurrentAllowDistinctKeys exercises the per-key map under heavy
// parallel creation. Each goroutine uses its own key, so every Allow must
// succeed; the failure mode would be a map race or a lost bucket insert.
func TestConcurrentAllowDistinctKeys(t *testing.T) {
	const goroutines = 1000

	now := time.Unix(0, 0)
	l := New(Config{Rate: 1, Burst: 1, Now: func() time.Time { return now }})

	var allowed int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		key := fmt.Sprintf("k-%d", i)
		go func() {
			defer wg.Done()
			<-start
			if l.Allow(key) {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if allowed != goroutines {
		t.Fatalf("allowed=%d, want %d", allowed, goroutines)
	}
	if got := l.Size(); got != goroutines {
		t.Fatalf("Size=%d, want %d", got, goroutines)
	}
}
