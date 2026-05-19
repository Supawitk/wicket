package ratelimit

import (
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
