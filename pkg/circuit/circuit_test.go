package circuit

import (
	"errors"
	"testing"
	"time"
)

func newTestBreaker() (*Breaker, *time.Time) {
	now := time.Unix(0, 0)
	cfg := DefaultConfig()
	cfg.MinSamples = 4
	cfg.FailureRatio = 0.5
	cfg.Cooldown = 10 * time.Second
	cfg.HalfOpenMax = 2
	cfg.Now = func() time.Time { return now }
	return New(cfg), &now
}

func TestClosedAllows(t *testing.T) {
	b, _ := newTestBreaker()
	if err := b.Allow(); err != nil {
		t.Fatalf("Allow: %v", err)
	}
}

func TestTripsOnFailureRatio(t *testing.T) {
	b, _ := newTestBreaker()
	// 2 success + 2 failure = 50% ratio at 4 samples → trip.
	for i := 0; i < 2; i++ {
		_ = b.Allow()
		b.RecordSuccess()
	}
	for i := 0; i < 2; i++ {
		_ = b.Allow()
		b.RecordFailure()
	}
	if b.State() != StateOpen {
		t.Fatalf("state = %v want open", b.State())
	}
	if err := b.Allow(); !errors.Is(err, ErrOpen) {
		t.Fatalf("got %v want ErrOpen", err)
	}
}

func TestDoesNotTripBelowMinSamples(t *testing.T) {
	b, _ := newTestBreaker()
	for i := 0; i < 3; i++ {
		_ = b.Allow()
		b.RecordFailure()
	}
	if b.State() != StateClosed {
		t.Fatalf("state = %v want closed (only 3 samples)", b.State())
	}
}

func TestHalfOpenAfterCooldown(t *testing.T) {
	b, now := newTestBreaker()
	for i := 0; i < 4; i++ {
		_ = b.Allow()
		b.RecordFailure()
	}
	if b.State() != StateOpen {
		t.Fatalf("setup: state %v want open", b.State())
	}

	*now = now.Add(11 * time.Second)
	if err := b.Allow(); err != nil {
		t.Fatalf("Allow after cooldown: %v", err)
	}
	if b.State() != StateHalfOpen {
		t.Fatalf("state = %v want half-open", b.State())
	}
}

func TestHalfOpenSuccessRecovers(t *testing.T) {
	b, now := newTestBreaker()
	for i := 0; i < 4; i++ {
		_ = b.Allow()
		b.RecordFailure()
	}
	*now = now.Add(11 * time.Second)
	for i := 0; i < 2; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("probe %d denied: %v", i, err)
		}
		b.RecordSuccess()
	}
	if b.State() != StateClosed {
		t.Fatalf("state = %v want closed", b.State())
	}
}

func TestHalfOpenFailureReopens(t *testing.T) {
	b, now := newTestBreaker()
	for i := 0; i < 4; i++ {
		_ = b.Allow()
		b.RecordFailure()
	}
	*now = now.Add(11 * time.Second)
	_ = b.Allow()
	b.RecordFailure()
	if b.State() != StateOpen {
		t.Fatalf("state = %v want open", b.State())
	}
}

// TestSlidingWindowDecaysOldSuccesses is the regression test for the
// cumulative-counter bug: a long-running service accumulates successes
// that drown out a real failure spike under a cumulative ratio. With a
// rolling window, the old successes age out and the burst trips.
func TestSlidingWindowDecaysOldSuccesses(t *testing.T) {
	now := time.Unix(0, 0)
	cfg := Config{
		FailureRatio:  0.5,
		MinSamples:    4,
		Cooldown:      time.Minute,
		HalfOpenMax:   2,
		Window:        10 * time.Second,
		WindowBuckets: 10,
		Now:           func() time.Time { return now },
	}
	b := New(cfg)

	for i := 0; i < 1_000_000; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("setup denied at i=%d: %v", i, err)
		}
		b.RecordSuccess()
	}
	if b.State() != StateClosed {
		t.Fatalf("after 1M successes state = %v want closed", b.State())
	}

	// Advance past the window so every accumulated success ages out.
	now = now.Add(11 * time.Second)

	// A small all-fail burst must now trip the breaker. The bug would
	// keep total ≈ 1M, ratio ≈ 4/1M ≈ 0.000004, far below threshold.
	for i := 0; i < 4; i++ {
		_ = b.Allow()
		b.RecordFailure()
	}
	if b.State() != StateOpen {
		t.Fatalf("state = %v want open (sliding window must decay old successes)", b.State())
	}
}

// TestRollingWindowPartialDecay checks that samples expire bucket-by-bucket
// rather than all at once. With cumulative counters, 10 successes + 5
// failures would give ratio 0.33 (no trip). With a rolling window, the
// oldest 6 successes age out, leaving 4 successes + 5 failures → ratio
// 0.56, which crosses the 0.5 threshold.
func TestRollingWindowPartialDecay(t *testing.T) {
	now := time.Unix(0, 0)
	cfg := Config{
		FailureRatio:  0.5,
		MinSamples:    8,
		Cooldown:      time.Minute,
		HalfOpenMax:   2,
		Window:        10 * time.Second,
		WindowBuckets: 10,
		Now:           func() time.Time { return now },
	}
	b := New(cfg)

	// Record one success per second for 10 seconds — one per bucket.
	for i := 0; i < 10; i++ {
		b.RecordSuccess()
		now = now.Add(time.Second)
	}
	// Advance another 5s. The 6 oldest buckets (5 we cross + the one
	// the failures land in) get cleared on the first failure's advance,
	// leaving the 4 most recent successes intact.
	now = now.Add(5 * time.Second)

	for i := 0; i < 5; i++ {
		b.RecordFailure()
	}
	if b.State() != StateOpen {
		t.Fatalf("state = %v want open (partial decay should let ratio reach threshold)", b.State())
	}
}

func TestHalfOpenCapsProbes(t *testing.T) {
	b, now := newTestBreaker()
	for i := 0; i < 4; i++ {
		_ = b.Allow()
		b.RecordFailure()
	}
	*now = now.Add(11 * time.Second)
	for i := 0; i < 2; i++ {
		if err := b.Allow(); err != nil {
			t.Fatalf("probe %d: %v", i, err)
		}
	}
	if err := b.Allow(); !errors.Is(err, ErrOpen) {
		t.Fatalf("3rd probe got %v want ErrOpen", err)
	}
}
