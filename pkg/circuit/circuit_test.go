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
