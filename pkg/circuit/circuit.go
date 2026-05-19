// Package circuit implements a three-state circuit breaker
// (Closed → Open → Half-Open) with a rolling time-window failure ratio.
//
// A breaker that has tripped rejects calls until a Cooldown elapses, then
// admits a bounded number of probe calls. Success during the probe phase
// returns the breaker to Closed; any failure trips it back to Open.
//
// The failure ratio is computed over the most recent Window of activity,
// not over the breaker's entire lifetime. Without this, a long-running
// service can accumulate so many successes that a sudden 100% failure
// spike never crosses the ratio threshold. Hystrix, sony-gobreaker, and
// resilience4j all use rolling windows for the same reason.
package circuit

import (
	"errors"
	"sync"
	"time"
)

var ErrOpen = errors.New("circuit: breaker is open")

type State int

const (
	StateClosed State = iota
	StateOpen
	StateHalfOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

type Config struct {
	FailureRatio float64
	MinSamples   int64
	Cooldown     time.Duration
	HalfOpenMax  int64

	// Window is the rolling time window over which success/failure
	// counts are tracked. Older samples decay out. Defaults to 10s.
	Window time.Duration
	// WindowBuckets is the number of buckets the window is divided
	// into. More buckets smooth out boundary effects at the cost of
	// memory. Defaults to 10.
	WindowBuckets int

	Now func() time.Time
}

func DefaultConfig() Config {
	return Config{
		FailureRatio:  0.5,
		MinSamples:    20,
		Cooldown:      30 * time.Second,
		HalfOpenMax:   3,
		Window:        10 * time.Second,
		WindowBuckets: 10,
		Now:           time.Now,
	}
}

type bucket struct {
	success int64
	failure int64
}

type Breaker struct {
	cfg Config
	mu  sync.Mutex

	state State

	// Rolling-window state, used only in StateClosed to compute the
	// failure ratio. Each bucket holds counts for one slice of the
	// window; the ring is rotated as time advances.
	buckets      []bucket
	bucketDur    time.Duration
	currentIdx   int
	currentStart time.Time

	// Half-open probe accounting. Kept separate from the window so
	// expiring buckets cannot reset probe progress.
	halfOpenSucc int64
	probe        int64
	openAt       time.Time
}

func New(cfg Config) *Breaker {
	if cfg.FailureRatio <= 0 || cfg.FailureRatio > 1 {
		cfg.FailureRatio = 0.5
	}
	if cfg.MinSamples <= 0 {
		cfg.MinSamples = 20
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 30 * time.Second
	}
	if cfg.HalfOpenMax <= 0 {
		cfg.HalfOpenMax = 3
	}
	if cfg.Window <= 0 {
		cfg.Window = 10 * time.Second
	}
	if cfg.WindowBuckets <= 0 {
		cfg.WindowBuckets = 10
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Breaker{
		cfg:          cfg,
		buckets:      make([]bucket, cfg.WindowBuckets),
		bucketDur:    cfg.Window / time.Duration(cfg.WindowBuckets),
		currentStart: cfg.Now(),
	}
}

// Allow returns nil if the call may proceed. After the call completes the
// caller MUST report the outcome with RecordSuccess or RecordFailure.
func (b *Breaker) Allow() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case StateClosed:
		return nil
	case StateOpen:
		if b.cfg.Now().Sub(b.openAt) < b.cfg.Cooldown {
			return ErrOpen
		}
		b.transitionLocked(StateHalfOpen)
		b.probe = 1
		return nil
	case StateHalfOpen:
		if b.probe >= b.cfg.HalfOpenMax {
			return ErrOpen
		}
		b.probe++
		return nil
	}
	return ErrOpen
}

func (b *Breaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case StateClosed:
		b.advanceLocked(b.cfg.Now())
		b.buckets[b.currentIdx].success++
	case StateHalfOpen:
		b.halfOpenSucc++
		if b.halfOpenSucc >= b.cfg.HalfOpenMax {
			b.transitionLocked(StateClosed)
		}
	}
}

func (b *Breaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case StateClosed:
		now := b.cfg.Now()
		b.advanceLocked(now)
		b.buckets[b.currentIdx].failure++
		failure, total := b.sumLocked()
		if total >= b.cfg.MinSamples && float64(failure)/float64(total) >= b.cfg.FailureRatio {
			b.transitionLocked(StateOpen)
		}
	case StateHalfOpen:
		b.transitionLocked(StateOpen)
	}
}

func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// advanceLocked rolls the ring forward so that buckets[currentIdx]
// represents the bucket containing now, zeroing any buckets we cross.
func (b *Breaker) advanceLocked(now time.Time) {
	elapsed := now.Sub(b.currentStart)
	if elapsed < b.bucketDur {
		return
	}
	steps := int(elapsed / b.bucketDur)
	if steps >= len(b.buckets) {
		// Entire window has elapsed since our last write; everything
		// stale, clear and restart at the current bucket boundary.
		for i := range b.buckets {
			b.buckets[i] = bucket{}
		}
		b.currentIdx = 0
		// Align currentStart to a bucket boundary anchored on now to
		// avoid drifting past the window length.
		b.currentStart = now
		return
	}
	for i := 0; i < steps; i++ {
		b.currentIdx = (b.currentIdx + 1) % len(b.buckets)
		b.buckets[b.currentIdx] = bucket{}
	}
	b.currentStart = b.currentStart.Add(time.Duration(steps) * b.bucketDur)
}

func (b *Breaker) sumLocked() (failure, total int64) {
	var success int64
	for _, bk := range b.buckets {
		success += bk.success
		failure += bk.failure
	}
	return failure, success + failure
}

func (b *Breaker) transitionLocked(next State) {
	b.state = next
	for i := range b.buckets {
		b.buckets[i] = bucket{}
	}
	b.currentIdx = 0
	b.currentStart = b.cfg.Now()
	b.halfOpenSucc = 0
	b.probe = 0
	if next == StateOpen {
		b.openAt = b.cfg.Now()
	}
}
