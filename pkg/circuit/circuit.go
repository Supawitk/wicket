// Package circuit implements a simple three-state circuit breaker
// (Closed → Open → Half-Open) suitable for wrapping calls to a flaky
// backend.
//
// A breaker that has tripped rejects calls until a Cooldown elapses, then
// admits a bounded number of probe calls. Success during the probe phase
// returns the breaker to Closed; any failure trips it back to Open.
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
	Now          func() time.Time
}

func DefaultConfig() Config {
	return Config{
		FailureRatio: 0.5,
		MinSamples:   20,
		Cooldown:     30 * time.Second,
		HalfOpenMax:  3,
		Now:          time.Now,
	}
}

type Breaker struct {
	cfg     Config
	mu      sync.Mutex
	state   State
	success int64
	failure int64
	openAt  time.Time
	probe   int64
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
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Breaker{cfg: cfg}
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
		b.success++
	case StateHalfOpen:
		b.success++
		if b.success >= b.cfg.HalfOpenMax {
			b.transitionLocked(StateClosed)
		}
	}
}

func (b *Breaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case StateClosed:
		b.failure++
		total := b.success + b.failure
		if total >= b.cfg.MinSamples {
			ratio := float64(b.failure) / float64(total)
			if ratio >= b.cfg.FailureRatio {
				b.transitionLocked(StateOpen)
			}
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

func (b *Breaker) transitionLocked(next State) {
	b.state = next
	b.success = 0
	b.failure = 0
	b.probe = 0
	if next == StateOpen {
		b.openAt = b.cfg.Now()
	}
}
