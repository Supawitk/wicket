// Package ratelimit provides token-bucket rate limiters keyed by an
// arbitrary string (typically client IP or identity).
package ratelimit

import (
	"sync"
	"time"
)

type Limiter interface {
	Allow(key string) bool
}

type bucket struct {
	tokens    float64
	updatedAt time.Time
}

// Config configures a Limiter.
//
//   - Rate is sustained tokens-per-second.
//   - Burst is the maximum tokens that can accumulate.
//   - IdleTTL evicts buckets whose last update is older than IdleTTL.
//     Zero (the default for the Config zero value) is treated as
//     defaultIdleTTL; pass a negative value to disable eviction.
//   - SweepInterval is the minimum time between eviction sweeps.
//     Defaults to IdleTTL/10 (capped at 1 minute).
type Config struct {
	Rate          float64
	Burst         float64
	IdleTTL       time.Duration
	SweepInterval time.Duration
	// MaxSweepBatch caps the number of map entries a single sweep may
	// visit while holding the limiter's lock. Zero (the default) leaves
	// the sweep unbounded — every Allow that crosses SweepInterval
	// scans the whole map. Set it (e.g. 10_000) under strict p99
	// budgets at multi-million-key fan-out, so one unlucky Allow can
	// never stall behind a 1M-entry sweep. Stale buckets just take a
	// few more sweep cycles to fully drain.
	MaxSweepBatch int
	Now           func() time.Time
}

const (
	defaultIdleTTL       = 10 * time.Minute
	defaultSweepInterval = time.Minute
)

type TokenBucket struct {
	mu            sync.Mutex
	rate          float64
	burst         float64
	now           func() time.Time
	buckets       map[string]*bucket
	idleTTL       time.Duration
	sweepInterval time.Duration
	lastSweep     time.Time
	maxSweepBatch int
}

func New(cfg Config) *TokenBucket {
	rate := cfg.Rate
	if rate <= 0 {
		rate = 1
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = rate
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	idleTTL := cfg.IdleTTL
	if idleTTL == 0 {
		idleTTL = defaultIdleTTL
	}
	sweepInterval := cfg.SweepInterval
	if sweepInterval <= 0 {
		sweepInterval = idleTTL / 10
		if sweepInterval > defaultSweepInterval {
			sweepInterval = defaultSweepInterval
		}
		if sweepInterval <= 0 {
			sweepInterval = defaultSweepInterval
		}
	}
	return &TokenBucket{
		rate:          rate,
		burst:         burst,
		now:           now,
		buckets:       make(map[string]*bucket),
		idleTTL:       idleTTL,
		sweepInterval: sweepInterval,
		lastSweep:     now(),
		maxSweepBatch: cfg.MaxSweepBatch,
	}
}

func (t *TokenBucket) Allow(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.maybeSweepLocked(now)
	b, ok := t.buckets[key]
	if !ok {
		b = &bucket{tokens: t.burst, updatedAt: now}
		t.buckets[key] = b
	}
	elapsed := now.Sub(b.updatedAt).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * t.rate
		if b.tokens > t.burst {
			b.tokens = t.burst
		}
		b.updatedAt = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// maybeSweepLocked evicts buckets idle longer than IdleTTL, but only when
// at least SweepInterval has elapsed since the previous sweep. Amortizes
// O(N) cleanup across many Allow calls so the steady-state cost stays
// low. When MaxSweepBatch > 0 the visit count is capped per call so the
// lock-hold time on a single Allow stays predictable even when the
// keyspace is in the millions.
func (t *TokenBucket) maybeSweepLocked(now time.Time) {
	if t.idleTTL < 0 {
		return
	}
	if now.Sub(t.lastSweep) < t.sweepInterval {
		return
	}
	cutoff := now.Add(-t.idleTTL)
	visited := 0
	for k, b := range t.buckets {
		if t.maxSweepBatch > 0 && visited >= t.maxSweepBatch {
			break
		}
		visited++
		if b.updatedAt.Before(cutoff) {
			delete(t.buckets, k)
		}
	}
	t.lastSweep = now
}

// Size reports the number of distinct keys tracked. Useful for tests and
// for monitoring fan-out.
func (t *TokenBucket) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.buckets)
}
