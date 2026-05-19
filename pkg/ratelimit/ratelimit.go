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

// Config configures a Limiter. Rate is tokens-per-second sustained;
// Burst is the maximum tokens accumulated.
type Config struct {
	Rate  float64
	Burst float64
	Now   func() time.Time
}

type TokenBucket struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	now     func() time.Time
	buckets map[string]*bucket
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
	return &TokenBucket{
		rate:    rate,
		burst:   burst,
		now:     now,
		buckets: make(map[string]*bucket),
	}
}

func (t *TokenBucket) Allow(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
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

// Size reports the number of distinct keys tracked. Useful for tests and
// for monitoring fan-out.
func (t *TokenBucket) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.buckets)
}
