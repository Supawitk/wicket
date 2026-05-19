package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigMinimal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "wicket.yml")
	if err := os.WriteFile(p, []byte("upstream: http://localhost:3000\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	c, err := loadConfig(p)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.Upstream != "http://localhost:3000" {
		t.Fatalf("upstream %q", c.Upstream)
	}
}

func TestLoadConfigRequiresUpstream(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "wicket.yml")
	_ = os.WriteFile(p, []byte("listen: :8080\n"), 0o644)
	if _, err := loadConfig(p); err == nil {
		t.Fatal("expected error for missing upstream")
	}
}

func TestLoadConfigRejectsBadUpstream(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "wicket.yml")
	_ = os.WriteFile(p, []byte("upstream: ftp://nope\n"), 0o644)
	if _, err := loadConfig(p); err == nil {
		t.Fatal("expected error for non-http upstream")
	}
}

func TestBuildStaticAllSections(t *testing.T) {
	c := &config{Upstream: "http://x"}
	c.PoW.Enabled = true
	c.Queue.Type = "vrf"
	c.Metrics.Enabled = false

	s, err := buildStatic(c)
	if err != nil {
		t.Fatalf("buildStatic: %v", err)
	}
	if s.chal == nil {
		t.Fatal("nil challenger")
	}
	if s.q == nil {
		t.Fatal("nil queue")
	}
}

func TestBuildStaticVRFAcceptsNoSeed(t *testing.T) {
	c := &config{Upstream: "http://x"}
	c.Queue.Type = "vrf" // no seed -> Ed25519 mode
	s, err := buildStatic(c)
	if err != nil {
		t.Fatalf("buildStatic: %v", err)
	}
	if s.q == nil {
		t.Fatal("nil queue")
	}
}

func TestBuildStaticUnknownQueueType(t *testing.T) {
	c := &config{Upstream: "http://x"}
	c.Queue.Type = "magic"
	if _, err := buildStatic(c); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildStaticFifoQueue(t *testing.T) {
	c := &config{Upstream: "http://x"}
	c.Queue.Type = "fifo"
	s, err := buildStatic(c)
	if err != nil {
		t.Fatalf("buildStatic: %v", err)
	}
	if s.q == nil {
		t.Fatal("nil queue")
	}
}

func TestBuildStaticECVRFQueue(t *testing.T) {
	c := &config{Upstream: "http://x"}
	c.Queue.Type = "ecvrf"
	s, err := buildStatic(c)
	if err != nil {
		t.Fatalf("buildStatic: %v", err)
	}
	if s.q == nil {
		t.Fatal("nil queue")
	}
}

func TestBuildStaticArgon2PoW(t *testing.T) {
	c := &config{Upstream: "http://x"}
	c.PoW.Enabled = true
	c.PoW.Algorithm = "argon2id"
	c.PoW.Argon2Memory = 4096
	s, err := buildStatic(c)
	if err != nil {
		t.Fatalf("buildStatic: %v", err)
	}
	if s.chal == nil {
		t.Fatal("nil challenger")
	}
}

func TestBuildStaticUnknownPowAlgo(t *testing.T) {
	c := &config{Upstream: "http://x"}
	c.PoW.Enabled = true
	c.PoW.Algorithm = "scrypt"
	if _, err := buildStatic(c); err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildHandlerComposes(t *testing.T) {
	c := &config{Upstream: "http://x"}
	c.RateLimit.RPS = 10
	c.CircuitBreaker.FailureRatio = 0.5
	c.CircuitBreaker.MinSamples = 5
	s, err := buildStatic(c)
	if err != nil {
		t.Fatalf("buildStatic: %v", err)
	}
	h, err := buildHandler(c, s)
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	if h == nil {
		t.Fatal("nil handler")
	}
}

// TestHotReloadPreservesLimiter is the regression test for the rate-limit
// reset on hot reload. Two buildHandler calls with the same rate_limit
// config must reuse the same *TokenBucket — otherwise an attacker can
// trigger an unrelated config edit during a flood and get a fresh burst
// quota every time.
func TestHotReloadPreservesLimiter(t *testing.T) {
	c := &config{Upstream: "http://x"}
	c.RateLimit.RPS = 10
	s, err := buildStatic(c)
	if err != nil {
		t.Fatalf("buildStatic: %v", err)
	}
	if _, err := buildHandler(c, s); err != nil {
		t.Fatalf("buildHandler 1: %v", err)
	}
	first := s.limiter
	if first == nil {
		t.Fatal("limiter not cached after first build")
	}

	// Simulate a hot reload that doesn't touch rate_limit.
	c2 := *c
	if _, err := buildHandler(&c2, s); err != nil {
		t.Fatalf("buildHandler 2: %v", err)
	}
	if s.limiter != first {
		t.Fatal("limiter rebuilt despite unchanged rate_limit config")
	}

	// Now flip an RPS field — must rebuild.
	c3 := *c
	c3.RateLimit.RPS = 20
	if _, err := buildHandler(&c3, s); err != nil {
		t.Fatalf("buildHandler 3: %v", err)
	}
	if s.limiter == first {
		t.Fatal("limiter not rebuilt despite rate_limit config change")
	}
}

// TestStoreBackendRedisRequiresAddr guards the sidecar against a config
// that asks for the Redis backend but omits the address — previously
// the build would silently fall back to in-memory.
func TestStoreBackendRedisRequiresAddr(t *testing.T) {
	c := &config{Upstream: "http://x"}
	c.Store.Backend = "redis"
	if _, err := buildStatic(c); err == nil {
		t.Fatal("expected error for redis backend with empty addr")
	}
}

func TestStoreBackendUnknown(t *testing.T) {
	c := &config{Upstream: "http://x"}
	c.Store.Backend = "etcd"
	if _, err := buildStatic(c); err == nil {
		t.Fatal("expected error for unknown store backend")
	}
}

func TestStaticDiff(t *testing.T) {
	a := &config{Upstream: "http://a", Listen: ":8080"}
	b := &config{Upstream: "http://b", Listen: ":8080"}
	if d := staticDiff(a, b); d != "upstream" {
		t.Fatalf("got %q want upstream", d)
	}
	if !changedStatic(a, b) {
		t.Fatal("changedStatic should be true")
	}
	c := &config{Upstream: "http://a", Listen: ":8080"}
	if changedStatic(a, c) {
		t.Fatal("changedStatic should be false")
	}
}
