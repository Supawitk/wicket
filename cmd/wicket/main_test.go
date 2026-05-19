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
