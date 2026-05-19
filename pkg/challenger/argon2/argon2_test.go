package argon2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Supawitk/wicket/pkg/challenger"
	"github.com/Supawitk/wicket/pkg/store/memory"
)

// Test params: tiny memory + 1 zero byte so solve is ~milliseconds.
func testConfig() Config {
	c := DefaultConfig()
	c.BaseZeroBytes = 1
	c.MaxZeroBytes = 2
	c.Memory = 8 * 1024 // 8 MiB, far below real production
	c.KeyLen = 16
	return c
}

func newTestChallenger(t *testing.T) *Challenger {
	t.Helper()
	s := memory.New()
	t.Cleanup(func() { _ = s.Close() })
	return New(s, testConfig())
}

func TestIssueIsUnique(t *testing.T) {
	c := newTestChallenger(t)
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		ch, err := c.Issue(context.Background(), challenger.Hint{})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if seen[ch.ID] {
			t.Fatalf("duplicate %s", ch.ID)
		}
		seen[ch.ID] = true
	}
}

func TestVerifyAcceptsValidSolution(t *testing.T) {
	c := newTestChallenger(t)
	ctx := context.Background()
	ch, _ := c.Issue(ctx, challenger.Hint{})
	cfg := c.cfg
	nonce := Solve(ch.Payload, ch.Difficulty, cfg.Time, cfg.Memory, cfg.Threads, cfg.KeyLen)
	if err := c.Verify(ctx, challenger.Solution{ID: ch.ID, Nonce: nonce}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsWrongNonce(t *testing.T) {
	c := newTestChallenger(t)
	ctx := context.Background()
	ch, _ := c.Issue(ctx, challenger.Hint{})
	err := c.Verify(ctx, challenger.Solution{ID: ch.ID, Nonce: []byte{0, 0, 0, 0}})
	if !errors.Is(err, challenger.ErrInvalidSolution) {
		t.Fatalf("got %v want ErrInvalidSolution", err)
	}
}

func TestVerifyRejectsUnknownID(t *testing.T) {
	c := newTestChallenger(t)
	err := c.Verify(context.Background(), challenger.Solution{ID: "nope", Nonce: []byte{1}})
	if !errors.Is(err, challenger.ErrUnknownID) {
		t.Fatalf("got %v want ErrUnknownID", err)
	}
}

func TestVerifyConsumes(t *testing.T) {
	c := newTestChallenger(t)
	ctx := context.Background()
	ch, _ := c.Issue(ctx, challenger.Hint{})
	cfg := c.cfg
	nonce := Solve(ch.Payload, ch.Difficulty, cfg.Time, cfg.Memory, cfg.Threads, cfg.KeyLen)
	if err := c.Verify(ctx, challenger.Solution{ID: ch.ID, Nonce: nonce}); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := c.Verify(ctx, challenger.Solution{ID: ch.ID, Nonce: nonce}); !errors.Is(err, challenger.ErrUnknownID) {
		t.Fatalf("replay got %v", err)
	}
}

func TestExpiryRejected(t *testing.T) {
	now := time.Unix(0, 0)
	s := memory.New(memory.WithClock(func() time.Time { return now }))
	t.Cleanup(func() { _ = s.Close() })
	cfg := testConfig()
	cfg.TTL = 5 * time.Second
	cfg.Now = func() time.Time { return now }
	c := New(s, cfg)

	ctx := context.Background()
	ch, _ := c.Issue(ctx, challenger.Hint{})
	nonce := Solve(ch.Payload, ch.Difficulty, cfg.Time, cfg.Memory, cfg.Threads, cfg.KeyLen)
	now = now.Add(6 * time.Second)
	if err := c.Verify(ctx, challenger.Solution{ID: ch.ID, Nonce: nonce}); !errors.Is(err, challenger.ErrUnknownID) {
		t.Fatalf("got %v want ErrUnknownID", err)
	}
}

func TestZeroBytesScalesWithLoad(t *testing.T) {
	c := newTestChallenger(t)
	low := c.zeroBytesFor(challenger.Hint{Load: 0})
	high := c.zeroBytesFor(challenger.Hint{Load: 1})
	if high <= low {
		t.Fatalf("expected high > low, got low=%d high=%d", low, high)
	}
}

func TestParamsExposed(t *testing.T) {
	c := newTestChallenger(t)
	tt, mem, threads, keyLen := c.Params()
	if tt == 0 || mem == 0 || threads == 0 || keyLen == 0 {
		t.Fatalf("zero param: %d %d %d %d", tt, mem, threads, keyLen)
	}
}
