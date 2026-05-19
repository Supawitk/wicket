package pow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Supawitk/wicket/pkg/challenger"
	"github.com/Supawitk/wicket/pkg/store/memory"
)

const testDifficulty = 8 // low so tests are fast

func newTestChallenger(t *testing.T) (*Challenger, *memory.Store) {
	t.Helper()
	s := memory.New()
	t.Cleanup(func() { _ = s.Close() })
	cfg := DefaultConfig()
	cfg.BaseDifficulty = testDifficulty
	cfg.MaxDifficulty = testDifficulty + 4
	return New(s, cfg), s
}

func TestIssueProducesUniqueChallenges(t *testing.T) {
	c, _ := newTestChallenger(t)
	ctx := context.Background()
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		ch, err := c.Issue(ctx, challenger.Hint{})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if seen[ch.ID] {
			t.Fatalf("duplicate id %s", ch.ID)
		}
		seen[ch.ID] = true
	}
}

func TestVerifyAcceptsCorrectNonce(t *testing.T) {
	c, _ := newTestChallenger(t)
	ctx := context.Background()
	ch, err := c.Issue(ctx, challenger.Hint{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	nonce := Solve(ch.Payload, ch.Difficulty)
	if err := c.Verify(ctx, challenger.Solution{ID: ch.ID, Nonce: nonce}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsWrongNonce(t *testing.T) {
	c, _ := newTestChallenger(t)
	ctx := context.Background()
	ch, err := c.Issue(ctx, challenger.Hint{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	bad := []byte{0, 0, 0, 0}
	err = c.Verify(ctx, challenger.Solution{ID: ch.ID, Nonce: bad})
	if !errors.Is(err, challenger.ErrInvalidSolution) {
		t.Fatalf("got %v want ErrInvalidSolution", err)
	}
}

func TestVerifyRejectsUnknownID(t *testing.T) {
	c, _ := newTestChallenger(t)
	err := c.Verify(context.Background(), challenger.Solution{ID: "nope", Nonce: []byte{1}})
	if !errors.Is(err, challenger.ErrUnknownID) {
		t.Fatalf("got %v want ErrUnknownID", err)
	}
}

func TestVerifyConsumesChallenge(t *testing.T) {
	c, _ := newTestChallenger(t)
	ctx := context.Background()
	ch, _ := c.Issue(ctx, challenger.Hint{})
	nonce := Solve(ch.Payload, ch.Difficulty)
	if err := c.Verify(ctx, challenger.Solution{ID: ch.ID, Nonce: nonce}); err != nil {
		t.Fatalf("Verify first: %v", err)
	}
	err := c.Verify(ctx, challenger.Solution{ID: ch.ID, Nonce: nonce})
	if !errors.Is(err, challenger.ErrUnknownID) {
		t.Fatalf("replay got %v want ErrUnknownID", err)
	}
}

func TestExpiryRejected(t *testing.T) {
	now := time.Unix(0, 0)
	s := memory.New(memory.WithClock(func() time.Time { return now }))
	t.Cleanup(func() { _ = s.Close() })
	cfg := DefaultConfig()
	cfg.BaseDifficulty = testDifficulty
	cfg.MaxDifficulty = testDifficulty + 4
	cfg.TTL = 10 * time.Second
	cfg.Now = func() time.Time { return now }
	c := New(s, cfg)

	ctx := context.Background()
	ch, _ := c.Issue(ctx, challenger.Hint{})
	nonce := Solve(ch.Payload, ch.Difficulty)

	now = now.Add(11 * time.Second)
	err := c.Verify(ctx, challenger.Solution{ID: ch.ID, Nonce: nonce})
	if !errors.Is(err, challenger.ErrUnknownID) {
		t.Fatalf("after expiry got %v want ErrUnknownID", err)
	}
}

func TestDifficultyScalesWithLoad(t *testing.T) {
	c, _ := newTestChallenger(t)
	ctx := context.Background()
	low, _ := c.Issue(ctx, challenger.Hint{Load: 0})
	high, _ := c.Issue(ctx, challenger.Hint{Load: 1})
	if !(high.Difficulty > low.Difficulty) {
		t.Fatalf("expected higher difficulty under load: low=%d high=%d", low.Difficulty, high.Difficulty)
	}
}

func TestDifficultyClampsLoad(t *testing.T) {
	c, _ := newTestChallenger(t)
	ctx := context.Background()
	maxed, _ := c.Issue(ctx, challenger.Hint{Load: 5})
	if maxed.Difficulty != c.cfg.MaxDifficulty {
		t.Fatalf("got %d want %d", maxed.Difficulty, c.cfg.MaxDifficulty)
	}
	minned, _ := c.Issue(ctx, challenger.Hint{Load: -5})
	if minned.Difficulty != c.cfg.BaseDifficulty {
		t.Fatalf("got %d want %d", minned.Difficulty, c.cfg.BaseDifficulty)
	}
}

func TestLeadingZeroBits(t *testing.T) {
	cases := []struct {
		in   []byte
		want int
	}{
		{[]byte{0x00, 0x00, 0xff}, 16},
		{[]byte{0x00, 0x80, 0x00}, 8},
		{[]byte{0x40}, 1},
		{[]byte{0x01}, 7},
		{[]byte{0xff}, 0},
		{[]byte{0x00, 0x00, 0x00, 0x00}, 32},
	}
	for _, c := range cases {
		if got := leadingZeroBits(c.in); got != c.want {
			t.Errorf("leadingZeroBits(%x) = %d, want %d", c.in, got, c.want)
		}
	}
}
