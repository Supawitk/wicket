package admission

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Supawitk/wicket/pkg/store/memory"
)

func newPair(t *testing.T) (*Issuer, *Verifier, *memory.Store, *time.Time) {
	t.Helper()
	now := time.Unix(1_000_000, 0)
	s := memory.New(memory.WithClock(func() time.Time { return now }))
	t.Cleanup(func() { _ = s.Close() })
	iss, err := NewIssuer(Config{
		Secret: []byte("01234567890123456789"),
		TTL:    10 * time.Second,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	ver := NewVerifier([]byte("01234567890123456789"), s, func() time.Time { return now })
	return iss, ver, s, &now
}

func TestIssueVerifyHappyPath(t *testing.T) {
	iss, ver, _, _ := newPair(t)
	tok, err := iss.Issue("ticket-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	subj, err := ver.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if subj != "ticket-1" {
		t.Fatalf("subj %q", subj)
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	iss, ver, _, _ := newPair(t)
	tok, _ := iss.Issue("t")
	if _, err := ver.Verify(context.Background(), tok); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if _, err := ver.Verify(context.Background(), tok); !errors.Is(err, ErrReplayed) {
		t.Fatalf("second verify got %v want ErrReplayed", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	iss, ver, _, now := newPair(t)
	tok, _ := iss.Issue("t")
	*now = now.Add(11 * time.Second)
	if _, err := ver.Verify(context.Background(), tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v want ErrExpired", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	iss, ver, _, _ := newPair(t)
	tok, _ := iss.Issue("t")
	// Swap a char in the middle of the signature segment to avoid
	// trailing-byte base64 ambiguity (the final character of a non-padded
	// base64 string can have bits that aren't significant).
	parts := strings.Split(tok, ".")
	sig := parts[3]
	mid := len(sig) / 2
	orig := sig[mid]
	swap := byte('A')
	if orig == 'A' {
		swap = 'B'
	}
	parts[3] = sig[:mid] + string(swap) + sig[mid+1:]
	tampered := strings.Join(parts, ".")
	if _, err := ver.Verify(context.Background(), tampered); !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v want ErrSignature", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	iss, ver, _, _ := newPair(t)
	tok, _ := iss.Issue("normal")
	parts := strings.Split(tok, ".")
	// Replace the subject; signature won't match.
	parts[2] = "ZXZpbA" // base64("evil")
	tampered := strings.Join(parts, ".")
	if _, err := ver.Verify(context.Background(), tampered); !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v want ErrSignature", err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	_, ver, _, _ := newPair(t)
	cases := []string{"", "not-a-token", "a.b.c", "a.b.c.d.e"}
	for _, c := range cases {
		if _, err := ver.Verify(context.Background(), c); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q got %v want ErrMalformed", c, err)
		}
	}
}

func TestIssuerSecretMinLength(t *testing.T) {
	_, err := NewIssuer(Config{Secret: []byte("short")})
	if err == nil {
		t.Fatal("expected error for short secret")
	}
}

func TestTokensAreDistinct(t *testing.T) {
	iss, _, _, _ := newPair(t)
	a, _ := iss.Issue("x")
	b, _ := iss.Issue("x")
	if a == b {
		t.Fatal("two issues for same subject produced identical token")
	}
}

func TestNonceCollisionDoesNotLeak(t *testing.T) {
	// Sanity: pre-populating the store with a colliding nonce should cause Verify to reject.
	iss, ver, s, _ := newPair(t)
	tok, _ := iss.Issue("t")
	parts := strings.Split(tok, ".")
	_ = s.Set(context.Background(), nonceKey(parts[0]), []byte{1}, time.Hour)
	if _, err := ver.Verify(context.Background(), tok); !errors.Is(err, ErrReplayed) {
		t.Fatalf("got %v want ErrReplayed", err)
	}
}
