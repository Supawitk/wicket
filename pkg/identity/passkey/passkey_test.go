package passkey

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Supawitk/wicket/pkg/identity"
	"github.com/Supawitk/wicket/pkg/store/memory"
)

func newTestVerifier(t *testing.T) *Verifier {
	t.Helper()
	creds := memory.New()
	chals := memory.New()
	t.Cleanup(func() {
		_ = creds.Close()
		_ = chals.Close()
	})
	return New(creds, chals, Config{})
}

func register(t *testing.T, v *Verifier, id string) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := v.Register(context.Background(), id, pub); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return priv, pub
}

func TestRegisterAndVerifyHappyPath(t *testing.T) {
	v := newTestVerifier(t)
	ctx := context.Background()
	priv, _ := register(t, v, "cred-1")

	ch, err := v.IssueChallenge(ctx, "cred-1")
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	sig := ed25519.Sign(priv, ch.Payload)
	proof, _ := json.Marshal(Proof{
		CredentialID: "cred-1",
		ChallengeID:  ch.ID,
		Signature:    hex.EncodeToString(sig),
	})
	nul, err := v.Verify(ctx, "concert", proof)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if nul.Hash != "cred-1" {
		t.Fatalf("Hash = %q", nul.Hash)
	}
	if nul.Scope != "concert" {
		t.Fatalf("Scope = %q", nul.Scope)
	}
}

func TestVerifyConsumesChallenge(t *testing.T) {
	v := newTestVerifier(t)
	ctx := context.Background()
	priv, _ := register(t, v, "cred-2")
	ch, _ := v.IssueChallenge(ctx, "cred-2")
	sig := ed25519.Sign(priv, ch.Payload)
	proof, _ := json.Marshal(Proof{
		CredentialID: "cred-2",
		ChallengeID:  ch.ID,
		Signature:    hex.EncodeToString(sig),
	})
	if _, err := v.Verify(ctx, "scope", proof); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := v.Verify(ctx, "scope", proof); !errors.Is(err, ErrUnknownChallenge) {
		t.Fatalf("replay got %v want ErrUnknownChallenge", err)
	}
}

func TestVerifyRejectsBadSignature(t *testing.T) {
	v := newTestVerifier(t)
	ctx := context.Background()
	_, _ = register(t, v, "cred-3")
	ch, _ := v.IssueChallenge(ctx, "cred-3")
	bogus := make([]byte, ed25519.SignatureSize)
	proof, _ := json.Marshal(Proof{
		CredentialID: "cred-3",
		ChallengeID:  ch.ID,
		Signature:    hex.EncodeToString(bogus),
	})
	if _, err := v.Verify(ctx, "s", proof); !errors.Is(err, identity.ErrInvalidProof) {
		t.Fatalf("got %v want ErrInvalidProof", err)
	}
}

func TestVerifyRejectsUnknownCredential(t *testing.T) {
	v := newTestVerifier(t)
	proof, _ := json.Marshal(Proof{CredentialID: "nope", ChallengeID: "x", Signature: "00"})
	_, err := v.Verify(context.Background(), "s", proof)
	if !errors.Is(err, ErrUnknownCredential) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyRejectsUnknownChallenge(t *testing.T) {
	v := newTestVerifier(t)
	_, _ = register(t, v, "cred-4")
	proof, _ := json.Marshal(Proof{CredentialID: "cred-4", ChallengeID: "ghost", Signature: "00"})
	_, err := v.Verify(context.Background(), "s", proof)
	if !errors.Is(err, ErrUnknownChallenge) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyRejectsMalformedProof(t *testing.T) {
	v := newTestVerifier(t)
	_, err := v.Verify(context.Background(), "s", []byte("not-json"))
	if !errors.Is(err, identity.ErrInvalidProof) {
		t.Fatalf("got %v", err)
	}
}

func TestRegisterRejectsBadPubKeySize(t *testing.T) {
	v := newTestVerifier(t)
	err := v.Register(context.Background(), "cred", []byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestIssueChallengeRejectsUnknownCredential(t *testing.T) {
	v := newTestVerifier(t)
	_, err := v.IssueChallenge(context.Background(), "missing")
	if !errors.Is(err, ErrUnknownCredential) {
		t.Fatalf("got %v", err)
	}
}

// TestVerifyRejectsCrossCredentialChallenge is the regression test for the
// DoS that lets Alice consume Bob's challenge with her own credential.
// Without the binding, Alice signs the stored payload with her own key
// (the verifier reads it back and accepts her signature), and Bob's
// challenge is deleted out from under him. With the binding, Verify must
// return ErrChallengeMismatch and leave Bob's challenge intact.
func TestVerifyRejectsCrossCredentialChallenge(t *testing.T) {
	v := newTestVerifier(t)
	ctx := context.Background()

	alicePriv, _ := register(t, v, "alice")
	_, _ = register(t, v, "bob")

	bobChal, err := v.IssueChallenge(ctx, "bob")
	if err != nil {
		t.Fatalf("IssueChallenge bob: %v", err)
	}

	// Alice signs Bob's challenge payload with her own private key and
	// presents her own credential ID.
	sig := ed25519.Sign(alicePriv, bobChal.Payload)
	proof, _ := json.Marshal(Proof{
		CredentialID: "alice",
		ChallengeID:  bobChal.ID,
		Signature:    hex.EncodeToString(sig),
	})
	_, err = v.Verify(ctx, "concert", proof)
	if !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("got %v want ErrChallengeMismatch", err)
	}

	// Bob's challenge must still be consumable by Bob.
	bobPriv, _ := register(t, v, "bob-2")
	bobChal2, err := v.IssueChallenge(ctx, "bob-2")
	if err != nil {
		t.Fatalf("IssueChallenge bob-2: %v", err)
	}
	bobSig := ed25519.Sign(bobPriv, bobChal2.Payload)
	bobProof, _ := json.Marshal(Proof{
		CredentialID: "bob-2",
		ChallengeID:  bobChal2.ID,
		Signature:    hex.EncodeToString(bobSig),
	})
	if _, err := v.Verify(ctx, "concert", bobProof); err != nil {
		t.Fatalf("Verify bob-2 after mismatch attempt: %v", err)
	}

	// Bob's original challenge must NOT have been consumed by Alice's
	// failed attempt — otherwise the bug is reachable as a DoS.
	if _, err := v.chals.Get(ctx, chalKey(bobChal.ID)); err != nil {
		t.Fatalf("bob's original challenge was deleted by Alice's attempt: %v", err)
	}
}

func TestIssueChallengeIDsAreUnique(t *testing.T) {
	v := newTestVerifier(t)
	_, _ = register(t, v, "cred-5")
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		ch, err := v.IssueChallenge(context.Background(), "cred-5")
		if err != nil {
			t.Fatalf("IssueChallenge: %v", err)
		}
		if seen[ch.ID] {
			t.Fatalf("duplicate id %s", ch.ID)
		}
		seen[ch.ID] = true
	}
}
