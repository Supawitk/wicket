// Package passkey implements the identity.Identity interface against
// Ed25519-signed credentials.
//
// This is the credential-verification core of a passkey/WebAuthn flow.
// Higher layers (the browser ceremony, COSE/CBOR parsing) sit on top of
// these primitives; an upstream caller hands the verifier a
// (credentialID, challengeID, signature) triple and the verifier returns
// a nullifier suitable for "one credential = one admission" enforcement.
//
// Concretely:
//
//   - Register stores a (credentialID, publicKey) pair.
//   - IssueChallenge generates a random challenge that the client must
//     sign with the credential's private key.
//   - Verify takes a JSON-encoded Proof{CredentialID, ChallengeID, Signature}
//     and returns a Nullifier whose Hash is the hex credentialID. The
//     challenge is consumed on success so an assertion cannot be replayed.
//
// Full COSE/CBOR/WebAuthn parsing can be layered above this package by
// extracting the Ed25519 public key from the attestation object during
// registration and feeding it into Register.
package passkey

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Supawitk/wicket/pkg/identity"
	"github.com/Supawitk/wicket/pkg/store"
)

var (
	ErrUnknownCredential = errors.New("passkey: unknown credential")
	ErrUnknownChallenge  = errors.New("passkey: unknown or expired challenge")
	// ErrChallengeMismatch fires when the challenge ID in a proof was
	// issued for a different credential than the one signing the proof.
	// Without this check, an attacker who observes another user's
	// challenge ID can consume it with their own credential — a DoS
	// against the original challenge owner.
	ErrChallengeMismatch = errors.New("passkey: challenge/credential mismatch")
)

// Proof is the JSON shape Verify expects.
type Proof struct {
	CredentialID string `json:"credential_id"`
	ChallengeID  string `json:"challenge_id"`
	Signature    string `json:"signature"` // hex
}

type Challenge struct {
	ID        string
	Payload   []byte
	ExpiresAt time.Time
}

type Config struct {
	ChallengeTTL time.Duration
	Now          func() time.Time
}

type Verifier struct {
	cfg       Config
	creds     store.Store // credentialID -> ed25519.PublicKey
	chals     store.Store // challengeID -> raw payload
}

// New constructs a passkey verifier. The two stores can be the same
// instance backed by Redis, in-memory, etc.
func New(creds, chals store.Store, cfg Config) *Verifier {
	if cfg.ChallengeTTL <= 0 {
		cfg.ChallengeTTL = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{cfg: cfg, creds: creds, chals: chals}
}

// Register stores a public key for credentialID.
func (v *Verifier) Register(ctx context.Context, credentialID string, pubKey ed25519.PublicKey) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("passkey: public key must be %d bytes", ed25519.PublicKeySize)
	}
	buf := make([]byte, len(pubKey))
	copy(buf, pubKey)
	return v.creds.SetNX(ctx, credKey(credentialID), buf, 0)
}

// IssueChallenge mints a fresh random challenge tied to credentialID. The
// credentialID is persisted alongside the payload so Verify can reject
// proofs that present a different credential than the one this challenge
// was issued for.
func (v *Verifier) IssueChallenge(ctx context.Context, credentialID string) (*Challenge, error) {
	if _, err := v.creds.Get(ctx, credKey(credentialID)); err != nil {
		return nil, ErrUnknownCredential
	}
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	payload := make([]byte, 32)
	if _, err := rand.Read(payload); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idBytes)
	stored, err := json.Marshal(storedChallenge{
		CredentialID: credentialID,
		Payload:      payload,
	})
	if err != nil {
		return nil, err
	}
	if err := v.chals.SetNX(ctx, chalKey(id), stored, v.cfg.ChallengeTTL); err != nil {
		return nil, err
	}
	return &Challenge{
		ID:        id,
		Payload:   payload,
		ExpiresAt: v.cfg.Now().Add(v.cfg.ChallengeTTL),
	}, nil
}

// storedChallenge is the on-disk shape of an issued challenge. The
// credentialID is included so Verify can refuse proofs signed by a
// different credential than the one IssueChallenge was called with.
type storedChallenge struct {
	CredentialID string `json:"credential_id"`
	Payload      []byte `json:"payload"`
}

// Verify implements identity.Identity. The proof argument must be a
// JSON-encoded Proof. On success the challenge is consumed and a
// Nullifier whose Hash equals the credentialID is returned.
func (v *Verifier) Verify(ctx context.Context, scope string, proof []byte) (*identity.Nullifier, error) {
	var p Proof
	if err := json.Unmarshal(proof, &p); err != nil {
		return nil, identity.ErrInvalidProof
	}

	pubRaw, err := v.creds.Get(ctx, credKey(p.CredentialID))
	if err != nil {
		return nil, ErrUnknownCredential
	}
	raw, err := v.chals.Get(ctx, chalKey(p.ChallengeID))
	if err != nil {
		return nil, ErrUnknownChallenge
	}
	var stored storedChallenge
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, ErrUnknownChallenge
	}
	if stored.CredentialID != p.CredentialID {
		// Do NOT delete the challenge here. If a stranger could trigger
		// deletion by guessing/observing a challenge ID, they could DoS
		// the original credential owner. The challenge will expire on
		// its TTL.
		return nil, ErrChallengeMismatch
	}
	sig, err := hex.DecodeString(p.Signature)
	if err != nil {
		return nil, identity.ErrInvalidProof
	}

	if !ed25519.Verify(ed25519.PublicKey(pubRaw), stored.Payload, sig) {
		return nil, identity.ErrInvalidProof
	}

	if err := v.chals.Delete(ctx, chalKey(p.ChallengeID)); err != nil {
		return nil, fmt.Errorf("passkey: consume challenge: %w", err)
	}

	return &identity.Nullifier{
		Hash:  p.CredentialID,
		Scope: scope,
	}, nil
}

func credKey(id string) string { return "pk:cred:" + id }
func chalKey(id string) string { return "pk:chal:" + id }
