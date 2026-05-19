// Package identity defines the optional proof-of-personhood abstraction.
//
// An Identity verifier takes an opaque proof supplied by the client and
// returns a stable nullifier — a hex string that is unique per credential
// per Scope. Wicket uses the nullifier to enforce "one credential = one
// admission" semantics when an identity layer is configured.
//
// Concrete adapters (WebAuthn passkey, Self Protocol, NDID, Human Passport)
// will land in subpackages.
package identity

import (
	"context"
	"errors"
)

var (
	ErrInvalidProof = errors.New("identity: invalid proof")
)

type Nullifier struct {
	Hash  string
	Scope string
}

type Identity interface {
	Verify(ctx context.Context, scope string, proof []byte) (*Nullifier, error)
}
