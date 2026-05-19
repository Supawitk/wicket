// Package challenger defines the bot-challenge abstraction.
//
// A Challenger issues a puzzle to a client and verifies the client's
// solution. The default implementation in pkg/challenger/pow uses an
// adaptive proof-of-work scheme.
package challenger

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidSolution = errors.New("challenger: invalid solution")
	ErrUnknownID       = errors.New("challenger: unknown or expired challenge id")
	ErrAlreadyUsed     = errors.New("challenger: challenge already consumed")
)

type Challenge struct {
	ID         string
	Payload    []byte
	Difficulty int
	IssuedAt   time.Time
	ExpiresAt  time.Time
}

type Solution struct {
	ID    string
	Nonce []byte
}

type Hint struct {
	Load float64
}

type Challenger interface {
	Issue(ctx context.Context, hint Hint) (*Challenge, error)
	Verify(ctx context.Context, sol Solution) error
}
