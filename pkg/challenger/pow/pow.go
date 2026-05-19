// Package pow implements an adaptive proof-of-work Challenger.
//
// The server issues a random payload plus a difficulty (number of leading
// zero bits required on SHA-256(payload || nonce)). The client searches for
// a nonce that satisfies the bound and submits it. The server verifies the
// hash and marks the challenge consumed so each issued challenge is good
// for exactly one admission.
//
// Difficulty is adaptive: a configured base level scales up with the Hint.Load
// value supplied by the caller (typically derived from current backend
// utilisation). Mobile-friendly defaults keep the expected solve time near
// one second on a mid-range phone.
package pow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/Supawitk/wicket/pkg/challenger"
	"github.com/Supawitk/wicket/pkg/store"
)

type Config struct {
	BaseDifficulty int
	MaxDifficulty  int
	PayloadBytes   int
	TTL            time.Duration
	Now            func() time.Time
}

func DefaultConfig() Config {
	return Config{
		BaseDifficulty: 16,
		MaxDifficulty:  24,
		PayloadBytes:   16,
		TTL:            5 * time.Minute,
		Now:            time.Now,
	}
}

type Challenger struct {
	cfg   Config
	store store.Store
}

func New(s store.Store, cfg Config) *Challenger {
	if cfg.BaseDifficulty <= 0 {
		cfg.BaseDifficulty = 16
	}
	if cfg.MaxDifficulty <= 0 || cfg.MaxDifficulty < cfg.BaseDifficulty {
		cfg.MaxDifficulty = cfg.BaseDifficulty + 8
	}
	if cfg.PayloadBytes <= 0 {
		cfg.PayloadBytes = 16
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Challenger{cfg: cfg, store: s}
}

func (c *Challenger) Issue(ctx context.Context, hint challenger.Hint) (*challenger.Challenge, error) {
	id, err := randomHex(8)
	if err != nil {
		return nil, fmt.Errorf("pow: gen id: %w", err)
	}
	payload := make([]byte, c.cfg.PayloadBytes)
	if _, err := rand.Read(payload); err != nil {
		return nil, fmt.Errorf("pow: gen payload: %w", err)
	}
	issued := c.cfg.Now()
	expires := issued.Add(c.cfg.TTL)
	ch := &challenger.Challenge{
		ID:         id,
		Payload:    payload,
		Difficulty: c.difficultyFor(hint),
		IssuedAt:   issued,
		ExpiresAt:  expires,
	}
	rec := encodeChallenge(ch)
	if err := c.store.SetNX(ctx, key(id), rec, c.cfg.TTL); err != nil {
		return nil, fmt.Errorf("pow: persist: %w", err)
	}
	return ch, nil
}

func (c *Challenger) Verify(ctx context.Context, sol challenger.Solution) error {
	raw, err := c.store.Get(ctx, key(sol.ID))
	if err != nil {
		return challenger.ErrUnknownID
	}
	ch, err := decodeChallenge(raw)
	if err != nil {
		return challenger.ErrUnknownID
	}
	if c.cfg.Now().After(ch.ExpiresAt) {
		_ = c.store.Delete(ctx, key(sol.ID))
		return challenger.ErrUnknownID
	}
	// Claim a one-shot consumed marker BEFORE the SHA-256 / Argon2 work
	// in Validate. Two concurrent Verify calls with the same (id, nonce)
	// used to both Get → Validate → Delete: the Delete is not atomic
	// with the Get, so both copies admitted the same nonce. SetNX gives
	// us a single winner; the loser gets ErrExists and bails out before
	// burning the hash budget a second time.
	consumedTTL := ch.ExpiresAt.Sub(c.cfg.Now())
	if consumedTTL <= 0 {
		consumedTTL = c.cfg.TTL
	}
	if err := c.store.SetNX(ctx, consumedKey(sol.ID), []byte{1}, consumedTTL); err != nil {
		if errors.Is(err, store.ErrExists) {
			return challenger.ErrUnknownID
		}
		return fmt.Errorf("pow: claim consume: %w", err)
	}
	if !Validate(ch.Payload, sol.Nonce, ch.Difficulty) {
		// Validation failed; release the consumed marker so an honest
		// retry with the correct nonce can still succeed.
		_ = c.store.Delete(ctx, consumedKey(sol.ID))
		return challenger.ErrInvalidSolution
	}
	if err := c.store.Delete(ctx, key(sol.ID)); err != nil {
		return fmt.Errorf("pow: consume: %w", err)
	}
	return nil
}

func (c *Challenger) difficultyFor(hint challenger.Hint) int {
	load := hint.Load
	if load < 0 {
		load = 0
	}
	if load > 1 {
		load = 1
	}
	span := float64(c.cfg.MaxDifficulty - c.cfg.BaseDifficulty)
	return c.cfg.BaseDifficulty + int(math.Round(span*load))
}

// Validate checks that SHA-256(payload || nonce) has at least difficulty
// leading zero bits. It is exported so clients (and the cmd/wicket binary's
// JS challenge page) can share the same primitive.
func Validate(payload, nonce []byte, difficulty int) bool {
	buf := make([]byte, 0, len(payload)+len(nonce))
	buf = append(buf, payload...)
	buf = append(buf, nonce...)
	sum := sha256.Sum256(buf)
	return leadingZeroBits(sum[:]) >= difficulty
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if x&(1<<i) == 0 {
				n++
			} else {
				return n
			}
		}
	}
	return n
}

func key(id string) string         { return "pow:" + id }
func consumedKey(id string) string { return "pow:consumed:" + id }

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func encodeChallenge(ch *challenger.Challenge) []byte {
	// payload-len(2) || payload || difficulty(2) || expires-unix-nano(8)
	buf := make([]byte, 0, 12+len(ch.Payload))
	plen := uint16(len(ch.Payload))
	buf = append(buf, byte(plen), byte(plen>>8))
	buf = append(buf, ch.Payload...)
	diff := uint16(ch.Difficulty)
	buf = append(buf, byte(diff), byte(diff>>8))
	exp := uint64(ch.ExpiresAt.UnixNano())
	for i := 0; i < 8; i++ {
		buf = append(buf, byte(exp>>(8*i)))
	}
	return buf
}

func decodeChallenge(buf []byte) (*challenger.Challenge, error) {
	if len(buf) < 2 {
		return nil, fmt.Errorf("pow: short record")
	}
	plen := int(buf[0]) | int(buf[1])<<8
	if len(buf) < 2+plen+2+8 {
		return nil, fmt.Errorf("pow: short record")
	}
	payload := make([]byte, plen)
	copy(payload, buf[2:2+plen])
	off := 2 + plen
	diff := int(buf[off]) | int(buf[off+1])<<8
	off += 2
	var exp uint64
	for i := 0; i < 8; i++ {
		exp |= uint64(buf[off+i]) << (8 * i)
	}
	return &challenger.Challenge{
		Payload:    payload,
		Difficulty: diff,
		ExpiresAt:  time.Unix(0, int64(exp)),
	}, nil
}

// Solve is a convenience helper for tests and example clients. It searches
// for a valid nonce by brute force. Not suitable for serving real client
// puzzles — those should run in the browser/mobile client.
func Solve(payload []byte, difficulty int) []byte {
	for n := uint64(0); ; n++ {
		nonce := make([]byte, 8)
		for i := 0; i < 8; i++ {
			nonce[i] = byte(n >> (8 * i))
		}
		if Validate(payload, nonce, difficulty) {
			return nonce
		}
	}
}
