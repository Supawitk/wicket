// Package argon2 implements a memory-bound proof-of-work Challenger using
// Argon2id. Unlike the SHA-256 PoW in pkg/challenger/pow, the cost of
// solving an Argon2id challenge is dominated by RAM bandwidth, which
// narrows the gap between commodity smartphones and GPU/ASIC bot farms.
//
// The challenge consists of a random payload, a target prefix length in
// leading zero bytes, and Argon2id parameters (time, memory, threads).
// The client searches for a nonce such that Argon2id(payload || nonce,
// salt=payload[:saltLen], …) has at least the target number of leading
// zero bytes. The server verifies by recomputing the hash.
//
// Use this when you suspect attackers are using GPU-accelerated SHA-256
// solvers; fall back to pkg/challenger/pow when minimum-friction matters
// more than memory-bound resistance.
package argon2

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/Supawitk/wicket/pkg/challenger"
	"github.com/Supawitk/wicket/pkg/store"
)

type Config struct {
	BaseZeroBytes int    // minimum leading-zero bytes required (default: 2 = 16 bits)
	MaxZeroBytes  int    // upper bound under maximum load (default: BaseZeroBytes+2)
	PayloadBytes  int    // length of random payload (default: 16)
	Time          uint32 // Argon2id time parameter (default: 1)
	Memory        uint32 // Argon2id memory KiB (default: 19 MiB — OWASP minimum)
	Threads       uint8  // Argon2id parallelism (default: 1)
	KeyLen        uint32 // Argon2id output length (default: 32)
	TTL           time.Duration
	Now           func() time.Time
}

func DefaultConfig() Config {
	return Config{
		BaseZeroBytes: 2,
		MaxZeroBytes:  4,
		PayloadBytes:  16,
		Time:          1,
		Memory:        19 * 1024, // 19 MiB
		Threads:       1,
		KeyLen:        32,
		TTL:           5 * time.Minute,
		Now:           time.Now,
	}
}

type Challenger struct {
	cfg   Config
	store store.Store
}

func New(s store.Store, cfg Config) *Challenger {
	if cfg.BaseZeroBytes <= 0 {
		cfg.BaseZeroBytes = 2
	}
	if cfg.MaxZeroBytes < cfg.BaseZeroBytes {
		cfg.MaxZeroBytes = cfg.BaseZeroBytes + 2
	}
	if cfg.PayloadBytes <= 0 {
		cfg.PayloadBytes = 16
	}
	if cfg.Time == 0 {
		cfg.Time = 1
	}
	if cfg.Memory == 0 {
		cfg.Memory = 19 * 1024
	}
	if cfg.Threads == 0 {
		cfg.Threads = 1
	}
	if cfg.KeyLen == 0 {
		cfg.KeyLen = 32
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
		return nil, fmt.Errorf("argon2: gen id: %w", err)
	}
	payload := make([]byte, c.cfg.PayloadBytes)
	if _, err := rand.Read(payload); err != nil {
		return nil, fmt.Errorf("argon2: gen payload: %w", err)
	}
	issued := c.cfg.Now()
	expires := issued.Add(c.cfg.TTL)
	zeroBytes := c.zeroBytesFor(hint)
	ch := &challenger.Challenge{
		ID:         id,
		Payload:    payload,
		Difficulty: zeroBytes,
		IssuedAt:   issued,
		ExpiresAt:  expires,
	}
	rec := encodeChallenge(ch)
	if err := c.store.SetNX(ctx, key(id), rec, c.cfg.TTL); err != nil {
		return nil, fmt.Errorf("argon2: persist: %w", err)
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
	// Claim a one-shot consumed marker BEFORE running Argon2id. Two
	// concurrent Verify calls used to both Get → validate → Delete and
	// each burned a full Argon2 computation (19 MiB / 1 thread by
	// default). An attacker holding a single valid nonce could amplify
	// that into arbitrary CPU/RAM cost on the server by issuing many
	// parallel Verify requests. SetNX gives us a single winner.
	consumedTTL := ch.ExpiresAt.Sub(c.cfg.Now())
	if consumedTTL <= 0 {
		consumedTTL = c.cfg.TTL
	}
	if err := c.store.SetNX(ctx, consumedKey(sol.ID), []byte{1}, consumedTTL); err != nil {
		if errors.Is(err, store.ErrExists) {
			return challenger.ErrUnknownID
		}
		return fmt.Errorf("argon2: claim consume: %w", err)
	}
	if !c.validate(ch.Payload, sol.Nonce, ch.Difficulty) {
		_ = c.store.Delete(ctx, consumedKey(sol.ID))
		return challenger.ErrInvalidSolution
	}
	if err := c.store.Delete(ctx, key(sol.ID)); err != nil {
		return fmt.Errorf("argon2: consume: %w", err)
	}
	return nil
}

// Params exports the Argon2id parameters so a client (e.g. a browser
// running argon2-browser in WASM) can replicate the computation.
func (c *Challenger) Params() (time, memory uint32, threads uint8, keyLen uint32) {
	return c.cfg.Time, c.cfg.Memory, c.cfg.Threads, c.cfg.KeyLen
}

func (c *Challenger) validate(payload, nonce []byte, zeroBytes int) bool {
	if zeroBytes <= 0 || zeroBytes > 32 {
		return false
	}
	buf := make([]byte, 0, len(payload)+len(nonce))
	buf = append(buf, payload...)
	buf = append(buf, nonce...)
	// Use the payload itself as the salt — deterministic, no extra state to
	// transmit, and unpredictable to the client until Issue.
	out := argon2.IDKey(buf, payload, c.cfg.Time, c.cfg.Memory, c.cfg.Threads, c.cfg.KeyLen)
	for i := 0; i < zeroBytes; i++ {
		if out[i] != 0 {
			return false
		}
	}
	return true
}

func (c *Challenger) zeroBytesFor(hint challenger.Hint) int {
	load := hint.Load
	if load < 0 {
		load = 0
	}
	if load > 1 {
		load = 1
	}
	span := float64(c.cfg.MaxZeroBytes - c.cfg.BaseZeroBytes)
	return c.cfg.BaseZeroBytes + int(math.Round(span*load))
}

func key(id string) string         { return "argon2:" + id }
func consumedKey(id string) string { return "argon2:consumed:" + id }

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func encodeChallenge(ch *challenger.Challenge) []byte {
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
		return nil, errors.New("argon2: short record")
	}
	plen := int(buf[0]) | int(buf[1])<<8
	if len(buf) < 2+plen+2+8 {
		return nil, errors.New("argon2: short record")
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

// Solve is a brute-force helper. Not for production clients (the browser
// should be using argon2-browser via WASM) but useful for tests and for
// the example client.
func Solve(payload []byte, zeroBytes int, time, memory uint32, threads uint8, keyLen uint32) []byte {
	for n := uint64(0); ; n++ {
		nonce := make([]byte, 8)
		for i := 0; i < 8; i++ {
			nonce[i] = byte(n >> (8 * i))
		}
		buf := append(append([]byte{}, payload...), nonce...)
		out := argon2.IDKey(buf, payload, time, memory, threads, keyLen)
		ok := true
		for i := 0; i < zeroBytes; i++ {
			if out[i] != 0 {
				ok = false
				break
			}
		}
		if ok {
			return nonce
		}
	}
}
