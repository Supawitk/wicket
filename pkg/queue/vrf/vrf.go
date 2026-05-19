// Package vrf implements a verifiable-fair admission queue.
//
// Three modes are supported, selected via Config:
//
//   - ECVRF mode: implements RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI via
//     github.com/ProtonMail/go-ecvrf. This is the strongest mode for
//     correctness — it provides the formal uniqueness, collision
//     resistance, and pseudorandomness properties of a true VRF. Use
//     this when an external auditor demands "this is RFC 9381 ECVRF."
//
//   - Ed25519 mode (default for low-friction setup): the operator
//     generates an Ed25519 keypair. Each ticket carries a signature of
//     its ID; the score is derived from the signature. Practically
//     equivalent for fairness but not formally a VRF.
//
//   - Seed mode: classic commit-reveal. The operator commits to
//     SHA-256(seed) before the queue opens and reveals seed after; each
//     ticket's score is SHA-256(seed || ticketID). Useful when an
//     external randomness beacon (drand) supplies the seed.
//
// All modes also expose an Audit() method returning a Merkle log of all
// (ticketID, score) pairs so an operator can publish a compact, tamper-
// evident summary after the event.
//
// Process-local state: this implementation keeps the ticket set and
// positions map in process memory. Running multiple sidecar instances
// in front of a shared upstream therefore requires sticky load balancing
// — Enqueue on replica A and Status on replica B will report "unknown
// ticket" on B. A shared-store variant is a known follow-up; the
// challenger pkg/store interface is the model.
package vrf

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	pmecvrf "github.com/ProtonMail/go-ecvrf/ecvrf"

	"github.com/Supawitk/wicket/pkg/queue"
)

var (
	ErrUnknownProof = errors.New("vrf: no proof for ticket")
)

type Mode int

const (
	ModeEd25519 Mode = iota
	ModeSeed
	ModeECVRF
)

type Config struct {
	// PrivateKey selects Ed25519 mode. If nil and Seed and ECVRFKey are
	// also nil, a fresh Ed25519 keypair is generated.
	PrivateKey ed25519.PrivateKey
	// Seed selects seed mode. Mutually exclusive with PrivateKey and ECVRFKey.
	Seed []byte
	// ECVRFKey selects ECVRF mode (RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI).
	// Mutually exclusive with PrivateKey and Seed. If UseECVRF is true and
	// ECVRFKey is nil, a fresh key is generated.
	ECVRFKey *pmecvrf.PrivateKey
	// UseECVRF requests ECVRF mode with an auto-generated key when
	// ECVRFKey is nil. Has no effect if any other key is supplied.
	UseECVRF bool
	Now      func() time.Time
}

type record struct {
	score    uint64
	proof    []byte // Ed25519 signature in Ed25519 mode; nil in seed mode
	issued   time.Time
	preQueue bool // true if enqueued before Open(); randomised into positions 1..N at open time
	seq      int64 // assigned for post-open arrivals to guarantee FIFO after the pre-queue
}

type Queue struct {
	mu         sync.RWMutex
	now        func() time.Time
	mode       Mode
	privKey    ed25519.PrivateKey
	pubKey     ed25519.PublicKey
	ecvrfPriv  *pmecvrf.PrivateKey
	ecvrfPub   *pmecvrf.PublicKey
	seed       []byte
	commitment [32]byte
	revealed   bool
	tickets    map[string]record
	cursor     int64

	// Pre-queue + open state. When the queue is opened, pre-queue tickets
	// are randomised by their VRF/seed score; post-open tickets get a
	// monotonic sequence number and queue strictly behind them. This is
	// the standard "lottery for early arrivals, FIFO after" pattern.
	opened   bool
	preCount int64 // count of pre-queue tickets at the moment Open() was called
	postSeq  int64 // next sequence number for post-open arrivals

	// positions maps ticket ID to its final position in the queue.
	// It is the source of truth for Status() once built. nil means the
	// ordering is stale (a pre-open Enqueue happened since the last
	// rebuild); the next Status() call will rebuild lazily.
	//
	// Open() materialises positions for the entire pre-queue in one
	// O(N log N) sort. Post-open Enqueue appends preCount + postSeq
	// directly, keeping the hot path O(1). Without this map the rank
	// computation walked the entire ticket set on every Status query,
	// which is ~21µs at 1k tickets but ≈21ms at 1M tickets — fatal at
	// the poll volumes a ticket-drop produces.
	positions map[string]int64
}

// New constructs a VRF queue. See package documentation for the modes.
func New(cfg Config) (*Queue, error) {
	keysSet := 0
	if cfg.PrivateKey != nil {
		keysSet++
	}
	if len(cfg.Seed) > 0 {
		keysSet++
	}
	if cfg.ECVRFKey != nil || cfg.UseECVRF {
		keysSet++
	}
	if keysSet > 1 {
		return nil, errors.New("vrf: at most one of PrivateKey, Seed, ECVRFKey/UseECVRF may be set")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	q := &Queue{
		now:     now,
		tickets: make(map[string]record),
	}
	switch {
	case len(cfg.Seed) > 0:
		q.mode = ModeSeed
		q.seed = make([]byte, len(cfg.Seed))
		copy(q.seed, cfg.Seed)
		q.commitment = sha256.Sum256(q.seed)
	case cfg.ECVRFKey != nil || cfg.UseECVRF:
		q.mode = ModeECVRF
		var err error
		if cfg.ECVRFKey == nil {
			q.ecvrfPriv, err = pmecvrf.GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}
		} else {
			q.ecvrfPriv = cfg.ECVRFKey
		}
		q.ecvrfPub, err = q.ecvrfPriv.Public()
		if err != nil {
			return nil, err
		}
		pubBytes := q.ecvrfPub.Bytes()
		if len(pubBytes) >= 32 {
			copy(q.commitment[:], pubBytes[:32])
		} else {
			copy(q.commitment[:], pubBytes)
		}
	default:
		q.mode = ModeEd25519
		var err error
		if cfg.PrivateKey == nil {
			q.pubKey, q.privKey, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}
		} else {
			q.privKey = cfg.PrivateKey
			q.pubKey = cfg.PrivateKey.Public().(ed25519.PublicKey)
		}
		copy(q.commitment[:], q.pubKey)
	}
	return q, nil
}

func (q *Queue) Mode() Mode { return q.mode }

// Commitment returns the published, pre-queue commitment. In seed mode
// this is SHA-256(seed); in Ed25519 mode it is the public key padded
// to 32 bytes (Ed25519 public keys are exactly 32 bytes).
func (q *Queue) Commitment() [32]byte { return q.commitment }

// PublicKey returns the operator's Ed25519 public key (Ed25519 mode only,
// nil otherwise). Auditors use this to verify per-ticket proofs.
func (q *Queue) PublicKey() ed25519.PublicKey {
	if q.mode != ModeEd25519 {
		return nil
	}
	out := make(ed25519.PublicKey, len(q.pubKey))
	copy(out, q.pubKey)
	return out
}

// ECVRFPublicKey returns the operator's ECVRF public-key bytes (ECVRF
// mode only, nil otherwise). Used together with the per-ticket Proof to
// independently recompute a ticket's score.
func (q *Queue) ECVRFPublicKey() []byte {
	if q.mode != ModeECVRF || q.ecvrfPub == nil {
		return nil
	}
	return q.ecvrfPub.Bytes()
}

// Reveal exposes the seed (seed mode only). Returns nil in Ed25519 mode —
// Ed25519 mode is verifiable per-ticket and does not need a reveal.
func (q *Queue) Reveal() []byte {
	if q.mode != ModeSeed {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.revealed = true
	out := make([]byte, len(q.seed))
	copy(out, q.seed)
	return out
}

func (q *Queue) Revealed() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.revealed
}

// Open transitions the queue from pre-queue to FIFO mode. All tickets
// enqueued before Open() are randomised into positions 1..N by their VRF
// score. Tickets enqueued after Open() get a monotonic sequence number
// and rank strictly behind all pre-queue tickets — speedy bots cannot
// jump ahead of legitimate early arrivals.
//
// Open() is optional. If never called, the queue operates as a single
// VRF-randomised pool (the v0.1 behaviour).
func (q *Queue) Open() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.opened {
		return
	}
	q.opened = true
	q.preCount = int64(len(q.tickets))
	q.rebuildPositionsLocked()
}

// rebuildPositionsLocked materialises the positions map from the current
// ticket set. The caller MUST hold the write lock.
func (q *Queue) rebuildPositionsLocked() {
	entries := q.exportLocked()
	q.positions = make(map[string]int64, len(entries))
	for _, e := range entries {
		q.positions[e.TicketID] = e.Position
	}
}

// Opened reports whether Open() has been called.
func (q *Queue) Opened() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.opened
}

func (q *Queue) Enqueue(_ context.Context, _ string) (*queue.Ticket, error) {
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idBytes)

	var score uint64
	var proof []byte
	switch q.mode {
	case ModeEd25519:
		sig := ed25519.Sign(q.privKey, []byte(id))
		proof = sig
		score = binary.BigEndian.Uint64(sig[:8])
	case ModeSeed:
		score = ScoreSeed(q.seed, id)
	case ModeECVRF:
		vrfOut, prf, err := q.ecvrfPriv.Prove([]byte(id))
		if err != nil {
			return nil, err
		}
		proof = prf
		if len(vrfOut) < 8 {
			return nil, errors.New("vrf: ECVRF output too short")
		}
		score = binary.BigEndian.Uint64(vrfOut[:8])
	}

	issued := q.now()
	q.mu.Lock()
	rec := record{score: score, proof: proof, issued: issued}
	if q.opened {
		q.postSeq++
		rec.seq = q.postSeq
		q.tickets[id] = rec
		// Post-open arrivals land in a deterministic position behind
		// everything that came before, so we can append directly
		// without resorting.
		if q.positions != nil {
			q.positions[id] = q.preCount + q.postSeq
		}
	} else {
		rec.preQueue = true
		q.tickets[id] = rec
		// Pre-open insertion changes the score-sorted ordering of all
		// pre-queue tickets; invalidate and let the next Status query
		// rebuild lazily. Open() will rebuild eagerly.
		q.positions = nil
	}
	q.mu.Unlock()
	return &queue.Ticket{ID: id, Issued: issued}, nil
}

func (q *Queue) Status(_ context.Context, ticketID string) (*queue.Status, error) {
	// Fast path: positions is already materialised. Concurrent Status
	// queries serialised on a write lock turn a polling storm
	// (1M users × /status every 5s) into a queue of its own. RLock lets
	// them run in parallel; we only escalate to a write lock if the
	// positions map needs a rebuild.
	q.mu.RLock()
	if _, ok := q.tickets[ticketID]; !ok {
		q.mu.RUnlock()
		return nil, queue.ErrUnknownTicket
	}
	if q.positions != nil {
		st := q.buildStatusLocked(ticketID)
		q.mu.RUnlock()
		return st, nil
	}
	q.mu.RUnlock()

	// Slow path: rebuild under the write lock, then read. Re-check
	// everything because a concurrent Enqueue / rebuild may have moved
	// state while we were unlocked.
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.tickets[ticketID]; !ok {
		return nil, queue.ErrUnknownTicket
	}
	if q.positions == nil {
		q.rebuildPositionsLocked()
	}
	return q.buildStatusLocked(ticketID), nil
}

// buildStatusLocked composes a Status from the current positions map and
// cursor. Caller must hold either q.mu (Lock or RLock); the function
// performs only reads.
func (q *Queue) buildStatusLocked(ticketID string) *queue.Status {
	position := q.positions[ticketID]
	ahead := position - q.cursor - 1
	if ahead < 0 {
		ahead = 0
	}
	return &queue.Status{
		TicketID: ticketID,
		Position: position,
		Cursor:   q.cursor,
		Ahead:    ahead,
		Admitted: position <= q.cursor,
	}
}

func (q *Queue) Advance(_ context.Context, n int64) error {
	if n <= 0 {
		return nil
	}
	q.mu.Lock()
	q.cursor += n
	if max := int64(len(q.tickets)); q.cursor > max {
		q.cursor = max
	}
	q.mu.Unlock()
	return nil
}

func (q *Queue) Size(_ context.Context) (int64, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return int64(len(q.tickets)), nil
}

// Proof returns the per-ticket cryptographic proof (Ed25519 and ECVRF
// modes). The caller can verify it with VerifyEd25519 or VerifyECVRF.
func (q *Queue) Proof(ticketID string) ([]byte, error) {
	if q.mode != ModeEd25519 && q.mode != ModeECVRF {
		return nil, ErrUnknownProof
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	r, ok := q.tickets[ticketID]
	if !ok {
		return nil, queue.ErrUnknownTicket
	}
	out := make([]byte, len(r.proof))
	copy(out, r.proof)
	return out, nil
}

// VerifyECVRF reconstructs the score for a ticket given the operator's
// ECVRF public-key bytes, the ticket ID, and the per-ticket ECVRF proof.
// Returns (score, true) on a valid proof; (0, false) otherwise.
func VerifyECVRF(pubKeyBytes []byte, ticketID string, proof []byte) (uint64, bool) {
	pub, err := pmecvrf.NewPublicKey(pubKeyBytes)
	if err != nil {
		return 0, false
	}
	ok, vrfOut, err := pub.Verify([]byte(ticketID), proof)
	if err != nil || !ok || len(vrfOut) < 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(vrfOut[:8]), true
}

// VerifyEd25519 reconstructs the score for a ticket given the operator's
// public key, ticket ID, and signature proof. Returns (score, true) if the
// signature is valid; (0, false) otherwise.
func VerifyEd25519(pubKey ed25519.PublicKey, ticketID string, proof []byte) (uint64, bool) {
	if len(proof) != ed25519.SignatureSize {
		return 0, false
	}
	if !ed25519.Verify(pubKey, []byte(ticketID), proof) {
		return 0, false
	}
	return binary.BigEndian.Uint64(proof[:8]), true
}

// ScoreSeed is exported so seed-mode auditors can replicate position
// derivation client-side after the seed is revealed.
func ScoreSeed(seed []byte, ticketID string) uint64 {
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte(ticketID))
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}

type Entry struct {
	TicketID string
	Score    uint64
	Position int64
}

// Export returns the full ticket list sorted by score (and ID as tiebreak).
func (q *Queue) Export() []Entry {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.exportLocked()
}

type sortableEntry struct {
	Entry
	preQueue bool
	seq      int64
}

func (q *Queue) exportLocked() []Entry {
	all := make([]sortableEntry, 0, len(q.tickets))
	for id, r := range q.tickets {
		all = append(all, sortableEntry{
			Entry:    Entry{TicketID: id, Score: r.score},
			preQueue: r.preQueue,
			seq:      r.seq,
		})
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.preQueue != b.preQueue {
			return a.preQueue // pre-queue comes before post-open
		}
		if a.preQueue {
			if a.Score != b.Score {
				return a.Score < b.Score
			}
			return a.TicketID < b.TicketID
		}
		// both post-open: order by sequence number
		return a.seq < b.seq
	})
	out := make([]Entry, len(all))
	for i, e := range all {
		e.Position = int64(i + 1)
		out[i] = e.Entry
	}
	return out
}

