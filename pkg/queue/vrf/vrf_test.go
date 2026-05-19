package vrf

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Supawitk/wicket/pkg/queue"
)

func TestEd25519IsDefault(t *testing.T) {
	q, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if q.Mode() != ModeEd25519 {
		t.Fatalf("default mode = %v want Ed25519", q.Mode())
	}
	if q.PublicKey() == nil {
		t.Fatal("PublicKey() nil in Ed25519 mode")
	}
}

func TestSeedModeWhenSeedProvided(t *testing.T) {
	q, err := New(Config{Seed: []byte("hello")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if q.Mode() != ModeSeed {
		t.Fatalf("mode = %v want Seed", q.Mode())
	}
	want := sha256.Sum256([]byte("hello"))
	if q.Commitment() != want {
		t.Fatal("commitment mismatch")
	}
}

func TestPrivateKeyAndSeedMutuallyExclusive(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, err := New(Config{PrivateKey: priv, Seed: []byte("x")})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRevealSeedMode(t *testing.T) {
	q, _ := New(Config{Seed: []byte("hello")})
	got := q.Reveal()
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
	if !q.Revealed() {
		t.Fatal("Revealed() false after Reveal()")
	}
}

func TestECVRFModeRequestable(t *testing.T) {
	q, err := New(Config{UseECVRF: true})
	if err != nil {
		t.Fatalf("New ECVRF: %v", err)
	}
	if q.Mode() != ModeECVRF {
		t.Fatalf("mode = %v want ECVRF", q.Mode())
	}
	if len(q.ECVRFPublicKey()) == 0 {
		t.Fatal("ECVRFPublicKey empty")
	}
}

func TestECVRFProofVerifies(t *testing.T) {
	q, _ := New(Config{UseECVRF: true})
	ctx := context.Background()
	tk, err := q.Enqueue(ctx, "")
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	proof, err := q.Proof(tk.ID)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	score, ok := VerifyECVRF(q.ECVRFPublicKey(), tk.ID, proof)
	if !ok {
		t.Fatal("VerifyECVRF false")
	}
	if score == 0 {
		t.Fatal("zero score")
	}
}

func TestECVRFProofRejectsTampering(t *testing.T) {
	q, _ := New(Config{UseECVRF: true})
	ctx := context.Background()
	tk, _ := q.Enqueue(ctx, "")
	proof, _ := q.Proof(tk.ID)
	proof[0] ^= 0xff
	if _, ok := VerifyECVRF(q.ECVRFPublicKey(), tk.ID, proof); ok {
		t.Fatal("VerifyECVRF accepted tampered proof")
	}
}

func TestECVRFRejectsConflictingKeys(t *testing.T) {
	_, err := New(Config{UseECVRF: true, Seed: []byte("x")})
	if err == nil {
		t.Fatal("expected error for both UseECVRF and Seed")
	}
}

func TestRevealEd25519ModeIsNil(t *testing.T) {
	q, _ := New(Config{})
	if q.Reveal() != nil {
		t.Fatal("Reveal() should be nil in Ed25519 mode")
	}
}

func TestEd25519ProofVerifies(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	tk, _ := q.Enqueue(ctx, "")
	proof, err := q.Proof(tk.ID)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	score, ok := VerifyEd25519(q.PublicKey(), tk.ID, proof)
	if !ok {
		t.Fatal("VerifyEd25519 false")
	}
	if score == 0 {
		t.Fatal("zero score")
	}
}

func TestEd25519ProofRejectsTamperedProof(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	tk, _ := q.Enqueue(ctx, "")
	proof, _ := q.Proof(tk.ID)
	proof[0] ^= 0xff
	if _, ok := VerifyEd25519(q.PublicKey(), tk.ID, proof); ok {
		t.Fatal("VerifyEd25519 accepted tampered proof")
	}
}

func TestProofUnknownTicket(t *testing.T) {
	q, _ := New(Config{})
	if _, err := q.Proof("nope"); !errors.Is(err, queue.ErrUnknownTicket) {
		t.Fatalf("got %v want ErrUnknownTicket", err)
	}
}

func TestProofUnsupportedInSeedMode(t *testing.T) {
	q, _ := New(Config{Seed: []byte("x")})
	ctx := context.Background()
	tk, _ := q.Enqueue(ctx, "")
	if _, err := q.Proof(tk.ID); !errors.Is(err, ErrUnknownProof) {
		t.Fatalf("got %v want ErrUnknownProof", err)
	}
}

func TestSeedModeStillWorks(t *testing.T) {
	q, _ := New(Config{Seed: []byte("ordering")})
	ctx := context.Background()
	const N = 20
	var ids []string
	for i := 0; i < N; i++ {
		tk, _ := q.Enqueue(ctx, "")
		ids = append(ids, tk.ID)
	}
	seen := map[int64]bool{}
	for _, id := range ids {
		s, _ := q.Status(ctx, id)
		if seen[s.Position] {
			t.Fatalf("duplicate position %d", s.Position)
		}
		seen[s.Position] = true
	}
	if len(seen) != N {
		t.Fatalf("got %d positions", len(seen))
	}
}

func TestOpenSeparatesPreAndPostQueue(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()

	// 5 early arrivals before Open()
	pre := make([]string, 5)
	for i := range pre {
		tk, _ := q.Enqueue(ctx, "")
		pre[i] = tk.ID
	}

	q.Open()
	if !q.Opened() {
		t.Fatal("Opened() should be true after Open()")
	}

	// 5 late arrivals after Open()
	post := make([]string, 5)
	for i := range post {
		tk, _ := q.Enqueue(ctx, "")
		post[i] = tk.ID
	}

	// Every pre-queue ticket should rank ahead of every post-open ticket.
	preMaxPos := int64(0)
	for _, id := range pre {
		s, _ := q.Status(ctx, id)
		if s.Position > preMaxPos {
			preMaxPos = s.Position
		}
	}
	postMinPos := int64(1 << 30)
	for _, id := range post {
		s, _ := q.Status(ctx, id)
		if s.Position < postMinPos {
			postMinPos = s.Position
		}
	}
	if preMaxPos >= postMinPos {
		t.Fatalf("pre-queue max position %d should be < post-open min position %d", preMaxPos, postMinPos)
	}
}

func TestPostOpenOrderingIsFIFO(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	q.Open()
	ids := make([]string, 5)
	for i := range ids {
		tk, _ := q.Enqueue(ctx, "")
		ids[i] = tk.ID
	}
	for i, id := range ids {
		s, _ := q.Status(ctx, id)
		want := int64(i + 1)
		if s.Position != want {
			t.Fatalf("ticket %d position = %d want %d", i, s.Position, want)
		}
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	q, _ := New(Config{})
	q.Open()
	q.Open() // should not panic, not reset state
	if !q.Opened() {
		t.Fatal("Opened() false after double Open()")
	}
}

func TestEd25519PositionsAreUnique(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	const N = 50
	var ids []string
	for i := 0; i < N; i++ {
		tk, _ := q.Enqueue(ctx, "")
		ids = append(ids, tk.ID)
	}
	seen := map[int64]bool{}
	for _, id := range ids {
		s, _ := q.Status(ctx, id)
		if seen[s.Position] {
			t.Fatalf("duplicate position %d", s.Position)
		}
		if s.Position < 1 || s.Position > N {
			t.Fatalf("position %d out of range", s.Position)
		}
		seen[s.Position] = true
	}
}

func TestAdvanceAdmits(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	ids := make([]string, 5)
	for i := range ids {
		tk, _ := q.Enqueue(ctx, "")
		ids[i] = tk.ID
	}
	_ = q.Advance(ctx, 3)
	admitted := 0
	for _, id := range ids {
		s, _ := q.Status(ctx, id)
		if s.Admitted {
			admitted++
		}
	}
	if admitted != 3 {
		t.Fatalf("admitted = %d", admitted)
	}
}

func TestStatusUnknownTicket(t *testing.T) {
	q, _ := New(Config{})
	_, err := q.Status(context.Background(), "nope")
	if !errors.Is(err, queue.ErrUnknownTicket) {
		t.Fatalf("got %v", err)
	}
}

func TestExportInSeedMode(t *testing.T) {
	seed := []byte("audit-me")
	q, _ := New(Config{Seed: seed})
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		_, _ = q.Enqueue(ctx, "")
	}
	revealed := q.Reveal()
	entries := q.Export()
	for i, e := range entries {
		if ScoreSeed(revealed, e.TicketID) != e.Score {
			t.Fatalf("entry %d score mismatch", i)
		}
	}
}

func TestMerkleSingleEntry(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	tk, _ := q.Enqueue(ctx, "")
	log := q.Audit()
	if log.Root() == [32]byte{} {
		t.Fatal("zero root for single entry")
	}
	entry, path, err := log.Prove(tk.ID)
	if err != nil {
		t.Fatalf("Prove: %v", err)
	}
	if len(path) != 0 {
		t.Fatalf("path len = %d want 0 for single entry", len(path))
	}
	if !Verify(log.Root(), log.Size(), entry, path) {
		t.Fatal("Verify failed for single entry")
	}
}

func TestMerkleProofRoundTrip(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	ids := make([]string, 13)
	for i := range ids {
		tk, _ := q.Enqueue(ctx, "")
		ids[i] = tk.ID
	}
	log := q.Audit()
	root := log.Root()
	for _, id := range ids {
		entry, path, err := log.Prove(id)
		if err != nil {
			t.Fatalf("Prove(%s): %v", id, err)
		}
		if !Verify(root, log.Size(), entry, path) {
			t.Fatalf("Verify failed for %s", id)
		}
	}
}

func TestMerkleProofRejectsWrongRoot(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	tk, _ := q.Enqueue(ctx, "")
	_, _ = q.Enqueue(ctx, "")
	log := q.Audit()
	entry, path, _ := log.Prove(tk.ID)
	bogusRoot := [32]byte{0xff}
	if Verify(bogusRoot, log.Size(), entry, path) {
		t.Fatal("Verify accepted bogus root")
	}
}

func TestMerkleProofRejectsUnknownTicket(t *testing.T) {
	q, _ := New(Config{})
	_, _ = q.Enqueue(context.Background(), "")
	log := q.Audit()
	if _, _, err := log.Prove("missing"); !errors.Is(err, queue.ErrUnknownTicket) {
		t.Fatalf("got %v", err)
	}
}

func TestMerkleProofRejectsTamperedEntry(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	tk, _ := q.Enqueue(ctx, "")
	_, _ = q.Enqueue(ctx, "")
	log := q.Audit()
	entry, path, _ := log.Prove(tk.ID)
	entry.Score ^= 0xdeadbeef
	if Verify(log.Root(), log.Size(), entry, path) {
		t.Fatal("Verify accepted tampered entry")
	}
}

// TestVerifyRejectsPositionOutOfBounds is the regression test for the
// missing tree-size check. A forged proof that claims a position
// outside the committed tree must be rejected even when the chain of
// hashes happens to recover the published root.
func TestVerifyRejectsPositionOutOfBounds(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	tk, _ := q.Enqueue(ctx, "")
	_, _ = q.Enqueue(ctx, "")
	_, _ = q.Enqueue(ctx, "")
	log := q.Audit()
	entry, path, _ := log.Prove(tk.ID)

	tampered := entry
	tampered.Position = log.Size() + 1
	if Verify(log.Root(), log.Size(), tampered, path) {
		t.Fatal("Verify accepted out-of-bounds position")
	}
	tampered.Position = 0
	if Verify(log.Root(), log.Size(), tampered, path) {
		t.Fatal("Verify accepted zero position")
	}
}

// TestVerifyRejectsWrongPathLength rejects proofs whose path depth
// doesn't match the committed tree size.
func TestVerifyRejectsWrongPathLength(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	tk, _ := q.Enqueue(ctx, "")
	_, _ = q.Enqueue(ctx, "")
	log := q.Audit()
	entry, path, _ := log.Prove(tk.ID)

	tooLong := append([][32]byte{}, path...)
	tooLong = append(tooLong, [32]byte{})
	if Verify(log.Root(), log.Size(), entry, tooLong) {
		t.Fatal("Verify accepted over-long path")
	}
}

func TestSizeReportsTicketCount(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, _ = q.Enqueue(ctx, "")
	}
	n, err := q.Size(ctx)
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if n != 5 {
		t.Fatalf("Size = %d want 5", n)
	}
}

func TestAdvanceNoOpForNonPositive(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	_, _ = q.Enqueue(ctx, "")
	if err := q.Advance(ctx, 0); err != nil {
		t.Fatalf("Advance(0): %v", err)
	}
	if err := q.Advance(ctx, -3); err != nil {
		t.Fatalf("Advance(-3): %v", err)
	}
}

func TestPublicKeyNilInNonEd25519Modes(t *testing.T) {
	seedQ, _ := New(Config{Seed: []byte("s")})
	if seedQ.PublicKey() != nil {
		t.Fatal("PublicKey should be nil in seed mode")
	}
	ecvrfQ, _ := New(Config{UseECVRF: true})
	if ecvrfQ.PublicKey() != nil {
		t.Fatal("PublicKey should be nil in ECVRF mode")
	}
}

func TestECVRFPublicKeyNilInNonECVRFModes(t *testing.T) {
	edQ, _ := New(Config{})
	if edQ.ECVRFPublicKey() != nil {
		t.Fatal("ECVRFPublicKey should be nil in Ed25519 mode")
	}
	seedQ, _ := New(Config{Seed: []byte("s")})
	if seedQ.ECVRFPublicKey() != nil {
		t.Fatal("ECVRFPublicKey should be nil in seed mode")
	}
}

func TestVerifyEd25519RejectsWrongLengthProof(t *testing.T) {
	q, _ := New(Config{})
	if _, ok := VerifyEd25519(q.PublicKey(), "id", []byte{1, 2, 3}); ok {
		t.Fatal("VerifyEd25519 accepted short proof")
	}
}

func TestVerifyECVRFRejectsMalformedPubKey(t *testing.T) {
	if _, ok := VerifyECVRF([]byte{1, 2, 3}, "id", make([]byte, 80)); ok {
		t.Fatal("VerifyECVRF accepted malformed pubkey")
	}
}

func TestVerifyECVRFRejectsMalformedProof(t *testing.T) {
	q, _ := New(Config{UseECVRF: true})
	if _, ok := VerifyECVRF(q.ECVRFPublicKey(), "id", []byte{1, 2}); ok {
		t.Fatal("VerifyECVRF accepted short proof")
	}
}

func TestMerkleLogEntriesReturnsCopy(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, _ = q.Enqueue(ctx, "")
	}
	log := q.Audit()
	entries := log.Entries()
	if len(entries) != 3 {
		t.Fatalf("Entries() len = %d want 3", len(entries))
	}
	entries[0].TicketID = "tampered"
	again := log.Entries()
	if again[0].TicketID == "tampered" {
		t.Fatal("Entries() returned shared backing array")
	}
}

func TestExportOnEmptyQueue(t *testing.T) {
	q, _ := New(Config{})
	entries := q.Export()
	if len(entries) != 0 {
		t.Fatalf("empty queue export len = %d", len(entries))
	}
}

// TestStatusAfterOpenIsConstantTime is the regression test for the O(N)
// rank bug. With the old per-call rank, polling N tickets cost O(N²) total
// — a 1M-ticket drop with each user polling once would do 10¹² ops. With
// positions materialised at Open(), each Status query is a map lookup.
//
// We don't assert wall-clock time (CI is noisy). Instead we assert the
// total time stays within a sane envelope for N polls over N tickets. The
// old implementation would blow past this by orders of magnitude.
func TestStatusAfterOpenIsConstantTime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping heavy queue test in -short mode")
	}
	q, _ := New(Config{})
	ctx := context.Background()
	const N = 20_000

	ids := make([]string, 0, N)
	for i := 0; i < N; i++ {
		tk, err := q.Enqueue(ctx, "")
		if err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
		ids = append(ids, tk.ID)
	}
	q.Open()

	start := time.Now()
	for _, id := range ids {
		if _, err := q.Status(ctx, id); err != nil {
			t.Fatalf("Status: %v", err)
		}
	}
	elapsed := time.Since(start)

	// Per-call budget. 50µs is generous on any 2020+ laptop; the O(N²)
	// implementation would burn ~21ms per call at this N, blowing past
	// even a 1s total budget.
	perCall := elapsed / N
	if perCall > 50*time.Microsecond {
		t.Fatalf("avg Status time = %v over %d tickets, want <50µs (O(N) rank regression?)", perCall, N)
	}
}

// TestConcurrentStatusUsesRLock is the regression test for the global
// write-lock on Status: with the positions map already materialised,
// many goroutines calling Status concurrently must all observe correct
// results without serialising. The -race detector catches any unsafe
// access to the shared map; correctness of the returned positions
// confirms the RLock fast path returns the same answer as the locked
// rebuild.
func TestConcurrentStatusUsesRLock(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()

	const N = 500
	ids := make([]string, 0, N)
	want := make(map[string]int64, N)
	for i := 0; i < N; i++ {
		tk, err := q.Enqueue(ctx, "")
		if err != nil {
			t.Fatalf("Enqueue %d: %v", i, err)
		}
		ids = append(ids, tk.ID)
	}
	q.Open()
	// Snapshot the expected positions from a serial pass.
	for _, id := range ids {
		s, err := q.Status(ctx, id)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		want[id] = s.Position
	}

	const goroutines = 32
	const perGoroutine = 200
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errCh := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				id := ids[i%len(ids)]
				s, err := q.Status(ctx, id)
				if err != nil {
					errCh <- err
					return
				}
				if s.Position != want[id] {
					errCh <- fmt.Errorf("position drift for %s: got %d want %d", id, s.Position, want[id])
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

// TestStatusO1AfterEnqueueOpen exercises the incremental positions update:
// post-open Enqueue must place the new ticket at preCount + postSeq
// without forcing a rebuild.
func TestStatusO1AfterEnqueueOpen(t *testing.T) {
	q, _ := New(Config{})
	ctx := context.Background()

	preIDs := make([]string, 100)
	for i := range preIDs {
		tk, _ := q.Enqueue(ctx, "")
		preIDs[i] = tk.ID
	}
	q.Open()

	// Post-open: every new ticket should land at strictly increasing
	// positions starting from preCount+1, regardless of how Status is
	// interleaved.
	for i := 1; i <= 50; i++ {
		tk, _ := q.Enqueue(ctx, "")
		s, err := q.Status(ctx, tk.ID)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		want := int64(100 + i)
		if s.Position != want {
			t.Fatalf("position[%d] = %d want %d", i, s.Position, want)
		}
	}
}
