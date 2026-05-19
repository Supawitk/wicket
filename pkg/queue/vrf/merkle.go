package vrf

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/Supawitk/wicket/pkg/queue"
)

// MerkleLog is a tamper-evident summary of every (ticketID, score) pair in
// the queue. Operators publish Root() and Size() after the event; any
// ticket holder can demand a Prove(ticketID) and verify inclusion with
// Verify against the public (root, size) pair.
//
// Including the size in Verify defends against a class of attacks where
// a malicious operator publishes a path that resolves to the root but
// claims a position outside the committed tree (e.g. position N+1
// derived by exploiting the duplicate-odd construction). Verifiers must
// reject any entry whose Position is outside [1, size].
type MerkleLog struct {
	entries []Entry
	leaves  [][32]byte
	root    [32]byte
}

// Audit builds a Merkle log from the current set of tickets.
func (q *Queue) Audit() *MerkleLog {
	q.mu.RLock()
	defer q.mu.RUnlock()
	entries := q.exportLocked()
	leaves := make([][32]byte, len(entries))
	for i, e := range entries {
		leaves[i] = leafHash(e)
	}
	return &MerkleLog{
		entries: entries,
		leaves:  leaves,
		root:    merkleRoot(leaves),
	}
}

// Root returns the Merkle root, suitable for public posting.
func (l *MerkleLog) Root() [32]byte { return l.root }

// Size returns the number of entries committed in the tree. Publish
// this alongside Root so verifiers can range-check claimed positions.
func (l *MerkleLog) Size() int64 { return int64(len(l.entries)) }

// Entries returns the full sorted ticket list. Useful when the operator
// wants to publish the entire export alongside the root.
func (l *MerkleLog) Entries() []Entry {
	out := make([]Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Prove returns a Merkle inclusion proof for ticketID. The path is the
// sibling hash at each level from leaf to root.
func (l *MerkleLog) Prove(ticketID string) (entry Entry, path [][32]byte, err error) {
	idx := -1
	for i, e := range l.entries {
		if e.TicketID == ticketID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Entry{}, nil, queue.ErrUnknownTicket
	}
	return l.entries[idx], merklePath(l.leaves, idx), nil
}

// Verify checks a Merkle inclusion proof against a published (root,
// size) pair.
//
// Given (root, size, entry, path) any party can confirm the entry was
// committed without holding the full ticket list. The size bound is
// load-bearing: it rejects forged proofs that claim a position outside
// the committed tree but happen to chain to the published root via the
// duplicate-odd construction.
//
// The path length must match the depth of a tree of `size` leaves; a
// proof that walks more or fewer levels is rejected outright.
func Verify(root [32]byte, size int64, entry Entry, path [][32]byte) bool {
	if size <= 0 {
		return false
	}
	if entry.Position < 1 || entry.Position > size {
		return false
	}
	if expected := treeDepth(size); len(path) != expected {
		return false
	}
	cur := leafHash(entry)
	idx := entry.Position - 1
	for _, sibling := range path {
		if idx%2 == 0 {
			cur = nodeHash(cur, sibling)
		} else {
			cur = nodeHash(sibling, cur)
		}
		idx /= 2
	}
	return cur == root
}

// treeDepth returns the number of levels between a leaf and the root
// for a tree of size leaves under the duplicate-odd construction.
// size == 1 has depth 0 (the leaf IS the root).
func treeDepth(size int64) int {
	if size <= 1 {
		return 0
	}
	d := 0
	for n := size; n > 1; n = (n + 1) / 2 {
		d++
	}
	return d
}

func leafHash(e Entry) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00}) // domain separator for leaves
	h.Write([]byte(e.TicketID))
	var sb [8]byte
	binary.BigEndian.PutUint64(sb[:], e.Score)
	h.Write(sb[:])
	var posb [8]byte
	binary.BigEndian.PutUint64(posb[:], uint64(e.Position))
	h.Write(posb[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func nodeHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01}) // domain separator for internal nodes
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func merkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	level := make([][32]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, nodeHash(level[i], level[i+1]))
			} else {
				next = append(next, nodeHash(level[i], level[i])) // duplicate odd
			}
		}
		level = next
	}
	return level[0]
}

func merklePath(leaves [][32]byte, idx int) [][32]byte {
	if len(leaves) <= 1 {
		return nil
	}
	level := make([][32]byte, len(leaves))
	copy(level, leaves)
	var path [][32]byte
	for len(level) > 1 {
		var sibling [32]byte
		if idx%2 == 0 {
			if idx+1 < len(level) {
				sibling = level[idx+1]
			} else {
				sibling = level[idx]
			}
		} else {
			sibling = level[idx-1]
		}
		path = append(path, sibling)

		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, nodeHash(level[i], level[i+1]))
			} else {
				next = append(next, nodeHash(level[i], level[i]))
			}
		}
		level = next
		idx /= 2
	}
	return path
}

