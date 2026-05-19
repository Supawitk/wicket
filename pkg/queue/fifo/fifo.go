// Package fifo provides a first-come-first-served admission Queue.
//
// Each Enqueue allocates the next monotonic position. Advance bumps the
// admission cursor by n; a ticket is admitted once its position is at or
// before the cursor.
//
// Process-local state: tickets live in a map on the *Queue struct.
// Multi-replica sidecar deployments therefore require sticky load
// balancing so Enqueue and Status for the same client land on the same
// replica.
package fifo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/Supawitk/wicket/pkg/queue"
)

type Config struct {
	Now func() time.Time
}

type record struct {
	position int64
	issued   time.Time
}

type Queue struct {
	mu       sync.RWMutex
	now      func() time.Time
	tickets  map[string]record
	nextPos  int64
	cursor   int64
}

func New(cfg Config) *Queue {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Queue{
		now:     now,
		tickets: make(map[string]record),
	}
}

func (q *Queue) Enqueue(_ context.Context, _ string) (*queue.Ticket, error) {
	id, err := randomHex(12)
	if err != nil {
		return nil, err
	}
	q.mu.Lock()
	q.nextPos++
	pos := q.nextPos
	issued := q.now()
	q.tickets[id] = record{position: pos, issued: issued}
	q.mu.Unlock()
	return &queue.Ticket{ID: id, Issued: issued}, nil
}

func (q *Queue) Status(_ context.Context, ticketID string) (*queue.Status, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	r, ok := q.tickets[ticketID]
	if !ok {
		return nil, queue.ErrUnknownTicket
	}
	ahead := r.position - q.cursor - 1
	if ahead < 0 {
		ahead = 0
	}
	return &queue.Status{
		TicketID: ticketID,
		Position: r.position,
		Cursor:   q.cursor,
		Ahead:    ahead,
		Admitted: r.position <= q.cursor,
	}, nil
}

func (q *Queue) Advance(_ context.Context, n int64) error {
	if n <= 0 {
		return nil
	}
	q.mu.Lock()
	q.cursor += n
	if q.cursor > q.nextPos {
		q.cursor = q.nextPos
	}
	q.mu.Unlock()
	return nil
}

func (q *Queue) Size(_ context.Context) (int64, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return int64(len(q.tickets)), nil
}

// Delete removes a ticket. The numbering of remaining tickets is not
// re-packed; their absolute positions stay stable so a downstream
// status poll still resolves to the same place in line.
func (q *Queue) Delete(_ context.Context, ticketID string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.tickets[ticketID]; !ok {
		return queue.ErrUnknownTicket
	}
	delete(q.tickets, ticketID)
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
