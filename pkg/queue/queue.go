// Package queue defines the admission-queue abstraction.
//
// A Queue accepts visitors via Enqueue and reports their current status via
// Status. The caller (typically the Wicket HTTP middleware) advances the
// admission cursor as backend capacity allows; a ticket is "admitted" once
// its position is at or before the cursor.
//
// Two reference implementations live in subpackages:
//
//   - pkg/queue/fifo  — simple first-come-first-served.
//   - pkg/queue/vrf   — commit-reveal randomness producing a verifiable
//                       random permutation of tickets (the project's
//                       differentiating feature).
package queue

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnknownTicket = errors.New("queue: unknown ticket")
	ErrClosed        = errors.New("queue: closed")
)

type Ticket struct {
	ID     string
	Issued time.Time
}

type Status struct {
	TicketID string
	Position int64
	Cursor   int64
	Ahead    int64
	Admitted bool
}

type Queue interface {
	Enqueue(ctx context.Context, visitorID string) (*Ticket, error)
	Status(ctx context.Context, ticketID string) (*Status, error)
	Advance(ctx context.Context, n int64) error
	Size(ctx context.Context) (int64, error)
	// Delete removes a ticket from the queue. Returns ErrUnknownTicket
	// when the ID is not present. Implementations use this for
	// operator-initiated eviction (admin tools, delete-on-request) and
	// for capping memory in long-running deployments.
	Delete(ctx context.Context, ticketID string) error
}
