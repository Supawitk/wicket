package fifo

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Supawitk/wicket/pkg/queue"
)

func TestEnqueueAssignsMonotonicPositions(t *testing.T) {
	q := New(Config{})
	ctx := context.Background()
	var positions []int64
	for i := 0; i < 5; i++ {
		tk, err := q.Enqueue(ctx, "visitor")
		if err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		s, _ := q.Status(ctx, tk.ID)
		positions = append(positions, s.Position)
	}
	for i := 1; i < len(positions); i++ {
		if positions[i] != positions[i-1]+1 {
			t.Fatalf("non-monotonic positions: %v", positions)
		}
	}
}

func TestStatusUnknownTicket(t *testing.T) {
	q := New(Config{})
	_, err := q.Status(context.Background(), "nope")
	if !errors.Is(err, queue.ErrUnknownTicket) {
		t.Fatalf("got %v want ErrUnknownTicket", err)
	}
}

func TestAdvanceAdmitsInOrder(t *testing.T) {
	q := New(Config{})
	ctx := context.Background()
	var ids []string
	for i := 0; i < 3; i++ {
		tk, _ := q.Enqueue(ctx, "")
		ids = append(ids, tk.ID)
	}
	for _, id := range ids {
		s, _ := q.Status(ctx, id)
		if s.Admitted {
			t.Fatalf("ticket %s admitted before advance", id)
		}
	}
	if err := q.Advance(ctx, 2); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	for i, id := range ids {
		s, _ := q.Status(ctx, id)
		want := i < 2
		if s.Admitted != want {
			t.Fatalf("ticket %d admitted=%v want %v (pos=%d cursor=%d)", i, s.Admitted, want, s.Position, s.Cursor)
		}
	}
}

func TestAheadComputation(t *testing.T) {
	q := New(Config{})
	ctx := context.Background()
	tk1, _ := q.Enqueue(ctx, "")
	tk2, _ := q.Enqueue(ctx, "")
	tk3, _ := q.Enqueue(ctx, "")

	s, _ := q.Status(ctx, tk3.ID)
	if s.Ahead != 2 {
		t.Fatalf("got Ahead=%d want 2", s.Ahead)
	}
	_ = q.Advance(ctx, 1)
	s, _ = q.Status(ctx, tk3.ID)
	if s.Ahead != 1 {
		t.Fatalf("after advance got Ahead=%d want 1", s.Ahead)
	}
	_ = q.Advance(ctx, 5) // over-advance
	s, _ = q.Status(ctx, tk3.ID)
	if s.Ahead != 0 || !s.Admitted {
		t.Fatalf("over-advance: ahead=%d admitted=%v", s.Ahead, s.Admitted)
	}
	_ = tk1
	_ = tk2
}

func TestSize(t *testing.T) {
	q := New(Config{})
	ctx := context.Background()
	for i := 0; i < 7; i++ {
		_, _ = q.Enqueue(ctx, "")
	}
	n, _ := q.Size(ctx)
	if n != 7 {
		t.Fatalf("size = %d want 7", n)
	}
}

func TestConcurrentEnqueue(t *testing.T) {
	q := New(Config{})
	ctx := context.Background()
	const N = 200
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, _ = q.Enqueue(ctx, "")
		}()
	}
	wg.Wait()
	n, _ := q.Size(ctx)
	if n != N {
		t.Fatalf("size = %d want %d", n, N)
	}
}
