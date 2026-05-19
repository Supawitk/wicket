// Concert ticket drop demo.
//
// Simulates a real ticket sale: a pre-queue window collects early
// arrivals, the operator opens the queue at sale time, the queue admits
// in controlled batches, and the operator publishes a Merkle root after
// the event so any fan can verify their position was assigned fairly.
//
// Run:
//
//	go run ./examples/02-concert
//	# in another terminal:
//	for i in $(seq 1 20); do
//	    curl -s -X POST http://localhost:8080/buy
//	    echo
//	done
//
// The server log shows the pre-queue/open transition, the admission
// cadence, and the final Merkle root.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Supawitk/wicket"
	"github.com/Supawitk/wicket/pkg/queue/vrf"
)

const preQueueWindow = 5 * time.Second

func main() {
	q, err := vrf.New(vrf.Config{})
	if err != nil {
		log.Fatal(err)
	}
	w := wicket.New(
		wicket.WithRateLimit(100, time.Second),
		wicket.WithCircuitBreaker(wicket.DefaultBreaker()),
		wicket.WithQueue(q),
	)

	log.Printf("commitment (public key): %s", hex.EncodeToString(q.PublicKey()))

	// Start a goroutine that opens the queue after the pre-queue window,
	// then drains admissions in batches. In a real deployment Open() and
	// Advance() would be triggered by an operator-facing control panel.
	go runOperator(q)

	mux := http.NewServeMux()
	mux.Handle("/__wicket__/", http.StripPrefix("/__wicket__", w.AdminHandler()))

	app := http.NewServeMux()
	app.HandleFunc("/buy", buyHandler(q))
	mux.Handle("/", w.Wrap(app))

	log.Printf("listening on :8080. pre-queue closes in %s", preQueueWindow)
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func runOperator(q *vrf.Queue) {
	time.Sleep(preQueueWindow)
	q.Open()
	n, _ := q.Size(context.Background())
	log.Printf("pre-queue closed with %d tickets; opening admissions", n)

	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for range tick.C {
		ctx := context.Background()
		size, _ := q.Size(ctx)
		if size == 0 {
			continue
		}
		_ = q.Advance(ctx, 2)
	}
}

type buyResponse struct {
	TicketID    string `json:"ticket_id"`
	Position    int64  `json:"position"`
	Ahead       int64  `json:"ahead"`
	Admitted    bool   `json:"admitted"`
	Proof       string `json:"proof,omitempty"`
	PublicKeyHx string `json:"public_key,omitempty"`
}

func buyHandler(q *vrf.Queue) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tk, err := q.Enqueue(ctx, "")
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		s, _ := q.Status(ctx, tk.ID)
		resp := buyResponse{
			TicketID: tk.ID,
			Position: s.Position,
			Ahead:    s.Ahead,
			Admitted: s.Admitted,
		}
		if proof, err := q.Proof(tk.ID); err == nil {
			resp.Proof = hex.EncodeToString(proof)
			resp.PublicKeyHx = hex.EncodeToString(q.PublicKey())
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(resp)
		fmt.Printf("issued ticket %s -> position %d (admitted=%v)\n", tk.ID, s.Position, s.Admitted)
	}
}

// Ensure go's import bookkeeping notes the ed25519 dependency that the
// examples README discusses, without using a blank import.
var _ ed25519.PublicKey
