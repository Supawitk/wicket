// Minimal Wicket demo.
//
// Wraps a tiny handler with a rate limiter (5 req/s) and a circuit breaker,
// and exposes the admin endpoints (challenger + queue) under /__wicket__/.
//
//	go run ./examples/01-minimal
//	curl http://localhost:8080/
//	curl -X POST http://localhost:8080/__wicket__/challenge
//	curl -X POST http://localhost:8080/__wicket__/enqueue
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Supawitk/wicket"
	"github.com/Supawitk/wicket/pkg/queue/vrf"
)

func main() {
	q, err := vrf.New(vrf.Config{Seed: []byte("demo-seed-please-change")})
	if err != nil {
		log.Fatal(err)
	}

	w := wicket.New(
		wicket.WithRateLimit(5, time.Second),
		wicket.WithCircuitBreaker(wicket.DefaultBreaker()),
		wicket.WithPoW(wicket.DefaultPoW()),
		wicket.WithQueue(q),
	)

	app := http.NewServeMux()
	app.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(rw, "hello from upstream")
	})

	root := http.NewServeMux()
	root.Handle("/__wicket__/", http.StripPrefix("/__wicket__", w.AdminHandler()))
	root.Handle("/", w.Wrap(app))

	addr := ":8080"
	log.Printf("listening on %s (commit=%x)", addr, q.Commitment())
	log.Fatal(http.ListenAndServe(addr, root))
}
