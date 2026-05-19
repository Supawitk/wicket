// Package bench contains reproducible Go benchmarks for the Wicket
// admission pipeline. Run with:
//
//	go test -bench=. -benchmem ./bench/
//
// Numbers measured on the host running the benchmark; they are NOT a
// claim about absolute throughput. The benchmarks exist to detect
// regressions and to compare the relative cost of each layer (rate
// limit, breaker, PoW verify, VRF rank).
package bench

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Supawitk/wicket"
	"github.com/Supawitk/wicket/pkg/circuit"
	"github.com/Supawitk/wicket/pkg/queue/vrf"
	"github.com/Supawitk/wicket/pkg/ratelimit"
)

func emptyHandler(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
}

func BenchmarkBaseline(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(emptyHandler))
	defer srv.Close()
	client := srv.Client()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, _ := client.Get(srv.URL)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

func BenchmarkWrapRateLimitOnly(b *testing.B) {
	w := wicket.New(
		wicket.WithLimiter(ratelimit.New(ratelimit.Config{Rate: 1e9, Burst: 1e9})),
	)
	srv := httptest.NewServer(w.Wrap(http.HandlerFunc(emptyHandler)))
	defer srv.Close()
	client := srv.Client()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, _ := client.Get(srv.URL)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

func BenchmarkWrapFullStack(b *testing.B) {
	w := wicket.New(
		wicket.WithLimiter(ratelimit.New(ratelimit.Config{Rate: 1e9, Burst: 1e9})),
		wicket.WithCircuitBreaker(circuit.New(circuit.DefaultConfig())),
	)
	srv := httptest.NewServer(w.Wrap(http.HandlerFunc(emptyHandler)))
	defer srv.Close()
	client := srv.Client()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, _ := client.Get(srv.URL)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

func BenchmarkVRFEnqueueEd25519(b *testing.B) {
	q, _ := vrf.New(vrf.Config{})
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = q.Enqueue(ctx, "")
	}
}

func BenchmarkVRFEnqueueSeed(b *testing.B) {
	q, _ := vrf.New(vrf.Config{Seed: []byte("bench-seed")})
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = q.Enqueue(ctx, "")
	}
}

func BenchmarkVRFEnqueueECVRF(b *testing.B) {
	q, _ := vrf.New(vrf.Config{UseECVRF: true})
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = q.Enqueue(ctx, "")
	}
}

func BenchmarkVRFStatusRank1000(b *testing.B) {
	q, _ := vrf.New(vrf.Config{})
	ctx := context.Background()
	ids := make([]string, 1000)
	for i := range ids {
		tk, _ := q.Enqueue(ctx, "")
		ids[i] = tk.ID
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = q.Status(ctx, ids[i%len(ids)])
	}
}

func BenchmarkEd25519Verify(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("benchmark-message")
	sig := ed25519.Sign(priv, msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Verify(pub, msg, sig)
	}
}

func BenchmarkMerkleAuditAndProve(b *testing.B) {
	q, _ := vrf.New(vrf.Config{})
	ctx := context.Background()
	ids := make([]string, 1000)
	for i := range ids {
		tk, _ := q.Enqueue(ctx, "")
		ids[i] = tk.ID
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log := q.Audit()
		_, _, _ = log.Prove(ids[i%len(ids)])
	}
}
