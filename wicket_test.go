package wicket

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/Supawitk/wicket/pkg/challenger"
	"github.com/Supawitk/wicket/pkg/challenger/pow"
	"github.com/Supawitk/wicket/pkg/circuit"
	"github.com/Supawitk/wicket/pkg/metrics"
	"github.com/Supawitk/wicket/pkg/queue/vrf"
	"github.com/Supawitk/wicket/pkg/ratelimit"
	"github.com/Supawitk/wicket/pkg/store/memory"
)

func TestWrapPassThrough(t *testing.T) {
	w := New()
	srv := httptest.NewServer(w.Wrap(http.HandlerFunc(okHandler)))
	defer srv.Close()
	res, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestWrapEnforcesRateLimit(t *testing.T) {
	w := New(WithLimiter(ratelimit.New(ratelimit.Config{Rate: 1, Burst: 1})))
	srv := httptest.NewServer(w.Wrap(http.HandlerFunc(okHandler)))
	defer srv.Close()

	res, _ := http.Get(srv.URL)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first request status %d", res.StatusCode)
	}
	res, _ = http.Get(srv.URL)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on second request, got %d", res.StatusCode)
	}
}

func TestWrapBreakerOpensOnFailures(t *testing.T) {
	cfg := circuit.DefaultConfig()
	cfg.MinSamples = 2
	cfg.FailureRatio = 0.5
	cfg.Cooldown = time.Hour
	w := New(WithCircuitBreaker(circuit.New(cfg)))

	srv := httptest.NewServer(w.Wrap(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	})))
	defer srv.Close()

	for i := 0; i < 2; i++ {
		res, _ := http.Get(srv.URL)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusInternalServerError {
			t.Fatalf("step %d: status %d", i, res.StatusCode)
		}
	}
	res, _ := http.Get(srv.URL)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 once breaker open, got %d", res.StatusCode)
	}
}

func TestAdminChallengeAndSolve(t *testing.T) {
	w := New(WithPoW(pow.New(memory.New(), lowDifficultyPoWConfig())))
	srv := httptest.NewServer(w.AdminHandler())
	defer srv.Close()

	res, err := http.Post(srv.URL+"/challenge", "application/json", nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("issue status %d body %s", res.StatusCode, body)
	}
	var ch challengeResponse
	if err := json.Unmarshal(body, &ch); err != nil {
		t.Fatalf("decode: %v", err)
	}

	payload, _ := hex.DecodeString(ch.Payload)
	nonce := pow.Solve(payload, ch.Difficulty)

	solveBody, _ := json.Marshal(solveRequest{ID: ch.ID, Nonce: hex.EncodeToString(nonce)})
	res, err = http.Post(srv.URL+"/solve", "application/json", bytes.NewReader(solveBody))
	if err != nil {
		t.Fatalf("solve: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("solve status %d body %s", res.StatusCode, b)
	}
	var sr solveResponse
	if err := json.NewDecoder(res.Body).Decode(&sr); err != nil {
		t.Fatalf("decode solve: %v", err)
	}
	if !sr.OK {
		t.Fatal("solve.OK = false")
	}
}

func TestAdminSolveRejectsBadNonce(t *testing.T) {
	w := New(WithPoW(pow.New(memory.New(), lowDifficultyPoWConfig())))
	srv := httptest.NewServer(w.AdminHandler())
	defer srv.Close()

	ctx := context.Background()
	ch, _ := w.challenger.Issue(ctx, challenger.Hint{})

	solveBody, _ := json.Marshal(solveRequest{ID: ch.ID, Nonce: "00"})
	res, err := http.Post(srv.URL+"/solve", "application/json", bytes.NewReader(solveBody))
	if err != nil {
		t.Fatalf("post solve: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}
}

func TestAdminQueueRoundTrip(t *testing.T) {
	q, _ := vrf.New(vrf.Config{Seed: []byte("test-seed")})
	w := New(WithQueue(q))
	srv := httptest.NewServer(w.AdminHandler())
	defer srv.Close()

	res, err := http.Post(srv.URL+"/enqueue", "application/json", nil)
	if err != nil {
		t.Fatalf("post enqueue: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enqueue: %d", res.StatusCode)
	}
	var er enqueueResponse
	if err := json.NewDecoder(res.Body).Decode(&er); err != nil {
		t.Fatalf("decode enqueue: %v", err)
	}
	if er.TicketID == "" {
		t.Fatal("empty ticket id")
	}

	res2, err := http.Get(srv.URL + "/status?ticket=" + er.TicketID)
	if err != nil {
		t.Fatalf("get status: %v", err)
	}
	defer res2.Body.Close()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", res2.StatusCode)
	}
	var sr statusResponse
	if err := json.NewDecoder(res2.Body).Decode(&sr); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if sr.TicketID != er.TicketID {
		t.Fatalf("ticket id mismatch")
	}
	if sr.Position < 1 {
		t.Fatalf("position %d", sr.Position)
	}
}

func TestAdminStatusUnknownTicket(t *testing.T) {
	q, _ := vrf.New(vrf.Config{Seed: []byte("test")})
	w := New(WithQueue(q))
	srv := httptest.NewServer(w.AdminHandler())
	defer srv.Close()
	res, err := http.Get(srv.URL + "/status?ticket=nope")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.StatusCode)
	}
}

func TestAdminEndpointsReturn404WhenNotConfigured(t *testing.T) {
	w := New()
	srv := httptest.NewServer(w.AdminHandler())
	defer srv.Close()
	cases := []struct {
		method, path string
	}{
		{http.MethodPost, "/challenge"},
		{http.MethodPost, "/solve"},
		{http.MethodPost, "/enqueue"},
		{http.MethodGet, "/status?ticket=x"},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(c.method, srv.URL+c.path, strings.NewReader("{}"))
		res, _ := http.DefaultClient.Do(req)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: status %d want 404", c.method, c.path, res.StatusCode)
		}
	}
}

func TestDefaultKey(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://x/", nil)
	r.RemoteAddr = "192.0.2.5:54321"
	if k := defaultKey(r); k != "192.0.2.5" {
		t.Fatalf("got %q", k)
	}
	r.RemoteAddr = ""
	if k := defaultKey(r); k != "unknown" {
		t.Fatalf("empty addr got %q", k)
	}
}

func TestErrorsAreExported(t *testing.T) {
	// Sanity: errors from sub-packages should be wrappable.
	if !errors.Is(challenger.ErrInvalidSolution, challenger.ErrInvalidSolution) {
		t.Fatal("errors.Is broken")
	}
}

func TestWrapEmitsMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewWith(reg)
	w := New(
		WithLimiter(ratelimit.New(ratelimit.Config{Rate: 1, Burst: 1})),
		WithMetrics(m),
	)
	srv := httptest.NewServer(w.Wrap(http.HandlerFunc(okHandler)))
	defer srv.Close()

	res, _ := http.Get(srv.URL)
	_ = res.Body.Close()
	res, _ = http.Get(srv.URL) // expect 429
	_ = res.Body.Close()

	if got := testutil.ToFloat64(m.RequestsTotal.WithLabelValues(metrics.OutcomeAdmitted)); got != 1 {
		t.Errorf("admitted = %v want 1", got)
	}
	if got := testutil.ToFloat64(m.RequestsTotal.WithLabelValues(metrics.OutcomeRateLimited)); got != 1 {
		t.Errorf("rate_limited = %v want 1", got)
	}
}

func TestWrapWithTracerStillServes(t *testing.T) {
	w := New(WithTracer(noop.NewTracerProvider().Tracer("test")))
	srv := httptest.NewServer(w.Wrap(http.HandlerFunc(okHandler)))
	defer srv.Close()
	res, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
}

func TestAdminMetricsForChallenges(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewWith(reg)
	w := New(WithPoW(pow.New(memory.New(), lowDifficultyPoWConfig())), WithMetrics(m))
	srv := httptest.NewServer(w.AdminHandler())
	defer srv.Close()

	res, _ := http.Post(srv.URL+"/challenge", "application/json", nil)
	_ = res.Body.Close()
	if got := testutil.ToFloat64(m.ChallengeIssued); got != 1 {
		t.Errorf("issued = %v want 1", got)
	}

	// Bad nonce should record an invalid verify.
	body, _ := json.Marshal(solveRequest{ID: "unknown", Nonce: "00"})
	res, _ = http.Post(srv.URL+"/solve", "application/json", bytes.NewReader(body))
	_ = res.Body.Close()
	if got := testutil.ToFloat64(m.ChallengeVerified.WithLabelValues(metrics.ChallengeUnknown)); got != 1 {
		t.Errorf("unknown verifies = %v want 1", got)
	}
}

// TestWrapConcurrentRequests fires many concurrent requests through Wrap
// with both a rate limiter and a breaker installed. Under -race this
// surfaces any unsynchronised access to the limiter map, breaker state,
// or the statusRecorder. The exact admit/deny split is asserted: with a
// frozen-burst limiter we know precisely how many requests can pass.
func TestWrapConcurrentRequests(t *testing.T) {
	const goroutines = 1000
	const burst = 50

	now := time.Unix(0, 0)
	lim := ratelimit.New(ratelimit.Config{Rate: 1, Burst: burst, Now: func() time.Time { return now }})

	w := New(
		WithLimiter(lim),
		WithCircuitBreaker(circuit.New(circuit.DefaultConfig())),
		WithKeyFunc(func(r *http.Request) string { return "shared" }),
	)
	srv := httptest.NewServer(w.Wrap(http.HandlerFunc(okHandler)))
	defer srv.Close()

	var admitted, throttled int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			res, err := http.Get(srv.URL)
			if err != nil {
				return
			}
			_ = res.Body.Close()
			switch res.StatusCode {
			case http.StatusOK:
				atomic.AddInt64(&admitted, 1)
			case http.StatusTooManyRequests:
				atomic.AddInt64(&throttled, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if admitted != burst {
		t.Fatalf("admitted=%d, want exactly %d (burst)", admitted, burst)
	}
	if admitted+throttled != goroutines {
		t.Fatalf("admitted+throttled=%d, want %d", admitted+throttled, goroutines)
	}
}

func TestProxyAwareKey(t *testing.T) {
	cases := []struct {
		name        string
		hops        int
		xff         string
		remote      string
		want        string
	}{
		{"single-hop", 1, "203.0.113.5, 10.0.0.1", "10.0.0.1:443", "10.0.0.1"},
		{"two-hop", 2, "203.0.113.5, 10.0.0.1, 10.0.0.2", "10.0.0.2:443", "10.0.0.1"},
		{"missing-xff falls back to remote", 1, "", "192.0.2.7:1234", "192.0.2.7"},
		{"too-few-hops falls back", 5, "203.0.113.5, 10.0.0.1", "10.0.0.1:443", "10.0.0.1"},
		{"single-entry", 1, "203.0.113.5", "10.0.0.1:443", "203.0.113.5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fn := ProxyAwareKey(c.hops)
			r, _ := http.NewRequest("GET", "http://x/", nil)
			r.RemoteAddr = c.remote
			if c.xff != "" {
				r.Header.Set("X-Forwarded-For", c.xff)
			}
			if got := fn(r); got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func okHandler(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte("ok"))
}

func lowDifficultyPoWConfig() pow.Config {
	c := pow.DefaultConfig()
	c.BaseDifficulty = 6
	c.MaxDifficulty = 8
	return c
}
