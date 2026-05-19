// Package wicket is the admission control backbone.
//
// A Wicket bundles a rate limiter, a circuit breaker, an optional bot
// challenger, an optional admission queue, and an optional identity
// verifier into a composable HTTP middleware.
//
// Typical use:
//
//	w := wicket.New(
//	    wicket.WithRateLimit(100, time.Second),
//	    wicket.WithCircuitBreaker(wicket.DefaultBreaker()),
//	)
//	http.Handle("/__wicket__/", w.AdminHandler())
//	http.ListenAndServe(":8080", w.Wrap(appMux))
//
// The Wrap middleware enforces the rate limit and circuit breaker on every
// request and reports success/failure outcomes back to the breaker based
// on the response status. The AdminHandler exposes JSON endpoints for the
// challenger and queue (when configured) so a client-side script can solve
// challenges and poll queue status.
package wicket

import (
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/Supawitk/wicket/pkg/admission"
	"github.com/Supawitk/wicket/pkg/challenger"
	"github.com/Supawitk/wicket/pkg/challenger/pow"
	"github.com/Supawitk/wicket/pkg/circuit"
	"github.com/Supawitk/wicket/pkg/identity"
	"github.com/Supawitk/wicket/pkg/metrics"
	"github.com/Supawitk/wicket/pkg/queue"
	"github.com/Supawitk/wicket/pkg/ratelimit"
	"github.com/Supawitk/wicket/pkg/store/memory"
)

type Wicket struct {
	limiter    ratelimit.Limiter
	breaker    *circuit.Breaker
	challenger challenger.Challenger
	queue      queue.Queue
	identity   identity.Identity
	issuer     *admission.Issuer
	metrics    *metrics.Metrics
	tracer     trace.Tracer

	keyFn func(*http.Request) string
}

type Option func(*Wicket)

// WithRateLimit installs a per-key token bucket limiter. Burst defaults to
// rps if not explicitly set.
func WithRateLimit(rps float64, per time.Duration) Option {
	return func(w *Wicket) {
		rate := rps
		if per > 0 {
			rate = rps / per.Seconds()
		}
		w.limiter = ratelimit.New(ratelimit.Config{Rate: rate, Burst: rps})
	}
}

// WithLimiter installs a custom limiter (e.g. for tests or future backends).
func WithLimiter(l ratelimit.Limiter) Option {
	return func(w *Wicket) { w.limiter = l }
}

func WithCircuitBreaker(b *circuit.Breaker) Option {
	return func(w *Wicket) { w.breaker = b }
}

func WithPoW(c challenger.Challenger) Option {
	return func(w *Wicket) { w.challenger = c }
}

func WithQueue(q queue.Queue) Option {
	return func(w *Wicket) { w.queue = q }
}

func WithIdentity(i identity.Identity) Option {
	return func(w *Wicket) { w.identity = i }
}

// WithMetrics installs Prometheus instrumentation. Pass metrics.New() to
// register against the default global registry, or metrics.NewWith(reg)
// against a private registry.
func WithMetrics(m *metrics.Metrics) Option {
	return func(w *Wicket) { w.metrics = m }
}

// WithAdmissionIssuer attaches an admission.Issuer. When configured, the
// /solve admin endpoint mints a single-use, HMAC-signed token on a
// successful proof-of-work verification. Backends can validate the token
// with an admission.Verifier sharing the same secret.
func WithAdmissionIssuer(i *admission.Issuer) Option {
	return func(w *Wicket) { w.issuer = i }
}

// WithTracer installs an OpenTelemetry tracer that emits a span for every
// admission decision. Pass otel.Tracer("wicket") (or any wrapper). When
// nil (the default) no spans are recorded. Wrap is additionally wrapped
// in otelhttp.NewHandler so the propagated trace context flows through
// to the backend.
func WithTracer(t trace.Tracer) Option {
	return func(w *Wicket) { w.tracer = t }
}

// WithKeyFunc overrides how the limiter key is derived from a request.
// Default is the remote address (RemoteAddr stripped of port).
//
// This is the integration point for richer client fingerprints such as
// JA4+ TLS fingerprints (https://github.com/FoxIO-LLC/ja4). A front-end
// proxy or TLS-aware listener can attach the fingerprint to the request
// (e.g. as a header set by an Envoy filter or a custom net/http listener)
// and the KeyFunc can mix it into the rate-limit key:
//
//	wicket.WithKeyFunc(func(r *http.Request) string {
//	    ja4 := r.Header.Get("X-JA4")
//	    return r.Header.Get("X-Real-IP") + "|" + ja4
//	})
//
// This raises the cost of large-scale automation that rotates IPs but
// reuses the same TLS stack — a common pattern in 2026 botnets.
func WithKeyFunc(fn func(*http.Request) string) Option {
	return func(w *Wicket) { w.keyFn = fn }
}

// DefaultBreaker returns a circuit breaker with sensible production defaults.
func DefaultBreaker() *circuit.Breaker {
	return circuit.New(circuit.DefaultConfig())
}

// DefaultPoW returns an adaptive proof-of-work challenger backed by an
// in-memory store. Suitable for single-instance deployments and tests.
func DefaultPoW() challenger.Challenger {
	return pow.New(memory.New(), pow.DefaultConfig())
}

func New(opts ...Option) *Wicket {
	w := &Wicket{
		keyFn: defaultKey,
	}
	for _, o := range opts {
		o(w)
	}
	return w
}

func defaultKey(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		addr = addr[:i]
	}
	if addr == "" {
		return "unknown"
	}
	return addr
}

// Wrap returns an HTTP middleware that enforces the configured rate limit
// and circuit breaker around calls to the wrapped handler. When a tracer
// is configured, the handler is additionally wrapped in
// otelhttp.NewHandler so trace context propagates to the backend.
func (w *Wicket) Wrap(h http.Handler) http.Handler {
	core := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := r.Context()

		var span trace.Span
		if w.tracer != nil {
			ctx, span = w.tracer.Start(ctx, "wicket.admit")
			defer span.End()
			r = r.WithContext(ctx)
		}

		key := w.keyFn(r)

		if w.limiter != nil && !w.limiter.Allow(key) {
			w.recordOutcome(metrics.OutcomeRateLimited, start)
			if span != nil {
				span.SetAttributes(attribute.String("wicket.outcome", metrics.OutcomeRateLimited))
			}
			http.Error(rw, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		if w.breaker != nil {
			if err := w.breaker.Allow(); err != nil {
				w.recordOutcome(metrics.OutcomeBreakerOpen, start)
				if span != nil {
					span.SetAttributes(attribute.String("wicket.outcome", metrics.OutcomeBreakerOpen))
				}
				http.Error(rw, "service temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
		}

		sr := &statusRecorder{ResponseWriter: rw, status: http.StatusOK}
		h.ServeHTTP(sr, r)

		outcome := metrics.OutcomeAdmitted
		if w.breaker != nil {
			if sr.status >= 500 {
				w.breaker.RecordFailure()
				outcome = metrics.OutcomeBackendError
			} else {
				w.breaker.RecordSuccess()
			}
			if w.metrics != nil {
				w.metrics.BreakerState.Set(float64(w.breaker.State()))
			}
		} else if sr.status >= 500 {
			outcome = metrics.OutcomeBackendError
		}
		w.recordOutcome(outcome, start)
		if span != nil {
			span.SetAttributes(
				attribute.String("wicket.outcome", outcome),
				attribute.Int("http.status_code", sr.status),
			)
		}
	})
	if w.tracer != nil {
		return otelhttp.NewHandler(core, "wicket.wrap")
	}
	return core
}

func (w *Wicket) recordOutcome(outcome string, start time.Time) {
	if w.metrics == nil {
		return
	}
	w.metrics.RequestsTotal.WithLabelValues(outcome).Inc()
	w.metrics.RequestDuration.Observe(time.Since(start).Seconds())
}

// Challenger returns the configured bot challenger, or nil.
func (w *Wicket) Challenger() challenger.Challenger { return w.challenger }

// Queue returns the configured admission queue, or nil.
func (w *Wicket) Queue() queue.Queue { return w.queue }

// Identity returns the configured identity verifier, or nil.
func (w *Wicket) Identity() identity.Identity { return w.identity }

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.status = http.StatusOK
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}
