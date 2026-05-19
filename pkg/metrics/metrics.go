// Package metrics defines the Prometheus instrumentation surfaced by Wicket.
//
// The default Metrics is registered against the global Prometheus
// registry. Tests and callers that need isolation can build a Metrics
// against a private *prometheus.Registry via NewWith.
package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	RequestsTotal      *prometheus.CounterVec
	RequestDuration    prometheus.Histogram
	BreakerState       prometheus.Gauge
	QueueSize          prometheus.Gauge
	QueueCursor        prometheus.Gauge
	ChallengeIssued    prometheus.Counter
	ChallengeVerified  *prometheus.CounterVec
	StoreDegraded      prometheus.Gauge
}

// Outcomes for RequestsTotal.
const (
	OutcomeAdmitted     = "admitted"
	OutcomeRateLimited  = "rate_limited"
	OutcomeBreakerOpen  = "breaker_open"
	OutcomeBackendError = "backend_error"
)

// ChallengeOutcome labels.
const (
	ChallengeOK             = "ok"
	ChallengeInvalid        = "invalid"
	ChallengeUnknown        = "unknown"
)

// New returns a Metrics registered on the default Prometheus registry.
func New() *Metrics { return NewWith(prometheus.DefaultRegisterer) }

// NewWith returns a Metrics registered on a custom registerer. Useful for
// tests that need isolation and for embedding Wicket in apps with their
// own registry.
func NewWith(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "wicket",
			Name:      "requests_total",
			Help:      "Requests classified by Wicket outcome.",
		}, []string{"outcome"}),
		RequestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "wicket",
			Name:      "request_duration_seconds",
			Help:      "Latency of the admission pipeline plus the wrapped handler.",
			Buckets:   prometheus.DefBuckets,
		}),
		BreakerState: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "wicket",
			Name:      "breaker_state",
			Help:      "Circuit breaker state: 0 closed, 1 half-open, 2 open.",
		}),
		QueueSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "wicket",
			Name:      "queue_size",
			Help:      "Number of tickets currently in the admission queue.",
		}),
		QueueCursor: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "wicket",
			Name:      "queue_cursor",
			Help:      "Admission cursor; tickets at or before this position are admitted.",
		}),
		ChallengeIssued: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "wicket",
			Name:      "challenge_issued_total",
			Help:      "Total proof-of-work challenges issued.",
		}),
		ChallengeVerified: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "wicket",
			Name:      "challenge_verified_total",
			Help:      "Proof-of-work verification attempts by outcome.",
		}, []string{"outcome"}),
		StoreDegraded: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "wicket",
			Name:      "store_degraded",
			Help:      "1 if the store wrapper is currently routing to fallback, else 0.",
		}),
	}
	if reg != nil {
		reg.MustRegister(
			m.RequestsTotal,
			m.RequestDuration,
			m.BreakerState,
			m.QueueSize,
			m.QueueCursor,
			m.ChallengeIssued,
			m.ChallengeVerified,
			m.StoreDegraded,
		)
	}
	return m
}
