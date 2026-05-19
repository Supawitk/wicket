package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewWith(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewWith(reg)
	if m == nil {
		t.Fatal("nil metrics")
	}
	// MustRegister would panic if any collector conflicts.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(mfs) == 0 {
		t.Fatal("no metric families registered")
	}
}

func TestCountersAndGaugesIncrement(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewWith(reg)

	m.RequestsTotal.WithLabelValues(OutcomeAdmitted).Inc()
	m.RequestsTotal.WithLabelValues(OutcomeRateLimited).Inc()
	m.ChallengeIssued.Inc()
	m.ChallengeVerified.WithLabelValues(ChallengeOK).Inc()
	m.BreakerState.Set(1)
	m.QueueSize.Set(42)
	m.QueueCursor.Set(7)
	m.StoreDegraded.Set(1)

	if v := testutil.ToFloat64(m.RequestsTotal.WithLabelValues(OutcomeAdmitted)); v != 1 {
		t.Errorf("admitted = %v", v)
	}
	if v := testutil.ToFloat64(m.ChallengeIssued); v != 1 {
		t.Errorf("challenge issued = %v", v)
	}
	if v := testutil.ToFloat64(m.QueueSize); v != 42 {
		t.Errorf("queue size = %v", v)
	}
}

func TestRegisterNilReg(t *testing.T) {
	// nil registerer is allowed (caller manages registration manually).
	m := NewWith(nil)
	if m == nil || m.RequestsTotal == nil {
		t.Fatal("nil-reg path broken")
	}
}

func TestObserveHistogram(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewWith(reg)
	m.RequestDuration.WithLabelValues(OutcomeAdmitted).Observe(0.005)
	m.RequestDuration.WithLabelValues(OutcomeAdmitted).Observe(0.05)
	m.RequestDuration.WithLabelValues(OutcomeRateLimited).Observe(0.001)
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if mf.GetName() == "wicket_request_duration_seconds" {
			// One series per outcome label value observed.
			if len(mf.Metric) != 2 {
				t.Fatalf("histogram series count = %d want 2", len(mf.Metric))
			}
			var admitted, rateLimited uint64
			for _, met := range mf.Metric {
				for _, lp := range met.GetLabel() {
					if lp.GetName() != "outcome" {
						continue
					}
					switch lp.GetValue() {
					case OutcomeAdmitted:
						admitted = met.GetHistogram().GetSampleCount()
					case OutcomeRateLimited:
						rateLimited = met.GetHistogram().GetSampleCount()
					}
				}
			}
			if admitted != 2 || rateLimited != 1 {
				t.Fatalf("admitted=%d rateLimited=%d want 2/1", admitted, rateLimited)
			}
			return
		}
	}
	t.Fatal("histogram not found")
}
