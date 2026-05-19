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
	m.RequestDuration.Observe(0.005)
	m.RequestDuration.Observe(0.05)
	mfs, _ := reg.Gather()
	for _, mf := range mfs {
		if mf.GetName() == "wicket_request_duration_seconds" {
			if len(mf.Metric) != 1 {
				t.Fatalf("histogram metric count = %d", len(mf.Metric))
			}
			if got := mf.Metric[0].GetHistogram().GetSampleCount(); got != 2 {
				t.Fatalf("sample count = %d", got)
			}
			return
		}
	}
	t.Fatal("histogram not found")
}
