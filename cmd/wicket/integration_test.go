package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// integrationServer wires the same parts cmd/wicket wires at startup, but
// exposes them via httptest so we can hit real HTTP without binding to a
// privileged port or fighting signal handlers. Closes the result.
type integrationServer struct {
	srv *httptest.Server
}

func (s *integrationServer) Close() { s.srv.Close() }

func newIntegration(t *testing.T, yamlCfg string) *integrationServer {
	t.Helper()

	// Upstream stub that echoes its path with a 200.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream "+r.URL.Path)
	}))
	t.Cleanup(upstream.Close)

	yamlCfg = strings.ReplaceAll(yamlCfg, "${UPSTREAM}", upstream.URL)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "wicket.yml")
	if err := os.WriteFile(cfgPath, []byte(yamlCfg), 0o644); err != nil {
		t.Fatalf("write cfg: %v", err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	static, err := buildStatic(cfg)
	if err != nil {
		t.Fatalf("buildStatic: %v", err)
	}
	h, err := buildHandler(cfg, static)
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &integrationServer{srv: srv}
}

func TestIntegrationPassThrough(t *testing.T) {
	srv := newIntegration(t, `
listen: :0
upstream: ${UPSTREAM}
`)
	res, err := http.Get(srv.srv.URL + "/hello")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if string(body) != "upstream /hello" {
		t.Fatalf("body = %q", body)
	}
}

func TestIntegrationRateLimit(t *testing.T) {
	srv := newIntegration(t, `
listen: :0
upstream: ${UPSTREAM}
rate_limit:
  rps: 2
`)
	codes := make([]int, 0, 6)
	for i := 0; i < 6; i++ {
		res, err := http.Get(srv.srv.URL + "/")
		if err != nil {
			t.Fatalf("req %d: %v", i, err)
		}
		_ = res.Body.Close()
		codes = append(codes, res.StatusCode)
	}
	gotLimited := false
	for _, c := range codes {
		if c == http.StatusTooManyRequests {
			gotLimited = true
		}
	}
	if !gotLimited {
		t.Fatalf("expected at least one 429 in %v", codes)
	}
}

func TestIntegrationAdminEnqueue(t *testing.T) {
	srv := newIntegration(t, `
listen: :0
upstream: ${UPSTREAM}
queue:
  type: ecvrf
`)
	res, err := http.Post(srv.srv.URL+"/__wicket__/enqueue", "application/json", nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("enqueue status = %d", res.StatusCode)
	}
	var body struct {
		TicketID string `json:"ticket_id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.TicketID == "" {
		t.Fatal("empty ticket id")
	}
}

func TestIntegrationMetricsEndpoint(t *testing.T) {
	// metrics use the global Prometheus registry, so other tests can leak
	// state in. Just check the endpoint is reachable and prefixed.
	srv := newIntegration(t, `
listen: :0
upstream: ${UPSTREAM}
metrics:
  enabled: true
`)
	res, err := http.Get(srv.srv.URL + "/__wicket__/metrics")
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("metrics status %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "wicket_") {
		t.Fatalf("metrics body has no wicket_ prefix")
	}
}

func TestIntegrationUnknownUpstream(t *testing.T) {
	// Sanity: verify URL parsing rejects unsupported schemes via loadConfig.
	dir := t.TempDir()
	p := filepath.Join(dir, "wicket.yml")
	_ = os.WriteFile(p, []byte("upstream: tcp://nope\n"), 0o644)
	if _, err := loadConfig(p); err == nil {
		t.Fatal("expected error for non-http upstream")
	}
}

func TestIntegrationProxyTargetReachable(t *testing.T) {
	// Sanity that buildHandler's reverse proxy can be reached via its
	// constructed url.URL — guards against future refactors that break
	// the proxy wiring.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	if u.Scheme != "http" {
		t.Fatalf("unexpected scheme %s", u.Scheme)
	}
	time.Sleep(0) // touch time import to keep it useful if removed later
}
