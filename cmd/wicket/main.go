// Command wicket runs Wicket as a reverse-proxy sidecar in front of an
// upstream HTTP service. Configuration is read from a YAML file passed via
// the -config flag.
//
// The config file is watched via fsnotify. On change, the dynamic sections
// (rate_limit, circuit_breaker) are rebuilt atomically; other sections
// (listen, upstream, store, queue, pow, identity) require a restart and
// are logged as a warning if changed.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	yaml "gopkg.in/yaml.v3"

	"github.com/Supawitk/wicket"
	"github.com/Supawitk/wicket/pkg/challenger"
	"github.com/Supawitk/wicket/pkg/challenger/argon2"
	"github.com/Supawitk/wicket/pkg/challenger/pow"
	"github.com/Supawitk/wicket/pkg/circuit"
	"github.com/Supawitk/wicket/pkg/metrics"
	"github.com/Supawitk/wicket/pkg/queue"
	"github.com/Supawitk/wicket/pkg/queue/fifo"
	"github.com/Supawitk/wicket/pkg/queue/vrf"
	"github.com/Supawitk/wicket/pkg/ratelimit"
	"github.com/Supawitk/wicket/pkg/store"
	"github.com/Supawitk/wicket/pkg/store/memory"
	redisstore "github.com/Supawitk/wicket/pkg/store/redis"
)

type config struct {
	Listen   string `yaml:"listen"`
	Upstream string `yaml:"upstream"`

	PoW struct {
		Enabled        bool   `yaml:"enabled"`
		Algorithm      string `yaml:"algorithm"` // "sha256" (default) or "argon2id"
		BaseDifficulty int    `yaml:"base_difficulty"`
		MaxDifficulty  int    `yaml:"max_difficulty"`
		Argon2Memory   uint32 `yaml:"argon2_memory_kib"`
	} `yaml:"pow"`

	Queue struct {
		Type string `yaml:"type"`
		Seed string `yaml:"seed"`
	} `yaml:"queue"`

	RateLimit struct {
		RPS           float64       `yaml:"rps"`
		Burst         float64       `yaml:"burst"`
		IdleTTL       time.Duration `yaml:"idle_ttl"`
		SweepInterval time.Duration `yaml:"sweep_interval"`
	} `yaml:"rate_limit"`

	CircuitBreaker struct {
		FailureRatio  float64       `yaml:"failure_ratio"`
		MinSamples    int64         `yaml:"min_samples"`
		Cooldown      time.Duration `yaml:"cooldown"`
		HalfOpenMax   int64         `yaml:"half_open_max"`
		Window        time.Duration `yaml:"window"`
		WindowBuckets int           `yaml:"window_buckets"`
	} `yaml:"circuit_breaker"`

	Metrics struct {
		Enabled bool   `yaml:"enabled"`
		Path    string `yaml:"path"`
	} `yaml:"metrics"`

	Tracing struct {
		Enabled  bool    `yaml:"enabled"`
		Endpoint string  `yaml:"otlp_http_endpoint"` // e.g. http://otel-collector:4318
		Service  string  `yaml:"service_name"`
		// SamplingRatio is the fraction of root spans to record. Zero
		// (the default) means 1% (TraceIDRatioBased(0.01)); set to 1.0
		// to record every span, or to a negative value to fall back to
		// AlwaysOff. The sampler is ParentBased so a sampled parent
		// keeps its children sampled across propagation boundaries.
		SamplingRatio float64 `yaml:"sampling_ratio"`
	} `yaml:"tracing"`

	Store struct {
		// Backend selects the store implementation that backs the PoW
		// challenger and identity verifier. "" or "memory" keeps the
		// previous single-process semantics; "redis" lets multiple
		// sidecar replicas share state.
		Backend string `yaml:"backend"`
		Redis   struct {
			Addr     string `yaml:"addr"`
			Password string `yaml:"password"`
			DB       int    `yaml:"db"`
		} `yaml:"redis"`
	} `yaml:"store"`
}

// staticParts is what we build once at startup and never replace.
type staticParts struct {
	cfg            *config
	upstream       *url.URL
	chal           challenger.Challenger
	q              queue.Queue
	metrics        *metrics.Metrics
	tracer         trace.Tracer
	tracerProvider *sdktrace.TracerProvider
	store          store.Store

	// limiter is preserved across hot reloads so an in-flight rate-limit
	// attack cannot reset every token bucket by triggering a config
	// reload on an unrelated field. It is rebuilt only when the
	// rate_limit section itself changes.
	limiter   *ratelimit.TokenBucket
	limiterMu sync.Mutex
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("wicket", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to YAML config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return fmt.Errorf("-config is required")
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	static, err := buildStatic(cfg)
	if err != nil {
		return fmt.Errorf("build static: %w", err)
	}

	var handler atomic.Pointer[http.Handler]
	apply := func(c *config) error {
		h, err := buildHandler(c, static)
		if err != nil {
			return err
		}
		handler.Store(&h)
		return nil
	}
	if err := apply(cfg); err != nil {
		return err
	}

	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*handler.Load()).ServeHTTP(w, r)
	})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go watchConfig(ctx, *configPath, static, apply)

	srv := &http.Server{Addr: cfg.Listen, Handler: proxy}
	if srv.Addr == "" {
		srv.Addr = ":8080"
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = srv.Shutdown(shutdownCtx)
		if static.tracerProvider != nil {
			_ = static.tracerProvider.Shutdown(shutdownCtx)
		}
	}()

	log.Printf("wicket: listening on %s, upstream=%s", srv.Addr, cfg.Upstream)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func loadConfig(path string) (*config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if c.Upstream == "" {
		return nil, fmt.Errorf("upstream is required")
	}
	if !strings.HasPrefix(c.Upstream, "http://") && !strings.HasPrefix(c.Upstream, "https://") {
		return nil, fmt.Errorf("upstream must be http(s) url")
	}
	return &c, nil
}

func buildStatic(cfg *config) (*staticParts, error) {
	u, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream: %w", err)
	}

	st, err := buildStore(&cfg.Store)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	var chal challenger.Challenger
	if cfg.PoW.Enabled {
		switch cfg.PoW.Algorithm {
		case "argon2id":
			acfg := argon2.DefaultConfig()
			if cfg.PoW.BaseDifficulty > 0 {
				acfg.BaseZeroBytes = cfg.PoW.BaseDifficulty
			}
			if cfg.PoW.MaxDifficulty > 0 {
				acfg.MaxZeroBytes = cfg.PoW.MaxDifficulty
			}
			if cfg.PoW.Argon2Memory > 0 {
				acfg.Memory = cfg.PoW.Argon2Memory
			}
			chal = argon2.New(st, acfg)
		case "", "sha256":
			pcfg := pow.DefaultConfig()
			if cfg.PoW.BaseDifficulty > 0 {
				pcfg.BaseDifficulty = cfg.PoW.BaseDifficulty
			}
			if cfg.PoW.MaxDifficulty > 0 {
				pcfg.MaxDifficulty = cfg.PoW.MaxDifficulty
			}
			chal = pow.New(st, pcfg)
		default:
			return nil, fmt.Errorf("unknown pow.algorithm %q", cfg.PoW.Algorithm)
		}
	}

	var q queue.Queue
	if cfg.Queue.Type != "" {
		switch cfg.Queue.Type {
		case "fifo":
			q = fifo.New(fifo.Config{})
		case "vrf":
			vc := vrf.Config{}
			if cfg.Queue.Seed != "" {
				vc.Seed = []byte(cfg.Queue.Seed)
			}
			vq, err := vrf.New(vc)
			if err != nil {
				return nil, err
			}
			q = vq
		case "ecvrf":
			vq, err := vrf.New(vrf.Config{UseECVRF: true})
			if err != nil {
				return nil, err
			}
			q = vq
		default:
			return nil, fmt.Errorf("unknown queue.type %q", cfg.Queue.Type)
		}
	}

	var m *metrics.Metrics
	if cfg.Metrics.Enabled {
		m = metrics.New()
	}

	var tracer trace.Tracer
	var tp *sdktrace.TracerProvider
	if cfg.Tracing.Enabled {
		var err error
		tp, err = newTracerProvider(cfg.Tracing.Endpoint, cfg.Tracing.Service, cfg.Tracing.SamplingRatio)
		if err != nil {
			return nil, fmt.Errorf("tracing: %w", err)
		}
		otel.SetTracerProvider(tp)
		tracer = tp.Tracer("wicket")
	}

	return &staticParts{
		cfg:            cfg,
		upstream:       u,
		chal:           chal,
		q:              q,
		metrics:        m,
		tracer:         tracer,
		tracerProvider: tp,
		store:          st,
	}, nil
}

// buildStore constructs the store.Store backing PoW challenges (and, in
// the future, identity nullifiers). "redis" makes the sidecar usable
// horizontally — without it, two replicas serve disjoint challenge sets
// and the issue/verify round trip can land on the wrong replica.
func buildStore(cfg *struct {
	Backend string `yaml:"backend"`
	Redis   struct {
		Addr     string `yaml:"addr"`
		Password string `yaml:"password"`
		DB       int    `yaml:"db"`
	} `yaml:"redis"`
}) (store.Store, error) {
	switch cfg.Backend {
	case "", "memory":
		return memory.New(), nil
	case "redis":
		if cfg.Redis.Addr == "" {
			return nil, fmt.Errorf("store.redis.addr is required when backend=redis")
		}
		return redisstore.New(redisstore.Config{
			Addr:     cfg.Redis.Addr,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		}), nil
	default:
		return nil, fmt.Errorf("unknown store.backend %q", cfg.Backend)
	}
}

func newTracerProvider(endpoint, service string, samplingRatio float64) (*sdktrace.TracerProvider, error) {
	if endpoint == "" {
		// stdout fallback would be noisy; require an endpoint for now.
		return nil, fmt.Errorf("tracing.otlp_http_endpoint is required when tracing is enabled")
	}
	if service == "" {
		service = "wicket"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(endpoint),
	)
	if err != nil {
		return nil, err
	}
	// 100% sampling at high RPS overwhelms an OTLP collector. Default to
	// 1% via TraceIDRatioBased, wrap in ParentBased so a sampled upstream
	// keeps its descendants sampled across the boundary.
	var sampler sdktrace.Sampler
	switch {
	case samplingRatio < 0:
		sampler = sdktrace.NeverSample()
	case samplingRatio == 0:
		sampler = sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.01))
	case samplingRatio >= 1:
		sampler = sdktrace.ParentBased(sdktrace.AlwaysSample())
	default:
		sampler = sdktrace.ParentBased(sdktrace.TraceIDRatioBased(samplingRatio))
	}
	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithSampler(sampler),
	), nil
}

func buildHandler(cfg *config, static *staticParts) (http.Handler, error) {
	opts := []wicket.Option{}
	if cfg.RateLimit.RPS > 0 {
		// Reuse the existing limiter when the rate-limit section is
		// unchanged. Without this, every hot reload — even one that
		// only touches an unrelated section — would zero every token
		// bucket and let an in-flight rate-limit attack reset to a
		// fresh burst quota.
		limiter := getOrBuildLimiter(static, cfg.RateLimit)
		opts = append(opts, wicket.WithLimiter(limiter))
	} else {
		// RPS was set previously but is now zero: drop the cached
		// limiter so re-enabling later starts fresh with the new rate.
		clearLimiter(static)
	}
	if cfg.CircuitBreaker.FailureRatio > 0 || cfg.CircuitBreaker.MinSamples > 0 {
		bcfg := circuit.DefaultConfig()
		if cfg.CircuitBreaker.FailureRatio > 0 {
			bcfg.FailureRatio = cfg.CircuitBreaker.FailureRatio
		}
		if cfg.CircuitBreaker.MinSamples > 0 {
			bcfg.MinSamples = cfg.CircuitBreaker.MinSamples
		}
		if cfg.CircuitBreaker.Cooldown > 0 {
			bcfg.Cooldown = cfg.CircuitBreaker.Cooldown
		}
		if cfg.CircuitBreaker.HalfOpenMax > 0 {
			bcfg.HalfOpenMax = cfg.CircuitBreaker.HalfOpenMax
		}
		if cfg.CircuitBreaker.Window > 0 {
			bcfg.Window = cfg.CircuitBreaker.Window
		}
		if cfg.CircuitBreaker.WindowBuckets > 0 {
			bcfg.WindowBuckets = cfg.CircuitBreaker.WindowBuckets
		}
		opts = append(opts, wicket.WithCircuitBreaker(circuit.New(bcfg)))
	}
	if static.chal != nil {
		opts = append(opts, wicket.WithPoW(static.chal))
	}
	if static.q != nil {
		opts = append(opts, wicket.WithQueue(static.q))
	}
	if static.metrics != nil {
		opts = append(opts, wicket.WithMetrics(static.metrics))
	}
	if static.tracer != nil {
		opts = append(opts, wicket.WithTracer(static.tracer))
	}

	w := wicket.New(opts...)
	proxy := httputil.NewSingleHostReverseProxy(static.upstream)

	mux := http.NewServeMux()
	mux.Handle("/__wicket__/", http.StripPrefix("/__wicket__", w.AdminHandler()))
	if static.metrics != nil {
		mux.Handle("/__wicket__/metrics", promhttp.Handler())
	}
	mux.Handle("/", w.Wrap(proxy))
	return mux, nil
}

func watchConfig(ctx context.Context, path string, static *staticParts, apply func(*config) error) {
	// Watch the parent directory rather than the file itself. Editors that
	// save via atomic-rename (vim, k9s, anything using tempfile+rename) drop
	// the inode the file-watch is bound to; events for the new inode are
	// never delivered. Watching the directory and filtering by the absolute
	// file path catches Write, Create, Rename, and Remove uniformly.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("wicket: watcher init failed: %v (hot reload disabled)", err)
		return
	}
	defer watcher.Close()
	absPath, err := filepath.Abs(path)
	if err != nil {
		log.Printf("wicket: watcher abs path failed: %v (hot reload disabled)", err)
		return
	}
	dir := filepath.Dir(absPath)
	if err := watcher.Add(dir); err != nil {
		log.Printf("wicket: watcher add %s failed: %v (hot reload disabled)", dir, err)
		return
	}
	debounce := time.NewTimer(time.Hour)
	debounce.Stop()
	defer debounce.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			evAbs, _ := filepath.Abs(ev.Name)
			if evAbs != absPath {
				continue
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0 {
				debounce.Reset(200 * time.Millisecond)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("wicket: watcher error: %v", err)
		case <-debounce.C:
			newCfg, err := loadConfig(path)
			if err != nil {
				log.Printf("wicket: reload skipped: %v", err)
				continue
			}
			if changedStatic(static.cfg, newCfg) {
				log.Printf("wicket: static fields changed; restart required for: %s", staticDiff(static.cfg, newCfg))
			}
			if err := apply(newCfg); err != nil {
				log.Printf("wicket: reload apply failed: %v", err)
				continue
			}
			log.Printf("wicket: config reloaded from %s", path)
		}
	}
}

// getOrBuildLimiter returns the cached rate limiter when its config has
// not changed; otherwise it builds a new one. Returning the same
// *TokenBucket across reloads preserves every per-key bucket — without
// this, a hot reload during an attack hands every offender a fresh
// burst quota.
func getOrBuildLimiter(static *staticParts, rl struct {
	RPS           float64       `yaml:"rps"`
	Burst         float64       `yaml:"burst"`
	IdleTTL       time.Duration `yaml:"idle_ttl"`
	SweepInterval time.Duration `yaml:"sweep_interval"`
}) *ratelimit.TokenBucket {
	static.limiterMu.Lock()
	defer static.limiterMu.Unlock()

	lcfg := ratelimit.Config{
		Rate:          rl.RPS,
		Burst:         rl.Burst,
		IdleTTL:       rl.IdleTTL,
		SweepInterval: rl.SweepInterval,
	}
	if lcfg.Burst <= 0 {
		lcfg.Burst = lcfg.Rate
	}
	if static.limiter == nil || !sameLimiterCfg(static.cfg.RateLimit, rl) {
		static.limiter = ratelimit.New(lcfg)
	}
	// Snapshot the new rate-limit config so the next reload can compare.
	static.cfg.RateLimit = rl
	return static.limiter
}

func clearLimiter(static *staticParts) {
	static.limiterMu.Lock()
	defer static.limiterMu.Unlock()
	static.limiter = nil
}

func sameLimiterCfg(a, b struct {
	RPS           float64       `yaml:"rps"`
	Burst         float64       `yaml:"burst"`
	IdleTTL       time.Duration `yaml:"idle_ttl"`
	SweepInterval time.Duration `yaml:"sweep_interval"`
}) bool {
	return a.RPS == b.RPS &&
		a.Burst == b.Burst &&
		a.IdleTTL == b.IdleTTL &&
		a.SweepInterval == b.SweepInterval
}

// changedStatic reports whether any field that requires a restart
// differs between old and new configs.
func changedStatic(a, b *config) bool {
	return staticDiff(a, b) != ""
}

func staticDiff(a, b *config) string {
	var diffs []string
	if a.Listen != b.Listen {
		diffs = append(diffs, "listen")
	}
	if a.Upstream != b.Upstream {
		diffs = append(diffs, "upstream")
	}
	if a.PoW != b.PoW {
		diffs = append(diffs, "pow")
	}
	if a.Queue != b.Queue {
		diffs = append(diffs, "queue")
	}
	if a.Metrics != b.Metrics {
		diffs = append(diffs, "metrics")
	}
	if a.Store != b.Store {
		diffs = append(diffs, "store")
	}
	if a.Tracing != b.Tracing {
		diffs = append(diffs, "tracing")
	}
	return strings.Join(diffs, ",")
}
