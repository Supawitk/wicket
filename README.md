# Wicket

**Admission control backbone for Go.**

Verifiable-fair waiting room · Adaptive bot challenge · Circuit breaker · Rate limit · Pluggable identity.

[Quick Start](#quick-start) · [Features](#features) · [Architecture](#architecture) · [Tech Stack](#tech-stack)

---

## What is Wicket?

Wicket is a self-hosted admission control layer for Go services. It sits in front of your application and protects it from traffic bursts, bot abuse, and contention storms — without sending your traffic through a third party.

Use it as:

- **A library** — import `wicket` and wrap any `http.Handler`.
- **A sidecar** — run the `wicket` binary as a reverse proxy in front of any backend.

It bundles a queue, an adaptive proof-of-work challenge, a rate limiter, a circuit breaker, and a pluggable identity verifier behind one composable API.

---

## Features

- 🎟️ **Verifiable-fair queue** — two modes. Ed25519 mode (default) gives every ticket a per-ticket cryptographic proof a client can verify on its own. Seed mode supports classic commit-reveal with an externally-supplied seed.
- 🌳 **Merkle audit log** — operators publish a single 32-byte root after the event; any ticket holder can verify inclusion with an `O(log N)` proof.
- 🧠 **Adaptive proof-of-work** — SHA-256-based challenge with difficulty that scales with reported load.
- 🚦 **Rate limit + circuit breaker** — per-key token bucket and three-state breaker, composable as middleware.
- 🔌 **Pluggable identity** *(optional)* — ships with a passkey adapter (Ed25519-signed credentials) implementing the `identity.Identity` interface.
- 🪶 **Pluggable storage** — in-memory, Redis (and Redis-compatible: Dragonfly, Valkey, KeyDB), plus a `degrading` wrapper that falls back to in-memory if the primary store dies.
- 📈 **Prometheus metrics** — request outcomes, breaker state, queue size, challenge counters, store-degraded gauge, all on by default in the sidecar.
- 🔄 **Hot-reloadable config** — the sidecar watches its YAML file; dynamic sections (rate limit, breaker) reload without dropping in-flight requests.
- 📦 **Single binary sidecar** — `wicket -config wicket.yml` proxies any HTTP upstream.

---

## Quick Start

### As a library

```go
package main

import (
    "log"
    "net/http"
    "time"

    "github.com/Supawitk/wicket"
    "github.com/Supawitk/wicket/pkg/queue/vrf"
)

func main() {
    q, err := vrf.New(vrf.Config{Seed: []byte("concert-2026-05-19")})
    if err != nil {
        log.Fatal(err)
    }

    gate := wicket.New(
        wicket.WithPoW(wicket.DefaultPoW()),
        wicket.WithQueue(q),
        wicket.WithRateLimit(100, time.Second),
        wicket.WithCircuitBreaker(wicket.DefaultBreaker()),
    )

    app := http.NewServeMux()
    app.HandleFunc("/buy", buyHandler)

    root := http.NewServeMux()
    root.Handle("/__wicket__/", http.StripPrefix("/__wicket__", gate.AdminHandler()))
    root.Handle("/", gate.Wrap(app))

    log.Fatal(http.ListenAndServe(":8080", root))
}

func buyHandler(w http.ResponseWriter, r *http.Request) {
    // your application handler
}
```

### As a sidecar

```bash
go install github.com/Supawitk/wicket/cmd/wicket@latest
wicket -config wicket.yml
```

`wicket.yml`:

```yaml
listen: :8080
upstream: http://backend:3000

pow:
  enabled: true
  base_difficulty: 16
  max_difficulty: 24

queue:
  type: vrf
  # seed is optional. Omit to run in Ed25519 mode (default):
  #   each ticket gets a per-ticket signature proof.
  # Provide a seed for commit-reveal mode (e.g. drand-supplied).
  # seed: concert-2026-05-19

rate_limit:
  rps: 100
  # idle_ttl: 10m       # evict per-key buckets idle for this long (default 10m, -1 disables)
  # sweep_interval: 1m  # how often the sweep runs (default idle_ttl/10, capped at 1m)

circuit_breaker:
  failure_ratio: 0.5
  min_samples: 20
  cooldown: 30s
  half_open_max: 3
  # window: 10s         # rolling window over which the ratio is computed (default 10s)
  # window_buckets: 10  # subdivides the window for sub-second resolution (default 10)

metrics:
  enabled: true

tracing:
  enabled: false
  otlp_http_endpoint: http://otel-collector:4318
  service_name: wicket
```

The sidecar watches the YAML file. Changes to `rate_limit` and
`circuit_breaker` are applied without dropping in-flight requests; the
other sections require a restart.

### Deployment notes

- **Behind a load balancer / CDN.** The default rate-limit key is
  `RemoteAddr`. Behind a proxy that becomes the proxy's IP and every
  client collapses into one bucket. Use [`wicket.ProxyAwareKey`](wicket.go)
  to read `X-Forwarded-For` with a trusted-hop count:

  ```go
  wicket.WithKeyFunc(wicket.ProxyAwareKey(1)) // one trusted proxy in front
  ```

  Never set the hop count higher than the number of proxies you actually
  control — attackers can forge XFF entries below your trust boundary.

- **Mobile / carrier-NAT traffic.** Millions of users can share a handful
  of public IPs. Pure IP rate-limiting will fire on legitimate users.
  Prefer an identity-derived key (e.g. the passkey credential ID after
  sign-in) for those flows.

- **Real-Redis integration tests.** The shipped Redis test suite uses
  `miniredis` (a faithful in-process reimpl of the RESP protocol). To
  exercise the store against an actual `redis-server` or compatible
  engine (Dragonfly / Valkey / KeyDB), run:

  ```bash
  REDIS_ADDR=localhost:6379 go test -tags=integration -race ./pkg/store/redis/...
  ```

  CI runs this against a `redis:7-alpine` service container on every
  push.

Runnable demos:

- [examples/01-minimal](examples/01-minimal) — wrap a handler, expose admin endpoints.
- [examples/02-concert](examples/02-concert) — full ticket-drop simulation: pre-queue, open, batch admit, publish proofs.
- [examples/03-verifier](examples/03-verifier) — client-side CLI that verifies a per-ticket VRF proof against the operator's public key.

---

## Architecture

```
                    ┌─────────────┐
                    │   Client    │
                    └──────┬──────┘
                           │
                  ┌────────▼────────┐
                  │  Wicket Layer   │
                  │                 │
                  │  ┌───────────┐  │
                  │  │ Adaptive  │  │  bot resistance
                  │  │   PoW     │  │
                  │  └─────┬─────┘  │
                  │        │        │
                  │  ┌─────▼─────┐  │  optional: 1-of-1 enforcement
                  │  │ Identity  │  │
                  │  │ (plug-in) │  │
                  │  └─────┬─────┘  │
                  │        │        │
                  │  ┌─────▼─────┐  │  verifiable-fair admission
                  │  │ VRF Queue │  │
                  │  └─────┬─────┘  │
                  │        │        │
                  │  ┌─────▼─────┐  │  protect backend
                  │  │ Rate Lmt  │  │
                  │  │ + Breaker │  │
                  │  └─────┬─────┘  │
                  └────────┼────────┘
                           │
                  ┌────────▼────────┐
                  │  Your Backend   │
                  └─────────────────┘
```

Each block is a pluggable interface. Disable, swap, or extend any of them.

---

## Tech Stack

Wicket is built on proven, boring infrastructure. Nothing experimental.

| Layer | Shipped | Planned |
|---|---|---|
| Language | Go 1.26.3 | — |
| HTTP | `net/http` (stdlib) | Gin / Fiber / Echo / Chi adapters |
| Storage | in-memory, Redis (also Dragonfly/Valkey/KeyDB), `degrading` wrapper | Postgres |
| Randomness | Ed25519 per-ticket proofs (default) + SHA-256 commit-reveal mode | drand-coordinated multi-instance VRF |
| Audit log | Merkle log with inclusion proofs | append-only signed log |
| Circuit breaker | in-house (Closed → Open → Half-Open) | — |
| Rate limit | per-key token bucket | sliding window option |
| Config | YAML with hot reload via `fsnotify` | env-var overrides |
| Observability | Prometheus metrics on by default | OpenTelemetry traces |
| Identity *(optional)* | passkey (Ed25519 credential) | Self Protocol, NDID, Human Passport |

---

## Use Cases

- **Ticket drops** — concerts, sports, limited events
- **Limited e-commerce** — sneaker drops, flash sales, collectibles
- **Bank / fintech bursts** — payday transaction storms, government payouts
- **High-volume signup flows** — viral launches, beta access
- **API throttling** — protect backend from bursty downstream clients

---

## Benchmarks

`go test -bench=. -benchmem ./bench/` produces reproducible numbers on your hardware. The values below were captured on an Intel i7-9750H, Go 1.26.3, darwin/amd64. They are useful for regression detection and for comparing relative cost between modes; they are not a claim about absolute throughput on production hardware.

| Benchmark | ns/op | allocs |
|---|---:|---:|
| Baseline `httptest` request | 62 433 | 54 |
| Wicket Wrap, rate limit only | 63 378 | 55 |
| Wicket Wrap, rate limit + breaker | 63 256 | 55 |
| VRF Enqueue, seed mode | 1 362 | 3 |
| VRF Enqueue, Ed25519 mode | 26 214 | 3 |
| VRF Enqueue, ECVRF (RFC 9381) | 169 110 | 11 |
| VRF Status (rank over 1000 tickets) | 21 589 | 1 |
| Merkle Audit + Prove (1000 tickets) | 1 535 912 | 3035 |

The Wicket middleware adds roughly 1 µs over the `net/http` baseline. Modes with stronger cryptographic guarantees are progressively more expensive — pick the lightest mode that satisfies your fairness requirement.

---

## Contributing

Contributions welcome. Open an issue before starting on anything beyond a small fix so we can confirm direction. PRs must include tests next to the code they cover and pass `make test lint`.

---

## License

[Apache 2.0](LICENSE)

---
