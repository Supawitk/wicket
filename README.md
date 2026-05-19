# Wicket

**Composable admission control primitives for Go.**

Per-key rate limiter · Three-state circuit breaker · SHA-256 / Argon2id PoW · Verifiable random queue · Pluggable storage · HMAC admission tokens.

[Quick Start](#quick-start) · [What's in the box](#whats-in-the-box) · [Architecture](#architecture) · [Known limitations](#known-limitations)

---

## What is Wicket?

Wicket is a set of self-hosted admission primitives for Go services. It sits in front of an application — as a library wrapping `http.Handler`, or as a sidecar reverse proxy — and gives you a small, composable toolbox: rate limit, circuit breaker, proof-of-work, an audit-friendly randomised queue, and a single-use HMAC admission token.

It is not a turnkey "verifiable-fair waiting room against a malicious operator." Where the threat model assumes a trusted operator, this README says so. Where a primitive can be tightened by wiring two pieces together, the [Known limitations](#known-limitations) section spells out how.

---

## What's in the box

- **Per-key rate limiter** — token bucket with configurable rate and burst, idle-bucket eviction, and an optional bounded sweep (`MaxSweepBatch`) for predictable lock-hold at multi-million-key fan-out. Single `sync.Mutex` today; sharded variant is a roadmap item.
- **Circuit breaker** — three-state (Closed → Open → Half-Open) with a rolling window failure ratio and an optional `ConsecutiveFailures` trip that catches 100% failure bursts which the ratio path can miss after a long run of successes.
- **SHA-256 proof of work** (`pkg/challenger/pow`) — a payload + difficulty puzzle with a single-winner consume on Verify (no TOCTOU). Difficulty scales from a base level toward a max as a `Hint.Load` field rises; in the bundled middleware that hint is derived from current breaker state and queue depth.
- **Argon2id proof of work** (`pkg/challenger/argon2`) — memory-bound variant with the same Verify discipline, so a captured nonce cannot be replayed to amplify Argon2 CPU/RAM cost on the server.
- **VRF queue** (`pkg/queue/vrf`) — randomised admission ordering with three score-derivation modes:
  - **Ed25519** (default): each ticket carries a per-ticket signature. Not formally a VRF; the score is the first 8 bytes of the signature. Practically uniform but not unforgeable in the VRF sense.
  - **Seed (commit-reveal)**: SHA-256(seed || ticketID). The operator commits to SHA-256(seed) up front and reveals seed after. Enqueue is rejected after Reveal so the seed becoming public cannot be used to grind tickets.
  - **ECVRF**: ECVRF-EDWARDS25519-SHA512-TAI via [`github.com/ProtonMail/go-ecvrf`](https://github.com/ProtonMail/go-ecvrf). That library is dormant (last release Dec 2021) and implements draft-irtf-cfrg-vrf-10, the predecessor to RFC 9381 — proofs are NOT guaranteed to interop with a strict RFC 9381 verifier. Treat ECVRF mode as experimental.
  - `Open()` returns a signed `OpenRecord` (Ed25519 mode) so external auditors can confirm when the queue transitioned and what was committed at that moment.
- **FIFO queue** (`pkg/queue/fifo`) — monotonic-position queue when randomisation is not wanted.
- **Merkle audit log** — `(root, size)` pair plus an `O(log N)` inclusion proof; `Verify` rejects out-of-bounds positions and wrong-length paths.
- **Admission tokens** (`pkg/admission`) — HMAC-SHA256-signed, single-use, store-backed nonce. The sidecar can be configured to require one on `/enqueue` so PoW and Queue are no longer independent endpoints a bot can ignore.
- **Pluggable storage** — in-memory, Redis (and Redis-compatible: Dragonfly / Valkey / KeyDB), plus a `degrading` wrapper. The wrapper now refuses to mark itself healthy on a primary "not found" while previously degraded, so values written only to the fallback during an outage are not silently lost when the primary returns.
- **Prometheus metrics** — request outcomes and per-outcome latency histograms, breaker state, queue size, challenge counters, store-degraded gauge. Metrics endpoint is mounted under the same admin mux: in production gate it with a header / private listener.
- **Hot-reloadable sidecar config** — `rate_limit` and `circuit_breaker` sections rebuild without dropping in-flight requests; the limiter and breaker instances are preserved across reloads so an attacker cannot force-reset their state by triggering an unrelated config edit. Other sections (listen, upstream, store, queue, pow, identity, tracing, timeouts) log a "restart required" diff.
- **HTTP timeouts on the sidecar** — `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout` on the listener; per-host connection caps, dial / response-header timeouts on the upstream transport. Slowloris-friendly defaults out of the box; every value is configurable under `timeouts:` and disabling any one is `-1`.
- **OpenTelemetry tracing** — `ParentBased(TraceIDRatioBased(0.01))` by default; `tracing.sampling_ratio` overrides.

---

## Quick Start

### As a library

```go
package main

import (
    "log"
    "net/http"

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
        wicket.WithRateLimitBurst(100, 100), // 100 rps steady, 100 burst
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

> `WithRateLimit(count, per)` accepts a count over a window, but burst equals count — so `WithRateLimit(100, time.Minute)` allows a 100-request burst that refills at ~1.67/s. Prefer `WithRateLimitBurst(rate, burst)` when steady rate and burst need to be tuned separately.

### As a sidecar

```bash
go install github.com/Supawitk/wicket/cmd/wicket@latest
wicket -config wicket.yml
```

`wicket.yml`:

```yaml
listen: :8080
upstream: http://backend:3000

timeouts:
  # All values default to a safe non-zero. Set to -1 to disable
  # an individual timeout.
  read_header: 5s
  read: 30s
  write: 30s
  idle: 120s
  upstream_dial: 5s
  upstream_response: 30s
  upstream_keepalive: 90s
  upstream_max_conns: 512

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
  # max_sweep_batch: 0  # cap entries scanned per sweep (0 = unbounded)

circuit_breaker:
  failure_ratio: 0.5
  min_samples: 20
  cooldown: 30s
  half_open_max: 3
  # consecutive_failures: 50  # 0 disables; trips on N straight failures even when ratio cannot
  # window: 10s
  # window_buckets: 10

store:
  backend: memory     # or "redis"
  # redis:
  #   addr: redis:6379

metrics:
  enabled: true       # NOTE: served on the admin mux with no auth.
                      # Put it behind a header check or a private listener
                      # before exposing in production.

tracing:
  enabled: false
  otlp_http_endpoint: http://otel-collector:4318
  service_name: wicket
  sampling_ratio: 0.01   # 0 → 1%, 1 → all spans, -1 → none
```

The sidecar watches the YAML file. Changes to `rate_limit` and `circuit_breaker` are applied without dropping in-flight requests; their state is preserved across the reload. Other sections require a restart and the reload logs a warning naming the diff.

### Deployment notes

- **Behind a load balancer / CDN.** The default rate-limit key is `RemoteAddr` (IPv4 and IPv6 are both handled cleanly via `net.SplitHostPort`). Behind a proxy that becomes the proxy's IP and every client collapses into one bucket. Use `wicket.ProxyAwareKey(N)` to read `X-Forwarded-For` with a trusted-hop count, and never set N higher than the number of proxies you control.

- **Mobile / carrier-NAT traffic.** Millions of users can share a handful of public IPs. Pure IP rate-limiting will fire on legitimate users. Prefer an identity-derived key once you have one.

- **Multi-replica sidecar.** With `store.backend: redis`, PoW challenges and identity state are shared across replicas. Queue state is process-local — multi-replica deployments need sticky load balancing so `/enqueue` and `/status` for the same client land on the same replica. A shared-store queue is a roadmap item.

- **Admin endpoints.** All four admin endpoints (`/challenge`, `/solve`, `/enqueue`, `/status`) are mounted under the same mux. When `WithAdmissionVerifier(...)` is configured, `/enqueue` requires a single-use `X-Wicket-Token` (minted by `/solve`) — this is what turns the PoW → Queue pipeline from documentation into an enforced flow. `/status` accepts `POST` with a JSON body so ticket IDs don't leak into access logs or the `Referer` header; the `GET ?ticket=` form is kept for local development.

- **Real-Redis integration tests.** The shipped Redis test suite uses `miniredis`. To exercise the store against a real `redis-server` (or Dragonfly / Valkey / KeyDB):

  ```bash
  REDIS_ADDR=localhost:6379 go test -tags=integration -race ./pkg/store/redis/...
  ```

Runnable demos:

- [examples/01-minimal](examples/01-minimal) — wrap a handler, expose admin endpoints.
- [examples/02-concert](examples/02-concert) — pre-queue, open, batch admit, publish proofs.
- [examples/03-verifier](examples/03-verifier) — client-side CLI that verifies a per-ticket Ed25519 proof against the operator's public key.

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
                  │  │    PoW    │  │  bot resistance (SHA-256 or Argon2id)
                  │  └─────┬─────┘  │
                  │        │        │
                  │  ┌─────▼─────┐  │  HMAC single-use token
                  │  │ Admission │  │  (gates /enqueue when configured)
                  │  └─────┬─────┘  │
                  │        │        │
                  │  ┌─────▼─────┐  │  optional: identity layer
                  │  │ Identity  │  │  (Ed25519-credential adapter)
                  │  └─────┬─────┘  │
                  │        │        │
                  │  ┌─────▼─────┐  │  randomised admission ordering
                  │  │   Queue   │  │  (VRF: Ed25519 / Seed / ECVRF)
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

## Known limitations

These are real and shape what Wicket is safe to claim. Read them before adopting.

- **Ed25519 queue mode is not a VRF in the unforgeable-output sense.** The score is the first 8 bytes of the per-ticket Ed25519 signature; that is uniform-looking in practice but it is not a formal VRF. ECVRF mode is closer to that, but see the next point.

- **ECVRF mode depends on a dormant library, against an obsoleted draft.** `github.com/ProtonMail/go-ecvrf v0.0.1` was last updated in December 2021 and targets draft-irtf-cfrg-vrf-10, not the published RFC 9381. Proofs may not interop with a strict RFC 9381 verifier. Treat ECVRF mode as experimental until either an interop test against the RFC test vectors lands or the dep is replaced.

- **The "passkey adapter" is an Ed25519-credential adapter, not WebAuthn.** It signs over a raw 32-byte payload and stores the credential ID as the nullifier hash; a real browser passkey ceremony will not produce a signature it accepts. There is no `signCount` clone detection. Use it as a Bring-Your-Own-Client Ed25519 credential layer or layer a real WebAuthn parser on top.

- **Operator-grinding in the VRF queue.** All three score-derivation modes compute the score from `(operator_key_or_seed, ticket_id)`. Ticket IDs are now bound to the requester's visitor key (so an attacker rotating IPs can't impersonate another user's ticket), but the operator still controls the random nonce mixed in. A malicious operator can mint, observe the score, discard, and retry until favourable. Fairness against a *trusted* operator holds; fairness against a *malicious* operator requires a two-step issue/redeem where the client commits first. That's a follow-up.

- **Queue state is process-local.** Multi-replica deployments need sticky load balancing for `/enqueue` and `/status`. A shared-store queue (mirroring the PoW challenger's `store.Store` plumbing) is on the roadmap.

- **Rate-limit `Allow` holds a single mutex.** Fine for typical workloads; under hundreds of thousands of QPS against the rate limiter alone, you'll see contention before CPU. A sharded variant is on the roadmap.

- **`degrading.Store` does not guarantee zero data loss across recovery.** Writes that landed only on the fallback during an outage are not back-filled to the primary when it returns. Reads of those keys continue to work because `Get` now consults the fallback on a primary miss while previously degraded. A migration / drain helper is a follow-up.

- **`/__wicket__/metrics` is unauthenticated.** The Prometheus exporter is on the same admin mux as everything else. Put it behind a header check or a private listener before exposing it.

---

## Use Cases

- **Ticket drops** — concerts, sports, limited events
- **Limited e-commerce** — sneaker drops, flash sales, collectibles
- **Bank / fintech bursts** — payday transaction storms, government payouts
- **High-volume signup flows** — viral launches, beta access
- **API throttling** — protect backend from bursty downstream clients

---

## Contributing

Contributions welcome. Open an issue before starting on anything beyond a small fix so we can confirm direction. PRs must include tests next to the code they cover and pass `make test lint`.

---

## License

[Apache 2.0](LICENSE)

---
