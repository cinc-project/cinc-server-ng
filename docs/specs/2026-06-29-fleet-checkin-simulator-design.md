# Fleet check-in simulator (`cmd/fleetsim`) — Design

Date: 2026-06-29
Status: Proposed — awaiting review

## Goal

A standalone, compile-and-run utility that makes an existing cinc-server-ng fleet
behave like a live datacenter: most nodes "check in" on a ~30-minute cadence,
continuously refreshing their last-seen time, while a stuck **2%** never report
— modelling the broken hosts every real fleet carries. It generates realistic,
steady-state traffic (not peak load — that's what `cmd/loadtest` is for).

This is a development/demo tool. Like `cmd/loadtest`, it is **not** built into
the `cinc-server-ng` binary.

## Domain model

A node's "last check-in date" is its `automatic.ohai_time` (a Unix timestamp).
`seedgen` stamps it and `internal/state/seed_test.go` asserts every node's
`ohai_time` is recent. A real `chef-client` run ends by `PUT`ing the full node
object with a freshly-stamped `ohai_time`. The simulator reproduces exactly that
HTTP shape, so the server sees production-like traffic.

## Confirmed scope decisions

| Area            | Decision |
|-----------------|----------|
| Node source     | **Discover from the server** at startup (`GET /nodes`, then `GET` each body). The discovered count is "the total number of nodes in the environment." |
| Auth            | **Single admin actor** (`--user` + `--keypem`), signing every request, reusing `internal/auth` and `cmd/loadtest`'s signing helpers. **Unsigned** when no key is given (for `--no-auth` servers). |
| Timing          | **Real-time scheduling with a `--speed` multiplier.** `--interval` and `--splay` default to `30m`; effective real durations are divided by `--speed`. `ohai_time` is always stamped with real wall-clock `time.Now().Unix()`, regardless of `--speed`. |
| Splay model     | **Per-cycle jitter (chef-client style).** Each converging node sleeps `(interval + rand[0,splay)) / speed` between check-ins, so spacing is always ≥ interval ("never more than once per 30 min") and the random offset keeps the fleet desynchronized ("constantly checking in"). |
| Stuck nodes     | **2%** (configurable via `--stuck`), chosen **deterministically** at startup from a `--seed`ed RNG (project convention: reproducible). Stuck nodes get no goroutine and never check in; their `ohai_time` goes stale. |
| Check-in shape  | **`GET` node → stamp `automatic.ohai_time = now` → `PUT` node** (2 requests), mirroring a real chef-client run. |
| Scheduler       | **Goroutine-per-node with self-scheduled sleeps** (approach A below). |

## Approaches considered (scheduler)

- **(A) Goroutine-per-node with self-scheduled sleeps — CHOSEN.** Each converging
  node owns a goroutine looping `sleep(period); checkin()`. Splay is the
  per-iteration jitter; desynchronization falls out for free. Go goroutines are
  cheap enough for thousands of nodes. Simplest and most faithful to independent
  hosts.
- (B) Central min-heap of next-fire times with a worker pool — more bookkeeping,
  no benefit at this scale.
- (C) Global ticker scanning all nodes each tick — wastes work and couples every
  node to one clock.

## Components

All under `cmd/fleetsim/`:

- **`main.go`** — flag parsing, wiring, `context`-based SIGINT handling, and a
  periodic summary log line.
- **`fleet.go`** — `discover(client)` (list nodes, fetch each body) and
  `selectStuck(names, frac, rng)` (deterministically pick `ceil(frac × N)`).
- **`schedule.go`** — `period(interval, splay, speed, rng) time.Duration`, pure
  and unit-testable; returns `(interval + rand[0,splay)) / speed`.
- **`checkin.go`** — the `GET → stamp → PUT` action behind a small interface so
  tests inject a fake. Signing/client logic is a **minimal local copy** of the
  `cmd/loadtest` helpers (both are `package main` in separate dirs, so they can't
  share unexported code without refactoring `loadtest` — out of scope here).

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--base` | (required) | Org URL, e.g. `http://127.0.0.1:8902/organizations/acme` |
| `--user` | `""` | Signing actor (empty ⇒ unsigned) |
| `--keypem` | `""` | PEM private key path for signing |
| `--interval` | `30m` | Simulated time between a node's check-ins |
| `--splay` | `30m` | Max extra random jitter added per cycle |
| `--speed` | `1.0` | Time-compression multiplier (60 ⇒ 30m sim = 30s real) |
| `--stuck` | `0.02` | Fraction of the fleet that never checks in |
| `--seed` | `1` | RNG seed for reproducible stuck-set + jitter |
| `--concurrency` | `64` | Cap on in-flight HTTP requests (semaphore) |
| `--timeout` | `15000` | Per-request timeout (ms) |

## Behavior

1. **Discover** all nodes from the server — the total fleet size.
2. **Select** `ceil(stuck × N)` nodes as stuck (deterministic from `--seed`).
   These never check in.
3. For each remaining (converging) node, start a goroutine: sleep an initial
   `rand[0,splay)/speed` (so the first check-in lands within the first window and
   the fleet is spread), then loop forever sleeping `(interval + rand[0,splay))/speed`
   between check-ins.
4. Each **check-in**: `GET` the node, set `automatic.ohai_time` to real
   `time.Now().Unix()`, `PUT` it back. A semaphore bounds concurrent requests.
5. Run until **SIGINT**; on each tick (e.g. every 30s real) log a summary:
   total nodes, converging, stuck, check-ins so far, errors.

## Error handling

- Discovery failure (can't list/fetch nodes) is fatal — exit non-zero with a
  clear message; there's nothing to simulate.
- A per-check-in HTTP error (timeout, 5xx) is **non-fatal**: increment an error
  counter, log at a throttled rate, and the node retries on its next cycle. One
  flaky node must not take down the run.
- SIGINT cancels the context; goroutines observe cancellation and exit; print a
  final summary before returning.

## Testing (TDD)

- `period()` — returned duration is within `[interval, interval+splay)/speed`;
  scaling by `speed` is correct; `splay == 0` ⇒ exactly `interval/speed`.
- `selectStuck()` — count is `ceil(frac × N)`; same seed ⇒ identical set;
  different seeds differ; fraction ≈ requested.
- End-to-end — against `httptest`/`newTestAPI` with a tiny interval and high
  speed: assert converging nodes' `ohai_time` advances past a baseline while
  stuck nodes' `ohai_time` stays put; assert no node check-ins are spaced closer
  than `interval/speed`.

## Out of scope (YAGNI)

- Per-node client identities / keys (single admin actor only).
- Creating or seeding nodes (discovery only — seed with `seedgen`/`--init`).
- Simulating cookbook downloads, search, or any traffic beyond node check-ins.
- A `--speed`-aware simulated `ohai_time` (stamps stay real wall-clock).

## Workspace

Implemented in the git worktree `worktree-fleetsim`, branched from fresh
`origin/main`.
