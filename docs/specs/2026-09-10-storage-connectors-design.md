# Storage Connectors: Backends as Independent, Self-Describing Units

Status: proposed
Date: 2026-09-10
Extends: `2026-06-29-pluggable-persistent-storage-design.md`

## Summary

The `store.Backend` seam introduced by the pluggable-storage design works, and it
carries two implementations. It does not carry twelve. The interface is sound; what
does not scale is everything *around* it: backend selection is a `switch` in
`server.buildStore`, backend-specific configuration lives in `server.Options` and
in top-level CLI flags, the two implementations sit in different kinds of package,
and three behavioral divergences between them are documented in `CLAUDE.md` rather
than asserted in a test.

This design turns a backend into a **connector**: a self-contained package that
registers a `Descriptor` describing itself, is configured through a validated
option bag rather than bespoke flags, and proves itself against a shared
conformance suite that is strict enough to be worth passing. Adding a connector
becomes a new package plus one line in a manifest. Nothing in `server`, `cmd`, or
`internal/api` changes.

PostgreSQL is the first connector built this way, and is the test of whether the
abstraction holds.

## Goals

- **A connector is an independent unit.** It depends on a contract package with no
  other internal imports, so it can be built, tested, and reasoned about without
  constructing a `Store` or linking the server.
- **Adding a connector touches no shared code.** No new field in `server.Options`,
  no new CLI flag, no new `case` in a `switch`, no new `if storage == "x"` branch
  in the startup banner.
- **Behavioral variance between connectors is eliminated or made explicit.** The
  three divergences `CLAUDE.md` currently warns about become either a strict,
  tested rule or a declared opt-in capability.
- **The conformance suite is the deliverable.** With a dozen implementations, the
  suite is what makes the abstraction real; a connector author's job is to make it
  pass.
- **Lay groundwork for out-of-tree storage plugins** without building a plugin
  system now.

## Non-Goals

- **Build tags, separate modules, or trimmed binaries.** All connectors compile
  into every build and their drivers live in the root `go.mod`. This is an accepted
  cost; the layout does not foreclose revisiting it.
- **A plugin loader.** No `plugin.Open`, no gRPC connectors, no dynamic discovery.
  The contract package is shaped so one could be added later.
- **Changing what a backend stores.** It remains opaque canonical-JSON object
  bodies keyed by `(org, collection, key)` plus opaque blobs keyed by
  `(org, checksum)`. No server-side search, no server-side ACL evaluation.
- **New `Backend` primitives** (batch get, CAS, predicate pushdown). If PostgreSQL
  or a later connector proves a need, the optional-interface mechanism defined here
  is how it gets added without touching the other eleven.

## Background: what exists today

`internal/store/backend.go` defines an 18-method `Backend` interface with
documented semantics: opaque bytes, the empty org string addressing the global
space, `Create` returning `ErrConflict`, `Tx` for atomic multi-writes.
`internal/store/backendtest` is a shared suite of twenty sub-tests that both
implementations run. `store.Store`/`Org` is a thin facade owning canonical-JSON and
copy semantics, the `Counts` tally, the groups generation counter, and the `Watch`
write-event stream — none of which a backend knows about.

That much is right and is kept. The friction is elsewhere:

| Friction | Location | Why it breaks at twelve |
| --- | --- | --- |
| `switch opts.Storage` | `server/server.go:125` | Every connector edits core; core imports every connector by name |
| `Options.DB`, `Options.SQLiteGroupCommit` | `server/server.go:82-91` | Per-connector configuration in a struct shared by all of them |
| `--db`, `--sqlite-group-commit` | `cmd/cinc-server-ng/main.go:71-73` | The same problem on the CLI surface; `--sqlite-group-commit` is silently ignored under `--storage memory` |
| `f.storage == "sqlite"` branches | `cmd/cinc-server-ng/main.go:169,183` | Startup banner and `--init` messaging hard-code the connector list |
| memory in `package store`, SQLite in a subpackage | `internal/store/memory.go` | Asymmetric; `backend.go`'s own doc comment already claims a `store/memory` that does not exist |
| `Range` identity, `Range` ordering, `Tx` isolation differ | `CLAUDE.md` | Documented as folklore; `backendtest` passes both behaviors, so a twelfth connector has nothing to check itself against |

The last row is the most important. With two implementations a maintainer can hold
the divergences in their head. With twelve, "undefined and untested" is where every
bug will come from.

## Architecture

### Package layout

`Backend` currently lives in `internal/store`, which also contains the facade. A
connector that imports it drags in `watch.go`, `Counts`, and the `Store` type. The
contract moves to a leaf package with no internal imports — the `database/sql`
arrangement:

```
internal/store/
  store.go        Store/Org facade, Counts, Tx, event stream  → imports connector, memory
  watch.go
  connector/      THE CONTRACT. stdlib only. Imports nothing internal.
    backend.go      Backend interface, ErrConflict, ErrNotFound
    descriptor.go   Descriptor, OptionSpec, Options
    registry.go     Register / Lookup / List / Open
    optional.go     Pinger, Migrator, Statser, UnorderedRanger
    checked/        test-only strict-contract decorator
  backendtest/    conformance suite
  all/            blank imports of every connector — the one file that lists them
  memory/         moves out of package store
  sqlite/         unchanged internals; gains a Descriptor
  postgres/       new
```

Import directions, all acyclic:

- `connector` imports nothing internal.
- `memory`, `sqlite`, `postgres` import `connector`.
- `store` imports `connector` and `memory` (so `store.New()` stays a direct
  construction, not a registry lookup).
- `all` blank-imports every connector.
- `server` imports `all`, so an embedder calling
  `server.New(Options{Storage: "postgres"})` needs no blank import of their own.
- `backendtest` imports `connector` and `store` (see "Testing strategy").

`internal/store` retains aliases so no consumer changes:

```go
type Backend = connector.Backend
var ErrConflict = connector.ErrConflict
var ErrNotFound = connector.ErrNotFound
```

Nothing in `internal/api` or `server` is edited by the extraction.

### The connector contract

```go
package connector

// Descriptor describes one storage connector. A connector registers exactly one
// from its package init.
type Descriptor struct {
	Name    string       // "memory", "sqlite", "postgres"
	Summary string       // one line, shown by --help
	Durable bool         // survives a restart; drives --init and banner wording
	Options []OptionSpec
	Open    func(Options) (Backend, error)
}

// OptionSpec declares one configurable option.
type OptionSpec struct {
	Name     string     // "path", "pool", "group_commit"
	Type     OptionType // String | Int | Bool | Duration
	Required bool
	Default  string
	Doc      string
	Secret   bool // redacted in the startup banner and in error text
}

// Options is the validated option bag handed to Open. Accessors are total:
// a declared option always has a value, defaulted if the operator omitted it.
type Options struct{ /* ... */ }

func (o Options) String(name string) string
func (o Options) Int(name string) int
func (o Options) Bool(name string) bool
func (o Options) Duration(name string) time.Duration

func Register(d Descriptor)
func List() []Descriptor
func Lookup(name string) (Descriptor, bool)
func Open(name string, kv map[string]string) (Backend, error)
```

`Open` performs validation centrally, so twelve connectors do not each reinvent it:

- unknown connector name: error listing every registered name
- unknown option key: error naming the connector and suggesting the nearest declared
  option (`unknown option "pth" for storage "sqlite"; did you mean "path"?`)
- missing required option: error naming it and quoting its `Doc`
- unparseable value: error naming the option and its expected type

`Secret` options are redacted wherever an option bag is rendered — the startup
banner, `--help` defaults, and validation errors — so a PostgreSQL password never
reaches a log line.

### Optional lifecycle interfaces

Beyond `Backend`, a connector may implement any of the following. Each is consumed
by core in exactly one place, through a type assertion, and each is verified by the
conformance suite *if present*, so the hooks cannot rot.

| Interface | Methods | Consumer |
| --- | --- | --- |
| `Pinger` | `Ping(ctx) error` | `GET /_status` (`internal/api/system.go:7`) |
| `Migrator` | `SchemaVersion() (int, error)`, `Migrate() error` | `--init`, startup schema check |
| `Statser` | `Stats() map[string]int64` | `internal/metrics`, alongside `store.Counts` |
| `UnorderedRanger` | `RangeUnordered(org, coll string, fn func(key string, raw []byte) bool) error` | the ordering fast path (below) |

A connector implementing none of them is fully functional; `/_status` reports it as
healthy by construction and `--init` reports nothing persisted unless `Durable`.

### Configuration

`server.Options` loses `DB` and `SQLiteGroupCommit` and gains one field:

```go
Storage     string            // "memory" (default), "sqlite", "postgres", ...
StorageOpts map[string]string // validated against the connector's OptionSpecs
Backend     store.Backend     // unchanged: still overrides everything, for tests
```

The CLI selects by name and configures by repeated key/value:

```
--storage sqlite   --storage-opt path=./cinc.db --storage-opt group_commit=false
--storage postgres --storage-opt host=db1 --storage-opt user=cinc --storage-opt pool=16
```

Key/value was chosen over a DSN URL because option values here include filesystem
paths and passwords, both of which acquire URL-escaping hazards inside a
connection string, and because a flat map is what an embedder passes
programmatically anyway.

Compatibility and ergonomics:

- `--db X` and `--sqlite-group-commit=X` remain as deprecated aliases desugaring to
  `--storage-opt path=X` and `--storage-opt group_commit=X`, each emitting a
  one-line deprecation notice. `CINC_SERVER_NG_DB` likewise.
- `CINC_SERVER_NG_STORAGE_OPTS="host=db1,pool=16"` supplies options in containers.
- `--help` enumerates every registered connector and its options, generated from
  the descriptors rather than hand-maintained.
- The startup banner and the `--init` message are rendered from `Descriptor.Name`,
  `Descriptor.Durable`, and the non-`Secret` options, deleting both
  `f.storage == "sqlite"` branches.

## Tightening the contract

Each divergence `CLAUDE.md` documents gets a decision and a test. The governing
principle: strict wherever a caller could silently get it wrong; an opt-in fast
path only where a benchmark justifies one.

### `Range` ordering: strict, ascending byte order

The contract becomes "`Range` visits keys in ascending byte order," matching
SQLite's `ORDER BY key`. The memory backend collects and sorts, which it already
does in `Keys`.

The escape hatch is the `UnorderedRanger` optional interface. A caller that
provably does not care type-asserts for it — plausibly the search reindex path —
and only after a benchmark shows the sort mattering. Every other caller gets
ordering for free and stops being silently backend-dependent.

This rule is also why the PostgreSQL connector must order by `key COLLATE "C"`
rather than the database's default collation: on a locale-aware cluster the default
is not byte order. The conformance suite's key-ordering case is what catches it.

### `Range` slice identity: strict rule, test-only enforcement

Requiring every backend to hand `fn` a fresh copy would tax the exact scan path
in-memory mode exists to make fast. So the contract tightens without the production
cost.

The rule: the slice passed to `fn` is valid only for the duration of that call.
Callers must not retain it, must not mutate it, and **must not use its identity**
(pointer or capacity) as a cache key.

The enforcement: `connector/checked`, a decorator wrapping any `Backend`, applied
automatically inside `backendtest` and available to any test that wants it. It
hands `fn` a fresh copy and then overwrites that copy once `fn` returns. A caller
that retained the slice reads garbage immediately and loudly, rather than behaving
correctly on memory and breaking under `--storage sqlite`.

The reasoning generalizes: when two implementations may legitimately differ on a
*permission*, the permission itself cannot be tested — only the callers' abuse of
it can. The decorator makes the loosest legal behavior the one that runs under
test, so the strictest connector is never the one that discovers the bug. The cost
is that the rule is enforced in tests rather than in production, which is accepted.

### `Tx` isolation: strict

The memory backend's `Tx` (`internal/store/memory.go:198`) snapshots the maps,
releases the lock while `fn` runs, and restores the snapshot on rollback — so a
write landing concurrently with a rolled-back transaction is silently reverted.
`Tx` serves only rare bootstrap operations (organization create and delete), so the
memory backend takes the store-wide write lock for the transaction's duration,
making it genuinely isolated.

The suite gains a case that drives a concurrent write against a rolling-back
transaction and asserts the concurrent write survives. It fails against today's
memory backend and passes against SQLite.

### What remains legitimately divergent

Read amplification. A durable connector pays a real read per `Get` where memory
does not, and that shows up in `store.Counts()`. This is a performance
characteristic, not a semantic one, and stays documented rather than tested for
equality. `CLAUDE.md`'s "Backend differences the default tests will not catch"
section shrinks to this one entry.

## Testing strategy

With twelve implementations the conformance suite *is* the abstraction. Three entry
points:

```go
backendtest.Run(t, newBackend)         // the full contract, through the checked decorator
backendtest.RunOptional(t, newBackend) // whichever optional interfaces are present
backendtest.RunFacade(t, newBackend)   // the contract as the Store facade depends on it
```

`RunFacade` is new and is the most valuable addition. It builds a real
`store.Store` over the connector and asserts the **write-stream invariants** that
derived indexes depend on: every committed write emitted exactly once; a conflicted
`Create` and a no-op `Delete` emitting nothing; transaction events released only on
commit and in order; `GroupsGeneration` advancing on `groups` writes and
deliberately not on `group_members` writes. Those properties are currently tested
once, against memory, in `internal/store`. A new connector could break every one of
them while `Run` stayed green.

New adversarial cases, drawn from the invariants `CLAUDE.md` already flags:

- keys containing `/`, `:`, and `%`. ACLs are keyed `"<type>/<name>"`, so a
  connector that splits on a separator corrupts authorization.
- unicode keys, and keys differing only in case (`Admin` versus `admin`). A
  case-insensitive collation would merge two distinct principals — a real hazard on
  PostgreSQL and MySQL.
- the empty-string org versus an organization literally named `""`; the global
  space must not collide with a named org.
- values at the size boundary, and a value that is not valid UTF-8 (blobs are
  opaque bytes, and a `text` column would corrupt them).
- `Keys`, `Range`, and `Collections` against a collection that has never existed.
- the `store.Counts()` tally, so a chatty connector's read amplification is visible
  rather than discovered in production.

A connector's own test file then runs to roughly fifteen lines: construct one, call
the three `Run` entry points, and add whatever is genuinely connector-specific.
SQLite's migration, close, latency, and group-commit tests stay where they are.

## The PostgreSQL connector

Built only against `connector` and `backendtest`. That constraint is the test of
whether the abstraction holds: if writing it requires editing anything outside its
own package and `all`, the design has failed and should be revised before the
remaining connectors are written.

- Schema mirroring SQLite's, so the differential harness can compare the two:
  `objects(org text, coll text, key text, val bytea, primary key (org, coll, key))`,
  `blobs(org, checksum, data)`, `orgs(name)`.
- Options: `host`, `port`, `user`, `password` (`Secret: true`), `dbname`,
  `sslmode`, `pool`, `conn_max_lifetime`; plus `dsn` as a single-option
  alternative for operators who already have a connection string.
- `Migrator` reusing the migration-table pattern from the schema-migration design;
  `Pinger` via `db.PingContext`; `Statser` via `sql.DBStats`.
- `Create` as `INSERT ... ON CONFLICT DO NOTHING` with `RowsAffected` driving
  `ErrConflict`.
- `Tx` as a real `BEGIN`, satisfying the isolation rule without special effort.
- `Range` as `ORDER BY key COLLATE "C"`, per the ordering rule above.

## Build sequence (phased)

Each phase ships independently with `make test && make lint` green, and each starts
from a failing test per the repository's TDD rule.

| # | Phase | Behavior change |
| --- | --- | --- |
| 1 | Extract `connector`; `store` keeps type aliases | none |
| 2 | Move memory to `store/memory`; both connectors gain Descriptors | none |
| 3 | Registry, `--storage-opt`, `Options.StorageOpts`; `--db` deprecated alias; banner and `--init` rendered from the Descriptor | CLI surface grows; old flags still work |
| 4 | Tighten ordering, identity, and isolation; add `checked`; expand `backendtest` and add `RunFacade` | memory backend gains sorted `Range` and isolated `Tx` |
| 5 | Wire `Pinger`, `Migrator`, `Statser` to `/_status`, `--init`, metrics | `/_status` reports backend health |
| 6 | PostgreSQL connector | new `--storage postgres` |

Phases 1 and 2 are pure moves and should be near-mechanical. Phase 4 carries the
real risk, since it changes memory-backend behavior on hot paths, so it lands alone
with the fleet benchmarks (`server/fleet_bench_test.go`,
`internal/api/checkin_bench_test.go`) re-run and compared. Phase 6 touches nothing
outside its own package, which is the point of the preceding five.

Documentation updated alongside: the README storage section and `--storage` table,
`docs/DEVELOPMENT.md`, `CLAUDE.md`'s backend-differences section (which shrinks to
read amplification), and a new "writing a connector" walkthrough.

## Alternatives considered

- **DSN connection strings** (`--storage 'postgres://u@h/db?pool=16'`). Familiar
  and trivially env-var-able, but filesystem paths and passwords acquire escaping
  hazards inside a URL, and embedders would be constructing strings to have them
  immediately parsed.
- **Connectors registering their own CLI flags.** Best `--help` discoverability,
  but it couples a connector to flag parsing and makes it awkward to configure
  programmatically or, later, as a plugin.
- **Declaring variance as capabilities** rather than tightening (`Capabilities()`
  reporting `OrderedScan`, `IsolatedTx`, and so on, with core branching on them).
  Rejected because every caller would then have to handle the weak case, and the
  fail-open hazards `CLAUDE.md` documents in the authorization layer would gain a
  new surface. Tightening with a narrow opt-in fast path keeps the default
  reasoning uniform.
- **Forcing every backend to copy in `Range`** instead of the `checked` decorator.
  Simpler to state, but it taxes the in-memory scan path that in-memory mode exists
  to make fast.
- **A separate `facadetest` package** instead of putting `RunFacade` in
  `backendtest`. `RunFacade` makes `backendtest` import `internal/store`, so the
  suite stops being a leaf and would be harder to lift out-of-tree if plugins
  happen later. One suite a connector author runs was judged more valuable than
  that future optionality; splitting it later is mechanical if plugins arrive.
- **Build tags or separate Go modules per connector**, keeping drivers out of the
  default build. Deferred deliberately: shipping a dozen drivers in one binary is
  acceptable for now, and the layout does not prevent revisiting it.

## Risks and open questions

- **Phase 4 is a performance change to the memory backend.** Sorted `Range` adds an
  allocation and a sort to every scan, and an exclusive `Tx` lock serializes
  bootstrap. Both need benchmark comparison before and after; if the scan cost is
  material, the search path is the first candidate for `UnorderedRanger`.
- **`--storage-opt` is more verbose than `--db`** for the common single-file SQLite
  case. The deprecated alias absorbs this, but the aliases should not become
  permanent; a removal release should be named once the connector set stabilizes.
- **`server` importing `store/all`** links every driver into every binary,
  including test binaries. Accepted, but it makes build time and `go.mod` a
  monotonically growing cost that the build-tag alternative exists to address later.
- **`RunFacade` asserts invariants that currently have exactly one implementation.**
  Writing it may surface that some of them are properties of the memory backend
  rather than of the contract. That discovery belongs in phase 4, before PostgreSQL
  is written against them.
