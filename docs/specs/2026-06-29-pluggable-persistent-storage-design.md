# Pluggable, Persistent Storage for cinc-zero

**Status:** Draft for review
**Date:** 2026-06-29

## Summary

Turn cinc-zero's storage layer into a pluggable backend so the same single-process
server can run fully in memory (today's "zero" experience, unchanged and still the
default) or persist all state durably to SQLite — with PostgreSQL/RDS reachable
later by a driver swap, not a rewrite. Persistence is what separates a disposable
test fixture from a server you can stop, upgrade, and restart without losing state.

The work is tractable because the store is already a schema-agnostic document KV:
every Chef object is stored as `(org, collection, key) → canonical JSON bytes`, and
every consumer already funnels data access through a small `Store`/`Org` method set.
A backend therefore never needs to understand what a node or a cookbook *is* — it
only persists opaque bytes.

## Goals

- A `Backend` interface that abstracts raw persistence, with two implementations:
  `memory` (default) and `sqlite`.
- `--storage memory|sqlite` plus a data-dir/DSN flag and matching env vars. No flags
  = today's in-memory behavior, byte-for-byte.
- SQLite via the pure-Go `modernc.org/sqlite` driver so `CGO_ENABLED=0` static builds
  and minimal containers keep working.
- Durable users, clients, keys, passwords, ACLs, groups, nodes, cookbooks, policies,
  data bags, and the cookbook file store — i.e. everything currently in the store.
- A shared backend **conformance test suite** that runs against every backend so the
  two are provably identical in observable behavior.
- The existing `internal/api` and `server` test suites pass against *both* backends.
- Forward-only schema migrations applied at startup so a binary upgrade against an
  existing database "just works."
- Backups delegated to the backend's native mechanism (no backup code in the product).
- A documented container story: mount a volume, point SQLite at it.

## Non-Goals

- **HA / clustering / multi-node.** Single process only. (Explicitly out of scope.)
- **External search.** Search stays in-process, scanning through the store; no Solr/
  Elasticsearch. (A seam for DB-native indexing is noted but not built here.)
- **Full erchef endpoint parity.** That is a separate, ongoing completeness effort
  tracked by the README status table, not this spec. This spec makes whatever the
  server *already* serves durable; it does not add new Chef endpoints.
- **A web management UI / password login flow** beyond what already exists. Auth is
  already genuine Mixlib signature verification; passwords are already stashed. This
  spec makes them durable, nothing more.
- **Postgres/RDS implementation.** The interface is designed so Postgres is a later
  drop-in; only `memory` and `sqlite` are built now.

## Background: what exists today

- `internal/store` — `Store` (global space + per-org `Org`s) and `Org`
  (`collection → key → []byte`, plus `blobs` = `checksum → []byte`). Concrete structs
  used directly across ~24 `internal/api` files plus `server`, `repo`, and
  `internal/state`. Method surface: `Get/Put/Create/Delete/Keys/View/Range/Collections`
  for objects; `PutBlob/Blob/BlobView/HasBlob/DeleteBlob` for the file store;
  `CreateOrg/Org/DeleteOrg/ListOrgs/Global` on `Store`.
- Values are canonical JSON so payloads round-trip exactly.
- Auth is already real (`server/auth.go` verifies Mixlib signatures against the gem).
  Users/clients/keys/passwords all live in the store as JSON, so persisting the store
  persists auth state automatically.
- Search (`internal/search`) has **no separate index** — it flattens and matches
  documents by scanning the store at query time via `Org.Range`. If the store
  persists, search persists with it and needs no second storage system.
- Nothing persists today except read-only startup hydration (`internal/repo`,
  `internal/state`) from on-disk chef-repo / state directories.

## Architecture

### The seam: a `Backend` beneath an unchanged `Store`/`Org` facade

`Store` and `Org` remain the public API every consumer uses. They keep ownership of
the *semantics* that must not be duplicated per backend: canonical JSON handling,
copy-on-read for `Get`/`Blob`, the read-only zero-copy contract of `View`/`Range`,
and blob handling. They delegate raw persistence to a small `Backend`:

```go
// Package store, new file backend.go
type Backend interface {
    Get(org, coll, key string) ([]byte, bool, error)
    Put(org, coll, key string, val []byte) error
    Create(org, coll, key string, val []byte) (created bool, err error)
    Delete(org, coll, key string) (old []byte, existed bool, err error)
    Keys(org, coll string) ([]string, error)                       // sorted
    Range(org, coll string, fn func(key string, raw []byte) bool) error
    Collections(org string) ([]string, error)                      // non-empty, sorted

    PutBlob(org, checksum string, data []byte) error
    Blob(org, checksum string) ([]byte, bool, error)
    HasBlob(org, checksum string) (bool, error)
    DeleteBlob(org, checksum string) error

    CreateOrg(name string) (created bool, err error)
    DeleteOrg(name string) (existed bool, err error)
    ListOrgs() ([]string, error)                                   // sorted
    HasOrg(name string) (bool, error)

    Tx(func(Backend) error) error   // atomic multi-write; memory backend no-ops to direct calls
    Close() error
}
```

Convention: `org == ""` addresses the global space (the `users`/`organizations`
collections), replacing today's separate `global *Org`.

`memory` backend = today's maps and locks, returning `nil` errors. `sqlite` backend =
the SQL below. The zero-copy fast path (`View`/`Range` returning the backing slice)
stays a real optimization for `memory`; for `sqlite`, each read allocates a fresh
slice that still satisfies the read-only contract (callers already may not mutate or
retain it).

`★ Why this seam:` a backend never unmarshals a Chef object, so the SQL schema is ~3
tables and is invariant to changes in Chef object shapes. "SQLite now, Postgres later"
becomes a driver swap.

### Error propagation (the main mechanical cost)

Database reads and writes can fail, so the `Store`/`Org` facade methods change from
e.g. `Get(coll, key) ([]byte, bool)` to `Get(coll, key) ([]byte, bool, error)`, and
**every call site in `internal/api` (and `server`, `repo`, `state`) is updated to
handle the error** — surfacing it as a JSON `500` via the existing `writeError`
helper. No DB error is ever swallowed. The `memory` backend never returns an error,
so existing in-memory behavior is unchanged; the new error paths only fire under
`sqlite`.

This is deliberately the faithful, no-silent-failure path (chosen over a transitional
panic-to-500 bridge). It is the bulk of the diff and is done test-first.

### Package layout

```
internal/store/
  store.go        Store/Org facade — delegates to a Backend, owns copy/canonical semantics
  backend.go      Backend interface + shared conformance test helper (exported for backends)
  memory/         memory.Backend — maps + RWMutex (today's logic, lifted behind the interface)
  sqlite/         sqlite.Backend — modernc.org/sqlite, schema + migrations
  conformance_test.go   table-driven suite run against every backend
```

`store.New()` keeps working (defaults to the memory backend) so the vast majority of
tests and `server.New` need no change beyond the error-returning signatures.
`store.NewWithBackend(b Backend)` (or a functional option) wires a chosen backend.

### SQLite backend

Driver: `modernc.org/sqlite` (pure Go, no cgo). Opened in WAL mode with
`busy_timeout` set, `foreign_keys=on`. Schema:

```sql
CREATE TABLE objects (
  org        TEXT NOT NULL,          -- "" = global space
  collection TEXT NOT NULL,
  key        TEXT NOT NULL,
  body       BLOB NOT NULL,          -- canonical JSON, opaque
  PRIMARY KEY (org, collection, key)
);
CREATE TABLE blobs (
  org      TEXT NOT NULL,
  checksum TEXT NOT NULL,
  content  BLOB NOT NULL,
  PRIMARY KEY (org, checksum)
);
CREATE TABLE orgs (
  name TEXT PRIMARY KEY
);
CREATE TABLE schema_migrations (
  version INTEGER NOT NULL
);
```

- `Keys`/`Collections`/`ListOrgs` use `ORDER BY` to match the memory backend's sorted
  output exactly.
- `Range` streams rows via `rows.Next()` so large collections don't load fully into
  memory at once.
- `Create` uses `INSERT ... ON CONFLICT DO NOTHING` and reports `created` from
  `RowsAffected`, matching `ErrConflict` semantics at the facade.
- `Tx` runs the callback inside a single SQL transaction; a returned error rolls back.

### Transactions / atomicity

A few domain operations write many keys: org creation (`api.CreateOrganization`
seeds default groups, ACLs, the validator client, `_default` environment) and org
deletion. In memory these can't fail partway; against a database a crash mid-sequence
could leave partial state. Those multi-write domain operations are wrapped in
`backend.Tx(...)` so they commit atomically. Single-key handler writes need no
explicit transaction (each `Put`/`Create` is atomic on its own).

### Search

Unchanged in design: the flattener and query engine keep reading documents through
`Org.Range`, so search is automatically backend-agnostic and correct on SQLite. For
large datasets a full scan per query is slower than erchef's Solr, but that is the
accepted trade for "no external search." A future optimization (out of scope here) can
push predicates into the backend — SQLite JSON1 / FTS5, or Postgres `jsonb` + GIN —
behind an optional `Searcher` capability the engine probes for; absent it, it falls
back to the scan. This spec only ensures the scan path stays correct.

### Configuration

New flags on `cmd/cinc-zero` and fields on `server.Options`:

| Flag | Env | Default | Meaning |
|------|-----|---------|---------|
| `--storage` | `CINC_SERVER_NG_STORAGE` | `memory` | `memory` or `sqlite` |
| `--db` | `CINC_SERVER_NG_DB` | `` | SQLite file path (or, later, a DSN) |

No flags → memory, identical to today. `--storage sqlite` with no `--db` is an error
(no implicit file location, to avoid surprise writes). `server.Options` grows a
`Storage`/`DB` pair (or an injected `store.Backend`) so embedding tests can choose a
backend; the zero value stays memory.

### Migrations / upgrades

`schema_migrations` holds the applied version. At startup the SQLite backend runs any
embedded, forward-only migrations whose version exceeds the stored one, inside a
transaction, then records the new version. Because bodies are opaque JSON, the schema
is small and rarely changes; Chef object-shape changes are driven by Chef API
versions, not by our schema. Downgrades are unsupported (forward-only) and documented.
Upgrading the binary against an existing DB is therefore: open → migrate → serve.

### Backups

Delegated to the backend, no product code:

- **SQLite:** `VACUUM INTO 'backup.db'` (consistent online copy) or a file copy while
  stopped. WAL checkpointing handled by the driver.
- **Postgres/RDS (future):** `pg_dump` / managed automated snapshots.

We document the per-backend recipe rather than shipping a backup subsystem.

### Container story

```
docker run -v cinc-data:/data cinc-zero \
  --storage sqlite --db /data/cinc.db --addr 0.0.0.0:443
```

Pure-Go SQLite means the image can stay `scratch`/`distroless` with a single static
binary. State lives on the mounted volume; the container is otherwise disposable.
The volume *is* the durability and backup unit.

## Testing strategy

- **Backend conformance suite** (`store` package): a table-driven set of behavioral
  assertions — conflict on duplicate `Create`, copy independence of `Get`, sorted
  `Keys`/`Collections`/`ListOrgs`, blob round-trip, `Range` early-stop, `Tx` rollback
  on error, global-space (`org==""`) handling — run against `memory` and `sqlite`
  from one shared runner. New backends must pass it unchanged.
- **Existing suites against both backends:** `newTestAPI`/`startServer` gain a way to
  select the backend; CI runs the `internal/api` and `server` suites under each.
- **SQLite-specific tests:** migration application from an empty and from a prior
  version; WAL durability across reopen; `Tx` atomicity (partial failure leaves no
  rows).
- Strict TDD throughout (write the failing conformance/feature test first), per the
  project's standing practice.

## Build sequence (phased)

1. **Extract the interface (no behavior change).** Define `Backend`; move today's map
   logic into `memory`; make `Store`/`Org` delegate; thread `error` through the facade
   and every call site; convert `global *Org` to `org==""`. Ship: all tests green on
   memory, signatures now fallible. *(Largest, purely mechanical phase.)*
2. **Conformance suite.** Write the shared behavioral suite; run it against `memory`.
3. **SQLite backend.** Implement `sqlite.Backend` + schema + migrations; pass the
   conformance suite; run the full `api`/`server` suites against it.
4. **Wiring + flags.** `--storage`/`--db`, env vars, `server.Options`, `cmd` parsing;
   memory remains default.
5. **Atomicity.** Wrap org create/delete (and any other multi-write domain op) in
   `Tx`.
6. **Docs.** Container usage, backup recipes, upgrade/migration notes; README status
   table updated for the storage capability.

## Risks & open questions

- **Call-site churn (Phase 1).** ~24 files change signatures. Mitigated by its
  mechanical nature, the conformance suite, and the memory backend never erroring.
- **Sort-order fidelity.** SQLite `ORDER BY` collation must match Go's
  `sort.Strings` for keys that the API returns in order. Covered by conformance tests;
  may require `ORDER BY ... COLLATE BINARY`.
- **`View`/`Range` zero-copy contract under SQL.** SQLite returns fresh allocations;
  fine as long as callers honor the existing read-only contract (they do). Worth an
  explicit conformance assertion that returned slices are independent.
- **Large-collection search performance on SQLite** — accepted trade; DB-native
  indexing deferred behind a future `Searcher` capability.
- **Open:** should `server.Options` take a constructed `store.Backend` (max
  flexibility for embedders) or just `Storage`/`DB` strings (simpler surface)? Leaning
  toward both: strings for the CLI, an optional injected `Backend` for tests.
