# SQLite Schema Migration Engine

**Status:** Draft for review
**Date:** 2026-06-29

## Summary

Replace the SQLite backend's one-shot schema stamp with a real, forward-only
**migration engine**: an append-only, numbered list of migrations applied in
order, each in its own transaction, gated by a recorded version, with a guard
that refuses to open a database created by a newer binary. This lets us evolve
the persistent schema safely after release — we know exactly which version a
database is at and how to advance it — and it is much cheaper to put in place now,
while version 1 is the only version in the wild, than to retrofit later.

## Background: what exists today

`internal/store/sqlite`'s `migrate()` (run from `Open`) creates the `objects`,
`blobs`, `orgs`, and `schema_migrations` tables with `CREATE TABLE IF NOT EXISTS`
and, only on a brand-new database, inserts `version = 1`. It has no way to apply
*incremental* changes and does not reject a database newer than the binary. The
`schema_migrations` table is the right scaffolding; the runner is missing. The
README already promises "pending migrations are applied automatically at startup"
and "forward-only … downgrading is not supported" — this spec makes that true.

## Two things to version (scope clarification)

1. **The SQL schema** — the shape of the tables (columns, indexes, new tables).
   This is what the engine versions. Most changes are additive DDL.
2. **The JSON body format** — the opaque bytes in `objects.body`. cinc-server-ng stores
   exactly what a Chef client sent and serves it back, so the body format tracks
   the *Chef API*, not our schema. Body rewrites are rare and avoided in favour of
   fidelity; when genuinely needed they are expressed as a migration that streams
   and rewrites rows (see Non-Goals / future work).

This spec builds the engine. It ships **only migration 1 (the current schema)** —
no new schema change — so it is a pure, behaviour-preserving refactor plus the
engine and its guards.

## Goals

- An ordered, append-only `migrations` list in the sqlite package; each entry is
  `{version int, name string, up func(querier) error}`.
- A runner that, on `Open`: ensures the `schema_migrations` ledger exists, reads
  the current version, applies every migration with a higher version in order,
  each inside its own transaction, recording the version on success.
- A **reject-newer guard**: if the database's recorded version exceeds the highest
  version the binary knows, `Open` fails with a clear "upgrade the binary" error
  rather than running against an unknown schema.
- **Backward compatibility**: existing version-1 databases (created by the current
  code) open unchanged — migration 1 is recognised as already applied.
- Idempotence: re-opening an up-to-date database applies nothing.
- A `Version()` accessor on the backend for tests/observability.
- Tests that exercise the **upgrade path**, not just fresh creation, plus the
  reject-newer guard and per-migration rollback.

## Non-Goals

- **No actual new schema change.** Migration 1 reproduces today's tables; version 2+
  arrive in later PRs when a real need exists.
- **No down/rollback migrations.** Forward-only, matching the documented policy. A
  `down` direction can be added later if a real need appears.
- **No body-format transformation yet.** The engine *supports* it (a migration `up`
  may stream and rewrite `objects.body`), but none is shipped here.
- **No cross-backend migration framework.** Migrations are SQL-dialect-specific and
  live in the sqlite backend. The memory backend has no schema; a future Postgres
  backend gets its own list. The `Backend` interface is unchanged.

## Design

### The migration type and list

```go
// A migration is a single, ordered, forward-only schema change. The list is
// APPEND-ONLY: once a version ships, its up func is a historical fact and must
// never be edited — fix mistakes by adding a new migration.
type migration struct {
	version int
	name    string
	up      func(q querier) error // DDL and/or data transform; runs inside a tx
}

var migrations = []migration{
	{1, "initial schema", func(q querier) error {
		_, err := q.Exec(`
CREATE TABLE objects (
  org TEXT NOT NULL, collection TEXT NOT NULL, key TEXT NOT NULL,
  body BLOB NOT NULL, PRIMARY KEY (org, collection, key));
CREATE TABLE blobs (
  org TEXT NOT NULL, checksum TEXT NOT NULL, content BLOB NOT NULL,
  PRIMARY KEY (org, checksum));
CREATE TABLE orgs (name TEXT PRIMARY KEY);`)
		return err
	}},
}
```

Migration 1 creates only the data tables; the runner owns the `schema_migrations`
ledger. It uses plain `CREATE TABLE` (no `IF NOT EXISTS`) because the runner
guarantees it executes only when the database is below version 1 (i.e. genuinely
fresh).

### The runner

```go
func (b *Backend) migrate() error { return applyMigrations(b.db, migrations) }

func applyMigrations(db *sql.DB, migs []migration) error {
	if _, err := db.Exec(
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		return err
	}
	var current int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	last := 0
	if len(migs) > 0 {
		last = migs[len(migs)-1].version
	}
	if current > last {
		return fmt.Errorf("database schema is version %d but this cinc-server-ng only knows up to %d; upgrade the binary", current, last)
	}
	for _, m := range migs {
		if m.version <= current {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if err := m.up(tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d (%s): %w", m.version, m.name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version) VALUES (?)`, m.version); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
```

- `applyMigrations` takes the list as a parameter so tests can drive it with
  synthetic migration sets (extra versions, a deliberately failing migration)
  without polluting the real list.
- Each migration runs in its own transaction (SQLite DDL is transactional), so a
  failure rolls back that migration and leaves the database at the last good
  version — never half-applied.
- The version gate makes migrations exactly-once; `IF NOT EXISTS` on the ledger is
  the only defensive create.

### Backward compatibility with existing version-1 databases

Databases created by the current code already contain the data tables and a
`schema_migrations` row `version = 1` (under the existing
`schema_migrations(version INTEGER NOT NULL)` definition). The runner's
`CREATE TABLE IF NOT EXISTS` leaves that table as-is, reads `current = 1`, and
skips migration 1. Fresh databases get `version INTEGER PRIMARY KEY` and run
migration 1. Both shapes store version rows identically; the runner works against
either.

### Observability

```go
// Version returns the database's current schema version (0 if unmigrated).
func (b *Backend) Version() (int, error)
```

## Testing strategy

All in `internal/store/sqlite` (white-box, so tests can call `applyMigrations` and
construct synthetic migrations):

1. **Fresh create** — a new database ends at the highest real version; the data
   tables exist (the existing conformance suite already covers behaviour).
2. **Idempotent reopen** — running the runner twice applies nothing the second
   time and leaves the version unchanged.
3. **Upgrade path** — start a database at version 1, then run a synthetic list
   `[v1, v2]` where v2 adds a column/table; assert the version advances to 2, v2's
   change is present, and rows written before the upgrade survive. This is the
   case that matters in production and the one a fresh-create test misses.
4. **Reject-newer guard** — write `version = 99`, run a list whose max is lower,
   assert a descriptive error and no mutation.
5. **Per-migration rollback** — a synthetic v2 whose `up` returns an error leaves
   the database at version 1 with no partial effect, and the error is propagated.
6. **`Version()`** — reports the expected number across the above.

Strict TDD: each test is written failing first, then the engine implemented.
`make test && make vet` green before committing.

## Operational rules (documented in code comments and README)

- **Append-only.** Never edit a shipped migration; add a new one. A migration is a
  historical fact some user's database already ran.
- **Forward-only.** No downgrades; opening a newer database on an older binary is a
  hard error, not a silent run.
- **Body migrations are exceptional.** Prefer additive columns/indexes over the
  opaque JSON (SQLite JSON1 / expression indexes / generated columns) to deriving
  or rewriting body content; this is also the seam for future DB-native search.

## Risks

- **Ledger table-shape drift** between pre-existing (`NOT NULL`) and new
  (`PRIMARY KEY`) databases. Harmless — both store version rows and the runner
  reads/writes both — and covered by an explicit "old-shape ledger" test.
- **Large body migrations** (future) could build oversized transactions; when one
  is first needed, batch within the migration. Out of scope here; noted so the
  first body migration's author batches deliberately.
