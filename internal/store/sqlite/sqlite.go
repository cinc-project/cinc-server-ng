// Package sqlite is the durable store.Backend backed by SQLite via the pure-Go
// modernc.org/sqlite driver (no cgo). Object bodies and blob contents are stored
// opaquely, so the schema is invariant to Chef object shapes and a single static
// binary can persist all server state to a file.
package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"sync"

	"github.com/tas50/cinc-server-ng/internal/store"
	_ "modernc.org/sqlite"
)

// A migration is a single, ordered, forward-only schema change. The migrations
// list is APPEND-ONLY: once a version ships, its up func is a historical fact that
// some database has already run, so it must never be edited — fix mistakes by
// adding a new migration. up runs inside a transaction; it may issue DDL and/or
// rewrite data.
type migration struct {
	version int
	name    string
	up      func(q querier) error
}

// migrations is the ordered, append-only schema history. To evolve the schema,
// append a new entry with the next version; never edit or reorder existing ones.
var migrations = []migration{
	{
		version: 1,
		name:    "initial schema",
		up: func(q querier) error {
			_, err := q.Exec(`
CREATE TABLE objects (
  org TEXT NOT NULL, collection TEXT NOT NULL, key TEXT NOT NULL,
  body BLOB NOT NULL, PRIMARY KEY (org, collection, key));
CREATE TABLE blobs (
  org TEXT NOT NULL, checksum TEXT NOT NULL, content BLOB NOT NULL,
  PRIMARY KEY (org, checksum));
CREATE TABLE orgs (name TEXT PRIMARY KEY);`)
			return err
		},
	},
}

// querier is the subset of *sql.DB / *sql.Tx the data methods use, so the same
// method bodies run either directly or inside a transaction.
type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
}

// Backend is a SQLite-backed store.Backend. Writes route through q (the writer
// *sql.DB, or a *sql.Tx inside Tx); reads route through rq (the reader pool, or
// the same *sql.Tx inside Tx so a transaction observes its own writes). db is
// the writer pool, retained for Begin/Close; rdb is the reader pool (equal to db
// for :memory:, where a second handle would be a distinct database).
//
// The objects table carries the per-node check-in traffic (a GET then a PUT on
// every client run), and the pure-Go driver recompiles a SQL string on every
// Exec/QueryRow. The stObj* fields hold *sql.Stmt prepared once against the
// pools, so that hot path reuses an already-compiled statement instead of
// reparsing per call. They are nil inside a Tx (the Tx struct literal leaves
// them unset): a pool-bound statement would run outside the transaction, so the
// data methods fall back to raw SQL on the tx connection when the stmt is nil.
type Backend struct {
	db  *sql.DB
	rdb *sql.DB
	q   querier
	rq  querier

	stObjGet    *sql.Stmt // reader pool: SELECT one object body
	stObjPut    *sql.Stmt // writer pool: upsert one object
	stObjCreate *sql.Stmt // writer pool: insert-if-absent one object
	stObjDelete *sql.Stmt // writer pool: delete one object

	stHasOrg     *sql.Stmt // reader pool: org-existence probe (run on every request)
	stBlobGet    *sql.Stmt // reader pool: SELECT one blob body
	stBlobHas    *sql.Stmt // reader pool: blob-existence probe (cookbook upload)
	stBlobPut    *sql.Stmt // writer pool: upsert one blob
	stBlobDelete *sql.Stmt // writer pool: delete one blob

	// cw, when non-nil, batches writes through a single coalescing committer
	// (WithGroupCommit). It is set only on the top-level Backend; the Tx view and
	// the coalescer's own per-batch view leave it nil, so writes made through
	// those run directly on their transaction connection.
	cw *coalescer
}

// Option configures an optional Backend behavior at Open time.
type Option func(*config)

// config holds the resolved Open options.
type config struct {
	groupCommit bool
}

// WithGroupCommit enables the coalescing writer: instead of committing every
// write in its own transaction, concurrently-pending writes are batched into a
// single shared transaction and committed once. Under fleet write load this
// amortizes the per-commit WAL syscalls and roughly doubles write throughput; it
// adds a small latency cost to a write that finds no batch to join (a single
// serialized client), so it is opt-in and off by default. The commit contract is
// preserved: a write call does not return until its batch has committed, so a
// following read observes it.
func WithGroupCommit() Option {
	return func(c *config) { c.groupCommit = true }
}

// Open opens (creating if needed) a SQLite database at path and applies migrations.
// path is a file path; ":memory:" yields an ephemeral database (mainly for tests).
func Open(path string, opts ...Option) (*Backend, error) {
	var cfg config
	for _, o := range opts {
		o(&cfg)
	}
	db, err := sql.Open("sqlite", dsnWithPragmas(path))
	if err != nil {
		return nil, err
	}
	// SQLite (even in WAL) admits exactly one writer at a time. With Go's default
	// unbounded pool, concurrent writers each grab a connection, collide on the
	// write lock, and busy-wait via usleep until busy_timeout — burning CPU and
	// thrashing the scheduler under fleet check-in load. Capping the writer pool to
	// a single connection turns that into a cheap in-process queue: writes serialize
	// on Go's connection mutex instead of spinning inside SQLite.
	db.SetMaxOpenConns(1)
	b := &Backend{db: db, q: db, rdb: db, rq: db}

	// WAL admits many readers concurrently with the single writer. Capping the
	// writer pool to one connection is right for writes, but forcing reads through
	// it too discards that concurrency: a dashboard scan then queues behind every
	// in-flight check-in. Give reads their own pool on the same file (query_only so
	// it never takes the write lock) so they run against the last committed
	// snapshot without blocking — or being blocked by — writers. A :memory: path is
	// per-connection, so a second handle would be a distinct empty database; there
	// reads must share the writer pool (memory-backed SQLite is test-only anyway).
	if !isMemory(path) {
		rdb, err := sql.Open("sqlite", dsnWithPragmas(path)+"&_pragma=query_only=true")
		if err != nil {
			db.Close()
			return nil, err
		}
		readers := max(4, runtime.NumCPU())
		rdb.SetMaxOpenConns(readers)
		rdb.SetMaxIdleConns(readers)
		b.rdb = rdb
		b.rq = rdb
	}

	if err := b.migrate(); err != nil {
		b.Close()
		return nil, err
	}
	if err := b.prepare(); err != nil {
		b.Close()
		return nil, err
	}
	if cfg.groupCommit {
		b.cw = newCoalescer(b)
	}
	return b, nil
}

// A writeJob is one queued write awaiting the coalescer. apply performs the
// write against a Backend bound to the shared batch transaction (so it reuses
// the ordinary tx-fallback code path); done receives the write's result once the
// batch the job rode commits.
type writeJob struct {
	apply func(tb *Backend) error
	done  chan error
}

// coalescer serializes all writes through one goroutine that batches whatever is
// queued into a single transaction and commits once, amortizing the per-commit
// WAL syscalls across the batch. A write does not return until its batch has
// committed, preserving the read-after-write contract.
type coalescer struct {
	b    *Backend       // owns db/rdb; used to build per-batch tx views
	ch   chan *writeJob // submitted writes awaiting a batch
	done chan struct{}  // closed when the loop has drained and exited
	// once guards the shutdown, so closing a Backend twice is a no-op rather
	// than a panic on an already-closed channel. Shutdown paths overlap in
	// practice — a deferred stop alongside an explicit one — and crashing the
	// process is a much worse outcome than doing nothing.
	once sync.Once
}

func newCoalescer(b *Backend) *coalescer {
	c := &coalescer{b: b, ch: make(chan *writeJob, 1024), done: make(chan struct{})}
	go c.loop()
	return c
}

// submit enqueues apply and blocks until its batch commits, returning the write's
// result (including the commit error, if the batch failed to commit).
func (c *coalescer) submit(apply func(tb *Backend) error) error {
	j := &writeJob{apply: apply, done: make(chan error, 1)}
	c.ch <- j
	return <-j.done
}

// loop is the single writer goroutine. It blocks for the next job, then greedily
// (and non-blockingly) drains everything already queued into one batch — so the
// batch is size 1 under no load and grows naturally under load, never waiting to
// accumulate and thus never adding latency to grow a batch.
func (c *coalescer) loop() {
	defer close(c.done)
	var batch []*writeJob
	for first := range c.ch {
		batch = append(batch[:0], first)
		for drained := false; !drained; {
			select {
			case j := <-c.ch:
				batch = append(batch, j)
			default:
				drained = true
			}
		}
		c.runBatch(batch)
	}
}

// txView builds a Backend bound to tx: cw and the prepared statements are nil, so
// every write method run against it takes its ordinary in-transaction path (raw
// SQL on tx), exactly like Backend.Tx.
func (c *coalescer) txView(tx *sql.Tx) *Backend {
	return &Backend{db: c.b.db, rdb: c.b.rdb, q: tx, rq: tx}
}

// runBatch applies every job in one transaction and commits once. ErrConflict is
// a normal Create result (the row's statement succeeded as a no-op), so it does
// not abort the batch. Any other apply error, or a commit failure, drops the
// whole batch to isolated single-job retries so one bad write cannot fail its
// innocent neighbors and each job still gets its true result.
func (c *coalescer) runBatch(batch []*writeJob) {
	tx, err := c.b.db.Begin()
	if err != nil {
		c.fail(batch, err)
		return
	}
	tb := c.txView(tx)
	results := make([]error, len(batch))
	for i, j := range batch {
		results[i] = j.apply(tb)
		if results[i] != nil && !errors.Is(results[i], store.ErrConflict) {
			tx.Rollback()
			c.runIsolated(batch)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		c.runIsolated(batch)
		return
	}
	for i, j := range batch {
		j.done <- results[i] // nil or ErrConflict, now committed
	}
}

// runIsolated re-runs each job in its own transaction, used when a batch could
// not be committed as a unit. Re-running an apply is safe: the failed batch was
// rolled back, so each job starts from the last committed state, and apply
// overwrites any result it captures.
func (c *coalescer) runIsolated(batch []*writeJob) {
	for _, j := range batch {
		tx, err := c.b.db.Begin()
		if err != nil {
			j.done <- err
			continue
		}
		err = j.apply(c.txView(tx))
		if err != nil && !errors.Is(err, store.ErrConflict) {
			tx.Rollback()
			j.done <- err
			continue
		}
		if cerr := tx.Commit(); cerr != nil {
			j.done <- cerr
		} else {
			j.done <- err
		}
	}
}

// fail reports err to every job in batch (used when a batch transaction cannot
// even begin).
func (c *coalescer) fail(batch []*writeJob, err error) {
	for _, j := range batch {
		j.done <- err
	}
}

// close stops the writer goroutine and waits for it to drain. After close, no
// further writes may be submitted (the same don't-use-after-Close contract the
// Backend already carries).
func (c *coalescer) close() {
	c.once.Do(func() {
		close(c.ch)
		<-c.done
	})
}

// SQL for the objects-table hot path, shared by the prepared statements and the
// raw fallback used inside a transaction.
const (
	sqlObjGet    = `SELECT body FROM objects WHERE org=? AND collection=? AND key=?`
	sqlObjPut    = `INSERT INTO objects(org,collection,key,body) VALUES(?,?,?,?) ON CONFLICT(org,collection,key) DO UPDATE SET body=excluded.body`
	sqlObjCreate = `INSERT INTO objects(org,collection,key,body) VALUES(?,?,?,?) ON CONFLICT(org,collection,key) DO NOTHING`
	sqlObjDelete = `DELETE FROM objects WHERE org=? AND collection=? AND key=?`

	sqlHasOrg     = `SELECT 1 FROM orgs WHERE name=?`
	sqlBlobGet    = `SELECT content FROM blobs WHERE org=? AND checksum=?`
	sqlBlobHas    = `SELECT 1 FROM blobs WHERE org=? AND checksum=?`
	sqlBlobPut    = `INSERT INTO blobs(org,checksum,content) VALUES(?,?,?) ON CONFLICT(org,checksum) DO UPDATE SET content=excluded.content`
	sqlBlobDelete = `DELETE FROM blobs WHERE org=? AND checksum=?`
)

// prepare compiles the objects-table hot-path statements once, after migration.
// Reads bind to the reader pool, writes to the writer pool; database/sql lazily
// (re)prepares each statement per pooled connection and caches it, so every
// connection reuses a compiled plan. Must run after migrate (the objects table
// must exist) and only on a top-level Backend (never inside a Tx).
func (b *Backend) prepare() error {
	var err error
	if b.stObjGet, err = b.rdb.Prepare(sqlObjGet); err != nil {
		return err
	}
	if b.stObjPut, err = b.db.Prepare(sqlObjPut); err != nil {
		return err
	}
	if b.stObjCreate, err = b.db.Prepare(sqlObjCreate); err != nil {
		return err
	}
	if b.stObjDelete, err = b.db.Prepare(sqlObjDelete); err != nil {
		return err
	}
	if b.stHasOrg, err = b.rdb.Prepare(sqlHasOrg); err != nil {
		return err
	}
	if b.stBlobGet, err = b.rdb.Prepare(sqlBlobGet); err != nil {
		return err
	}
	if b.stBlobHas, err = b.rdb.Prepare(sqlBlobHas); err != nil {
		return err
	}
	if b.stBlobPut, err = b.db.Prepare(sqlBlobPut); err != nil {
		return err
	}
	if b.stBlobDelete, err = b.db.Prepare(sqlBlobDelete); err != nil {
		return err
	}
	return nil
}

// queryRow runs a single-row read through the prepared statement st when set,
// else as raw SQL on rq (the path taken inside a Tx, where st is nil so the read
// uses the transaction's own connection).
func (b *Backend) queryRow(st *sql.Stmt, query string, args ...any) *sql.Row {
	if st != nil {
		return st.QueryRow(args...)
	}
	return b.rq.QueryRow(query, args...)
}

// exec runs a write through the prepared statement st when set, else as raw SQL
// on q (the path taken inside a Tx).
func (b *Backend) exec(st *sql.Stmt, query string, args ...any) (sql.Result, error) {
	if st != nil {
		return st.Exec(args...)
	}
	return b.q.Exec(query, args...)
}

// coalesce runs the write fn either through the group-commit coalescer (when
// enabled on this Backend) or directly. fn is written once against a *Backend:
// run directly it sees the prepared statements and writes in autocommit; run by
// the coalescer it receives a batch-transaction view (cw and stmts nil), so the
// same body takes its in-transaction path (raw SQL on the shared tx). The fn may
// run more than once if a batch fails and falls back to isolated retries, so it
// must be safe to repeat — every write method here is (it only issues SQL and
// overwrites any captured result).
func (b *Backend) coalesce(fn func(tb *Backend) error) error {
	if b.cw != nil {
		return b.cw.submit(fn)
	}
	return fn(b)
}

// isMemory reports whether path designates an in-memory database, whose pages
// live only within a single connection and so cannot be shared by a second pool.
func isMemory(path string) bool {
	return strings.Contains(path, ":memory:") || strings.Contains(path, "mode=memory")
}

// dsnWithPragmas appends connection pragmas to path as modernc _pragma query
// params. Unlike a one-shot db.Exec("PRAGMA ..."), these run on EVERY pooled
// connection, so busy_timeout actually applies pool-wide — without it concurrent
// writers get SQLITE_BUSY instead of waiting. WAL allows concurrent readers
// alongside the single writer; journal_mode is persisted in the file header but
// set here too so a fresh database starts in WAL immediately.
func dsnWithPragmas(path string) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout=5000")
	q.Add("_pragma", "journal_mode=WAL")
	q.Add("_pragma", "foreign_keys=1")
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + q.Encode()
}

// migrate brings the database up to the latest schema version by applying every
// pending migration. It is forward-only and safe to run on every Open.
func (b *Backend) migrate() error { return applyMigrations(b.db, migrations) }

// Version returns the database's current schema version (0 if unmigrated).
func (b *Backend) Version() (int, error) { return schemaVersion(b.db) }

// schemaVersion reads the highest applied migration version, or 0 if none.
func schemaVersion(db *sql.DB) (int, error) {
	var v int
	err := db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&v)
	return v, err
}

// applyMigrations runs every migration in migs whose version exceeds the
// database's recorded version, in order, each inside its own transaction
// (recording the version on success so a migration applies exactly once). A
// database recorded at a higher version than migs knows about is rejected rather
// than run against an unknown schema (forward-only; no silent downgrade). Taking
// migs as a parameter lets tests drive the engine with synthetic migration sets.
func applyMigrations(db *sql.DB, migs []migration) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		return fmt.Errorf("schema_migrations: %w", err)
	}
	current, err := schemaVersion(db)
	if err != nil {
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

func (b *Backend) Get(org, coll, key string) ([]byte, bool, error) {
	var body []byte
	err := b.queryRow(b.stObjGet, sqlObjGet, org, coll, key).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return body, true, nil
}

func (b *Backend) Put(org, coll, key string, val []byte) error {
	return b.coalesce(func(tb *Backend) error {
		_, err := tb.exec(tb.stObjPut, sqlObjPut, org, coll, key, val)
		return err
	})
}

func (b *Backend) Create(org, coll, key string, val []byte) error {
	return b.coalesce(func(tb *Backend) error {
		res, err := tb.exec(tb.stObjCreate, sqlObjCreate, org, coll, key, val)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return store.ErrConflict
		}
		return nil
	})
}

func (b *Backend) Delete(org, coll, key string) ([]byte, bool, error) {
	var old []byte
	var existed bool
	err := b.coalesce(func(tb *Backend) error {
		o, ok, err := tb.Get(org, coll, key)
		if err != nil || !ok {
			old, existed = nil, false
			return err
		}
		if _, err := tb.exec(tb.stObjDelete, sqlObjDelete, org, coll, key); err != nil {
			return err
		}
		old, existed = o, true
		return nil
	})
	return old, existed, err
}

func (b *Backend) Keys(org, coll string) ([]string, error) {
	rows, err := b.rq.Query(
		`SELECT key FROM objects WHERE org=? AND collection=? ORDER BY key`, org, coll)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (b *Backend) Range(org, coll string, fn func(key string, raw []byte) bool) error {
	rows, err := b.rq.Query(
		`SELECT key, body FROM objects WHERE org=? AND collection=? ORDER BY key`, org, coll)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var body []byte
		if err := rows.Scan(&k, &body); err != nil {
			return err
		}
		if !fn(k, body) {
			return nil
		}
	}
	return rows.Err()
}

func (b *Backend) Collections(org string) ([]string, error) {
	rows, err := b.rq.Query(
		`SELECT DISTINCT collection FROM objects WHERE org=? ORDER BY collection`, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var colls []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		colls = append(colls, c)
	}
	return colls, rows.Err()
}

func (b *Backend) PutBlob(org, checksum string, data []byte) error {
	return b.coalesce(func(tb *Backend) error {
		_, err := tb.exec(tb.stBlobPut, sqlBlobPut, org, checksum, data)
		return err
	})
}

func (b *Backend) Blob(org, checksum string) ([]byte, bool, error) {
	var content []byte
	err := b.queryRow(b.stBlobGet, sqlBlobGet, org, checksum).Scan(&content)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return content, true, nil
}

func (b *Backend) HasBlob(org, checksum string) (bool, error) {
	var one int
	err := b.queryRow(b.stBlobHas, sqlBlobHas, org, checksum).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (b *Backend) DeleteBlob(org, checksum string) error {
	return b.coalesce(func(tb *Backend) error {
		_, err := tb.exec(tb.stBlobDelete, sqlBlobDelete, org, checksum)
		return err
	})
}

func (b *Backend) CreateOrg(name string) error {
	return b.coalesce(func(tb *Backend) error {
		res, err := tb.q.Exec(`INSERT INTO orgs(name) VALUES(?) ON CONFLICT(name) DO NOTHING`, name)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return store.ErrConflict
		}
		return nil
	})
}

func (b *Backend) DeleteOrg(name string) (bool, error) {
	var existed bool
	err := b.coalesce(func(tb *Backend) error {
		res, err := tb.q.Exec(`DELETE FROM orgs WHERE name=?`, name)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			existed = false
			return nil
		}
		if _, err := tb.q.Exec(`DELETE FROM objects WHERE org=?`, name); err != nil {
			return err
		}
		if _, err := tb.q.Exec(`DELETE FROM blobs WHERE org=?`, name); err != nil {
			return err
		}
		existed = true
		return nil
	})
	return existed, err
}

func (b *Backend) ListOrgs() ([]string, error) {
	rows, err := b.rq.Query(`SELECT name FROM orgs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

func (b *Backend) HasOrg(name string) (bool, error) {
	var one int
	err := b.queryRow(b.stHasOrg, sqlHasOrg, name).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// Tx runs fn inside a single SQL transaction: returning nil commits, returning a
// non-nil error rolls back and propagates it. The Backend passed to fn routes its
// queries through the transaction, so it observes its own writes and nothing is
// visible to other connections until commit.
func (b *Backend) Tx(fn func(tx store.Backend) error) error {
	sqlTx, err := b.db.Begin()
	if err != nil {
		return err
	}
	// Inside the transaction both reads and writes use the tx connection so it
	// observes its own uncommitted writes (the reader pool would only see the last
	// committed snapshot).
	if err := fn(&Backend{db: b.db, rdb: b.rdb, q: sqlTx, rq: sqlTx}); err != nil {
		_ = sqlTx.Rollback()
		return err
	}
	return sqlTx.Commit()
}

func (b *Backend) Close() error {
	// Stop the coalescing writer first so no batch is mid-commit on the writer
	// pool when we close it (and so its goroutine exits). After this, submitting a
	// write panics — the same don't-use-after-Close contract the Backend carries.
	if b.cw != nil {
		b.cw.close()
	}
	// db.Close releases statements prepared against the pool, but close them
	// explicitly first for orderly teardown (and to release reader-pool
	// statements before that pool closes below). Each is nil-safe to close.
	for _, st := range []*sql.Stmt{
		b.stObjGet, b.stObjPut, b.stObjCreate, b.stObjDelete,
		b.stHasOrg, b.stBlobGet, b.stBlobHas, b.stBlobPut, b.stBlobDelete,
	} {
		if st != nil {
			st.Close()
		}
	}
	err := b.db.Close()
	if b.rdb != nil && b.rdb != b.db {
		if rerr := b.rdb.Close(); err == nil {
			err = rerr
		}
	}
	return err
}
