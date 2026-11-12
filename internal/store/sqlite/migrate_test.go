package sqlite

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

func rawDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func currentVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&v); err != nil {
		t.Fatalf("read version: %v", err)
	}
	return v
}

func latest() int { return migrations[len(migrations)-1].version }

// TestOpenAppliesAllMigrations: a fresh database ends at the highest known version.
func TestOpenAppliesAllMigrations(t *testing.T) {
	b, err := Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	got, err := b.Version()
	if err != nil {
		t.Fatal(err)
	}
	if got != latest() {
		t.Fatalf("Version = %d, want %d", got, latest())
	}
}

// TestReopenIsIdempotent: reopening an up-to-date database applies nothing.
func TestReopenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	b1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b1.Close()
	b2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	if v, _ := b2.Version(); v != latest() {
		t.Fatalf("version changed on reopen: %d", v)
	}
}

// TestUpgradeAppliesNewMigrationsAndPreservesData: the production case a
// fresh-create test misses — an existing database gains a new migration's change
// while its pre-existing rows survive.
func TestUpgradeAppliesNewMigrationsAndPreservesData(t *testing.T) {
	db := rawDB(t)
	if err := applyMigrations(db, migrations[:1]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO objects(org,collection,key,body) VALUES('acme','nodes','web',?)`,
		[]byte(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}

	withV2 := append(append([]migration(nil), migrations[:1]...), migration{
		version: 2, name: "add events table",
		up: func(q querier) error {
			_, err := q.Exec(`CREATE TABLE events (id INTEGER PRIMARY KEY)`)
			return err
		},
	})
	if err := applyMigrations(db, withV2); err != nil {
		t.Fatal(err)
	}

	if v := currentVersion(t, db); v != 2 {
		t.Fatalf("version = %d, want 2", v)
	}
	if _, err := db.Exec(`INSERT INTO events(id) VALUES(1)`); err != nil {
		t.Fatalf("v2's change not applied: %v", err)
	}
	var body []byte
	if err := db.QueryRow(
		`SELECT body FROM objects WHERE org='acme' AND collection='nodes' AND key='web'`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"n":1}` {
		t.Fatalf("data not preserved across upgrade: %s", body)
	}
}

// TestRejectsDatabaseNewerThanBinary: forward-only — a database at a higher
// version than the binary knows is a hard error, never a silent run.
func TestRejectsDatabaseNewerThanBinary(t *testing.T) {
	db := rawDB(t)
	if err := applyMigrations(db, migrations); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version) VALUES(99)`); err != nil {
		t.Fatal(err)
	}
	err := applyMigrations(db, migrations)
	if err == nil {
		t.Fatal("expected an error opening a database newer than the binary")
	}
	if !strings.Contains(err.Error(), "upgrade the binary") {
		t.Fatalf("error should tell the operator to upgrade: %v", err)
	}
}

// TestFailingMigrationRollsBackAndStops: a migration that errors leaves the
// database at the prior version with none of its partial effects.
func TestFailingMigrationRollsBackAndStops(t *testing.T) {
	db := rawDB(t)
	if err := applyMigrations(db, migrations[:1]); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	bad := append(append([]migration(nil), migrations[:1]...), migration{
		version: 2, name: "creates a table then fails",
		up: func(q querier) error {
			if _, err := q.Exec(`CREATE TABLE half (id INTEGER)`); err != nil {
				return err
			}
			return boom
		},
	})
	err := applyMigrations(db, bad)
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	if v := currentVersion(t, db); v != 1 {
		t.Fatalf("version advanced despite failure: %d", v)
	}
	if _, err := db.Exec(`INSERT INTO half(id) VALUES(1)`); err == nil {
		t.Fatal("failed migration's table survived rollback")
	}
}

// TestCompatibleWithExistingVersion1Database: a database created by the
// pre-engine code (old ledger shape, version 1 recorded) opens unchanged.
func TestCompatibleWithExistingVersion1Database(t *testing.T) {
	db := rawDB(t)
	if _, err := db.Exec(`
CREATE TABLE objects (org TEXT NOT NULL, collection TEXT NOT NULL, key TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY (org,collection,key));
CREATE TABLE blobs (org TEXT NOT NULL, checksum TEXT NOT NULL, content BLOB NOT NULL, PRIMARY KEY (org,checksum));
CREATE TABLE orgs (name TEXT PRIMARY KEY);
CREATE TABLE schema_migrations (version INTEGER NOT NULL);
INSERT INTO schema_migrations(version) VALUES(1);`); err != nil {
		t.Fatal(err)
	}
	if err := applyMigrations(db, migrations); err != nil {
		t.Fatalf("migrating an existing v1 database: %v", err)
	}
	if v := currentVersion(t, db); v != latest() {
		t.Fatalf("version = %d, want %d", v, latest())
	}
}

// TestObjectsWrittenBeforeTimesHaveNone: a row written before objects carried
// times reads back with unknown (zero) times, not invented ones; its next write
// records the update, and its creation time stays unknown.
func TestObjectsWrittenBeforeTimesHaveNone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
CREATE TABLE objects (org TEXT NOT NULL, collection TEXT NOT NULL, key TEXT NOT NULL, body BLOB NOT NULL, PRIMARY KEY (org,collection,key));
CREATE TABLE blobs (org TEXT NOT NULL, checksum TEXT NOT NULL, content BLOB NOT NULL, PRIMARY KEY (org,checksum));
CREATE TABLE orgs (name TEXT PRIMARY KEY);
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
INSERT INTO schema_migrations(version) VALUES(1);
INSERT INTO objects(org,collection,key,body) VALUES('acme','nodes','web','{}');`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	m, ok, err := b.Meta("acme", "nodes", "web")
	if err != nil || !ok {
		t.Fatalf("Meta: ok=%v err=%v", ok, err)
	}
	if !m.CreatedAt.IsZero() || !m.UpdatedAt.IsZero() || m.UpdatedBy != "" {
		t.Fatalf("meta of a pre-existing row = %+v, want unknown", m)
	}
	at := time.Date(2026, 11, 12, 2, 7, 41, 0, time.UTC)
	if err := b.Put("acme", "nodes", "web", []byte(`{"v":2}`), store.Stamp{At: at, By: "users/alice"}); err != nil {
		t.Fatal(err)
	}
	m, _, _ = b.Meta("acme", "nodes", "web")
	if !m.CreatedAt.IsZero() || !m.UpdatedAt.Equal(at) || m.UpdatedBy != "users/alice" {
		t.Fatalf("meta after an update = %+v, want unknown creation, updated %v by users/alice", m, at)
	}
}
