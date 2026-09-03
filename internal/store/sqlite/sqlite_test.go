package sqlite_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/backendtest"
	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
	_ "modernc.org/sqlite"
)

func TestConformance(t *testing.T) {
	backendtest.Run(t, func(t *testing.T) store.Backend {
		db := filepath.Join(t.TempDir(), "test.db")
		b, err := sqlite.Open(db)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { b.Close() })
		return b
	})
}

func TestPersistsAcrossReopen(t *testing.T) {
	db := filepath.Join(t.TempDir(), "p.db")
	b, err := sqlite.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Put("acme", "nodes", "web", []byte(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b2, err := sqlite.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer b2.Close()
	got, ok, err := b2.Get("acme", "nodes", "web")
	if err != nil || !ok || string(got) != `{"n":1}` {
		t.Fatalf("after reopen: got=%q ok=%v err=%v", got, ok, err)
	}
}

// TestErrorPropagatesAfterClose proves the design's central contract: when the
// database fails, methods return a non-nil error (rather than silently reporting
// not-found). Closing the backend makes every subsequent operation fail.
func TestErrorPropagatesAfterClose(t *testing.T) {
	b, err := sqlite.Open(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Get("acme", "nodes", "web"); err == nil {
		t.Error("Get after Close: want error, got nil")
	}
	if err := b.Put("acme", "nodes", "web", []byte(`{}`)); err == nil {
		t.Error("Put after Close: want error, got nil")
	}
	if err := b.Create("acme", "nodes", "web", []byte(`{}`)); err == nil {
		t.Error("Create after Close: want error, got nil")
	}
	if _, err := b.Keys("acme", "nodes"); err == nil {
		t.Error("Keys after Close: want error, got nil")
	}
	if err := b.Range("acme", "nodes", func(string, []byte) bool { return true }); err == nil {
		t.Error("Range after Close: want error, got nil")
	}
	if err := b.CreateOrg("acme"); err == nil {
		t.Error("CreateOrg after Close: want error, got nil")
	}
}

// TestMigrateIdempotent asserts reopening an existing database does not re-run the
// version insert: schema_migrations holds exactly one row at the current version.
func TestMigrateIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	for range 3 {
		b, err := sqlite.Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var rows, version int
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&rows, &version); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || version != 1 {
		t.Fatalf("schema_migrations: rows=%d version=%d, want 1/1", rows, version)
	}
}
