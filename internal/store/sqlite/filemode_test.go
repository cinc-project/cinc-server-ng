//go:build unix

package sqlite_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
)

// withUmask runs the test body under a permissive umask, so a file mode that
// only looks private because of the caller's umask is caught.
func withUmask(t *testing.T, mask int) {
	t.Helper()
	old := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(old) })
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s: mode %04o, want %04o", filepath.Base(path), got, want)
	}
}

// The database holds user passwords, keys and data bags, so a fresh database
// and its WAL and shared-memory files are owner-only whatever the umask.
func TestOpenCreatesOwnerOnlyFiles(t *testing.T) {
	withUmask(t, 0)
	db := filepath.Join(t.TempDir(), "cinc.db")
	b, err := sqlite.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	if err := b.Put("acme", "nodes", "web", []byte(`{"n":1}`), store.Stamp{}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{db, db + "-wal", db + "-shm"} {
		assertMode(t, p, 0o600)
	}
}

// A database created by an earlier version (world-readable under umask 022)
// is tightened on open: group and other permissions are removed from the
// database and any WAL or shared-memory file next to it.
func TestOpenTightensExistingFiles(t *testing.T) {
	withUmask(t, 0)
	dir := t.TempDir()
	db := filepath.Join(dir, "cinc.db")
	b, err := sqlite.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Put("acme", "nodes", "web", []byte(`{"n":1}`), store.Stamp{}); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	// Leave a stale WAL behind, as a crash would, and loosen everything.
	if err := os.WriteFile(db+"-wal", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{db, db + "-wal"} {
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	b2, err := sqlite.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b2.Close() })
	if err := b2.Put("acme", "nodes", "db", []byte(`{"n":2}`), store.Stamp{}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{db, db + "-wal", db + "-shm"} {
		assertMode(t, p, 0o600)
	}
}

// Group permissions are removed too, not only world-readable bits.
func TestOpenStripsGroupPermissions(t *testing.T) {
	withUmask(t, 0)
	db := filepath.Join(t.TempDir(), "cinc.db")
	b, err := sqlite.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(db, 0o640); err != nil {
		t.Fatal(err)
	}
	b2, err := sqlite.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b2.Close() })
	assertMode(t, db, 0o600)
}
