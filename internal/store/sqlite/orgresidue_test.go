package sqlite_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
)

// openWithResidue opens a database holding rows under org without org
// existing, as a write that raced the org's deletion could leave them before
// writes were refused.
func openWithResidue(t *testing.T, org string) *sqlite.Backend {
	t.Helper()
	path := filepath.Join(t.TempDir(), "r.db")
	b, err := sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range [][2]string{{"clients", "ghost"}, {"group_members", "clients\x00clients\x00ghost"}} {
		if _, err := db.Exec(`INSERT INTO objects(org,collection,key,body) VALUES(?,?,?,'{}')`, org, row[0], row[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO blobs(org,checksum,content) VALUES(?,'cafe','x')`, org); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = sqlite.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func wantNoResidue(t *testing.T, b store.Backend, org string) {
	t.Helper()
	if colls, err := b.Collections(org); err != nil || len(colls) != 0 {
		t.Fatalf("Collections = %v (%v), want none", colls, err)
	}
	if ok, _ := b.HasBlob(org, "cafe"); ok {
		t.Fatal("residue blob survived CreateOrg")
	}
}

// TestCreateOrgPurgesResidue asserts a created org starts empty even if rows
// were left under its name.
func TestCreateOrgPurgesResidue(t *testing.T) {
	b := openWithResidue(t, "acme")
	if err := b.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	wantNoResidue(t, b, "acme")
}

// TestTxCreateOrgPurgesResidue is the same through a transaction, as the API
// creates organizations.
func TestTxCreateOrgPurgesResidue(t *testing.T) {
	b := openWithResidue(t, "acme")
	if err := b.Tx(func(tx store.Backend) error {
		if err := tx.CreateOrg("acme"); err != nil {
			return err
		}
		wantNoResidue(t, tx, "acme")
		return tx.Put("acme", "nodes", "web", []byte(`{}`), store.Stamp{})
	}); err != nil {
		t.Fatal(err)
	}
	if colls, _ := b.Collections("acme"); len(colls) != 1 || colls[0] != "nodes" {
		t.Fatalf("Collections = %v, want [nodes]", colls)
	}
}

// TestGroupCommitRefusesMissingOrg covers the coalescing writer, whose
// batches run each write through a shared transaction.
func TestGroupCommitRefusesMissingOrg(t *testing.T) {
	path := filepath.Join(t.TempDir(), "g.db")
	b, err := sqlite.Open(path, sqlite.WithGroupCommit())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Put("acme", "nodes", "web", []byte(`{}`), store.Stamp{}); err == nil {
		t.Fatal("group-commit Put into a missing org succeeded")
	}
	if err := b.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	if err := b.Put("acme", "nodes", "web", []byte(`{}`), store.Stamp{}); err != nil {
		t.Fatal(err)
	}
}
