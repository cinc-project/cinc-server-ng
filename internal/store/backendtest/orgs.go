package backendtest

import (
	"errors"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// wantNoOrg asserts err is the refusal of a write to a missing organization.
func wantNoOrg(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, store.ErrOrgNotFound) {
		t.Fatalf("%s = %v, want ErrOrgNotFound", what, err)
	}
}

// wantOrgEmpty asserts org holds nothing: no collections, no web node, no
// blob, no metadata.
func wantOrgEmpty(t *testing.T, b store.Backend, org string) {
	t.Helper()
	if colls, err := b.Collections(org); err != nil || len(colls) != 0 {
		t.Fatalf("Collections(%q) = %v (%v), want none", org, colls, err)
	}
	if _, ok, err := b.Get(org, "clients", "ghost"); err != nil || ok {
		t.Fatalf("Get(%q, clients, ghost): ok=%v err=%v, want absent", org, ok, err)
	}
	if _, ok, err := b.Meta(org, "clients", "ghost"); err != nil || ok {
		t.Fatalf("Meta(%q, clients, ghost): ok=%v err=%v, want absent", org, ok, err)
	}
	if ok, err := b.HasBlob(org, "cafe"); err != nil || ok {
		t.Fatalf("HasBlob(%q, cafe): ok=%v err=%v, want absent", org, ok, err)
	}
}

// writeGhost attempts every kind of write into org.
func writeGhost(b store.Backend, org string) [3]error {
	return [3]error{
		b.Put(org, "clients", "ghost", []byte(`{}`), store.Stamp{}),
		b.Create(org, "group_members", "clients\x00clients\x00ghost", []byte(`{}`), store.Stamp{}),
		b.PutBlob(org, "cafe", []byte("x")),
	}
}

// testWriteToMissingOrgRefused asserts a write into an organization that does
// not exist is refused and stores nothing, while the global space ("") is
// always writable.
func testWriteToMissingOrgRefused(t *testing.T, b store.Backend) {
	errs := writeGhost(b, "acme")
	wantNoOrg(t, "Put", errs[0])
	wantNoOrg(t, "Create", errs[1])
	wantNoOrg(t, "PutBlob", errs[2])
	wantOrgEmpty(t, b, "acme")
	mustPut(t, b, "", "users", "pivotal", `{}`)
}

// testDeletedOrgRecreatedEmpty asserts that writes landing after an org is
// deleted (a request that found the org before the delete) are refused, and
// that an org recreated under the same name starts empty.
func testDeletedOrgRecreatedEmpty(t *testing.T, b store.Backend) {
	if err := b.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	mustPut(t, b, "acme", "nodes", "web", `{}`)
	if _, err := b.DeleteOrg("acme"); err != nil {
		t.Fatal(err)
	}
	errs := writeGhost(b, "acme")
	wantNoOrg(t, "Put after DeleteOrg", errs[0])
	wantNoOrg(t, "Create after DeleteOrg", errs[1])
	wantNoOrg(t, "PutBlob after DeleteOrg", errs[2])
	if err := b.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	wantOrgEmpty(t, b, "acme")
}

// testTxWriteToMissingOrgRefused asserts a transaction cannot write into an
// org that does not exist, or that it dropped, but can into one it created.
func testTxWriteToMissingOrgRefused(t *testing.T, b store.Backend) {
	err := b.Tx(func(tx store.Backend) error {
		return tx.Put("acme", "clients", "ghost", []byte(`{}`), store.Stamp{})
	})
	wantNoOrg(t, "Tx Put into a missing org", err)
	wantOrgEmpty(t, b, "acme")

	if err := b.Tx(func(tx store.Backend) error {
		if err := tx.CreateOrg("acme"); err != nil {
			return err
		}
		return tx.Put("acme", "nodes", "web", []byte(`{}`), store.Stamp{})
	}); err != nil {
		t.Fatalf("Tx Put into an org it created: %v", err)
	}

	err = b.Tx(func(tx store.Backend) error {
		if _, err := tx.DeleteOrg("acme"); err != nil {
			return err
		}
		errs := writeGhost(tx, "acme")
		for _, err := range errs {
			if !errors.Is(err, store.ErrOrgNotFound) {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Tx writes into an org it dropped: %v, want each refused", err)
	}
	if ok, _ := b.HasOrg("acme"); ok {
		t.Fatal("dropped org still exists")
	}
	wantOrgEmpty(t, b, "acme")
}

// testTxOrgDeletedConcurrently asserts that a transaction writing into an org
// that another writer deletes while it is open does not leave its writes
// behind under the org's name.
func testTxOrgDeletedConcurrently(t *testing.T, b store.Backend) {
	var done <-chan struct{}
	var delErr error
	txErr := b.Tx(func(tx store.Backend) error {
		if err := tx.Put("acme", "clients", "ghost", []byte(`{}`), store.Stamp{}); err != nil {
			return err
		}
		done = concurrently(func() { _, delErr = b.DeleteOrg("acme") })
		return nil
	})
	<-done
	if delErr != nil {
		t.Fatalf("DeleteOrg: %v", delErr)
	}
	if txErr != nil && !errors.Is(txErr, store.ErrOrgNotFound) {
		t.Fatalf("Tx = %v, want nil or ErrOrgNotFound", txErr)
	}
	if ok, _ := b.HasOrg("acme"); ok {
		t.Fatal("deleted org still exists")
	}
	wantOrgEmpty(t, b, "acme")
	if err := b.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	wantOrgEmpty(t, b, "acme")
}
