package store_test

import (
	"testing"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// The authorization layer caches a reverse index of group membership, which is
// only safe if it can tell that groups changed. The signal has to live in the
// store, because group writes happen from several packages and any call site
// missed by a hand-maintained invalidation would silently serve stale
// authorization.

func TestGroupsGenerationChangesOnGroupWrite(t *testing.T) {
	st := store.New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	before := org.GroupsGeneration()

	if err := org.Put("groups", "admins", []byte(`{"name":"admins"}`)); err != nil {
		t.Fatal(err)
	}
	if org.GroupsGeneration() == before {
		t.Fatal("generation unchanged after a groups Put")
	}

	mid := org.GroupsGeneration()
	if err := org.Create("groups", "devs", []byte(`{"name":"devs"}`)); err != nil {
		t.Fatal(err)
	}
	if org.GroupsGeneration() == mid {
		t.Fatal("generation unchanged after a groups Create")
	}

	mid = org.GroupsGeneration()
	if _, _, err := org.Delete("groups", "devs"); err != nil {
		t.Fatal(err)
	}
	if org.GroupsGeneration() == mid {
		t.Fatal("generation unchanged after a groups Delete")
	}
}

func TestGroupsGenerationIgnoresOtherCollections(t *testing.T) {
	st := store.New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	before := org.GroupsGeneration()
	for range 10 {
		if err := org.Put("nodes", "web01", []byte(`{"name":"web01"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if got := org.GroupsGeneration(); got != before {
		t.Fatalf("generation moved on non-group writes: %d -> %d", before, got)
	}
}

// A write made inside a transaction must move the generation too, or a cache
// built before the transaction would survive it.
func TestGroupsGenerationChangesInsideTx(t *testing.T) {
	st := store.New()
	if _, err := st.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	org, _, _ := st.Org("acme")
	before := org.GroupsGeneration()

	if err := st.Tx(func(tx *store.Store) error {
		txOrg, _, err := tx.Org("acme")
		if err != nil {
			return err
		}
		return txOrg.Put("groups", "admins", []byte(`{"name":"admins"}`))
	}); err != nil {
		t.Fatal(err)
	}
	if org.GroupsGeneration() == before {
		t.Fatal("generation unchanged after a groups write inside a transaction")
	}
}

// Every handle onto the same store must observe the same generation, since the
// cache is keyed by it.
func TestGroupsGenerationSharedAcrossHandles(t *testing.T) {
	st := store.New()
	if _, err := st.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	a, _, _ := st.Org("acme")
	b, _, _ := st.Org("acme")
	if err := a.Put("groups", "admins", []byte(`{"name":"admins"}`)); err != nil {
		t.Fatal(err)
	}
	if a.GroupsGeneration() != b.GroupsGeneration() {
		t.Fatalf("handles disagree: %d vs %d", a.GroupsGeneration(), b.GroupsGeneration())
	}
}
