package api

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// newIndexedOrg returns an org with the default groups seeded and a cache with
// its index already built, which is the state observe() patches in place.
func newIndexedOrg(t *testing.T) (*store.Org, *groupIndexCache) {
	t.Helper()
	st := store.New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := seedAuthz(org); err != nil {
		t.Fatal(err)
	}
	c := newGroupIndexCache()
	// Wire the cache to the write stream the way api.New does, so a membership
	// row written below reaches observe().
	st.Watch(c.observe)
	if _, err := c.get(org); err != nil {
		t.Fatal(err)
	}
	return org, c
}

// observe() folds each membership row into the cached index in place — that is
// what keeps a fleet bootstrap linear — while authorization checks read the same
// index concurrently. Both must be synchronized against the index itself, not
// just against the map that holds it. Run under -race (which `make test` does),
// this fails on unsynchronized maps.
func TestGroupIndexConcurrentObserveAndMembership(t *testing.T) {
	org, c := newIndexedOrg(t)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 2000 {
			c.observe(store.Event{
				Org: "acme", Collection: groupMembersColl,
				Key: memberKey("clients", memberClients, fmt.Sprintf("node%d", i)),
			})
		}
	}()
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 2000 {
				idx, err := c.get(org)
				if err != nil {
					t.Error(err)
					return
				}
				_ = idx.membership(Actor{Name: "node7", IsClient: true})
			}
		}()
	}
	wg.Wait()
}

// A rebuild is triggered by a write to a group *document*, and it re-reads the
// membership rows. Rows folded in since the last build must survive it: they are
// the only record that a registered client belongs to the org's clients group,
// and losing one denies that client every permission the group carries.
func TestGroupIndexRebuildKeepsMembershipRows(t *testing.T) {
	org, c := newIndexedOrg(t)

	if err := addClientToOrgGroup(org, "clients", "node1"); err != nil {
		t.Fatal(err)
	}
	idx, err := c.get(org)
	if err != nil {
		t.Fatal(err)
	}
	if !idx.membership(Actor{Name: "node1", IsClient: true})["clients"] {
		t.Fatal("node1 is not in the clients group before the rebuild")
	}

	// Any write to a group document advances the generation and forces a rebuild.
	if err := org.Put("groups", "admins", mustEncode(groupDoc("admins", []string{"alice"}, nil, nil))); err != nil {
		t.Fatal(err)
	}
	idx, err = c.get(org)
	if err != nil {
		t.Fatal(err)
	}
	if !idx.membership(Actor{Name: "node1", IsClient: true})["clients"] {
		t.Error("the rebuild dropped node1's membership row")
	}
	if !idx.membership(Actor{Name: "alice"})["admins"] {
		t.Error("the rebuild missed the group document it was triggered by")
	}
}
