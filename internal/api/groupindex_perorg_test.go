package api

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// stallingBackend holds a Range over one org's groups until released, standing
// in for an org whose index takes long to build (a large fleet, a slow disk).
type stallingBackend struct {
	store.Backend
	org      string
	armed    atomic.Bool
	once     sync.Once
	entered  chan struct{}
	released chan struct{}
}

func (b *stallingBackend) Range(org, coll string, fn func(string, []byte) bool) error {
	if b.armed.Load() && org == b.org && coll == "groups" {
		b.once.Do(func() {
			close(b.entered)
			<-b.released
		})
	}
	return b.Backend.Range(org, coll, fn)
}

// One org's index rebuild, however long, must not hold up another org's
// authorization checks or membership rows: the cache is shared by every org on
// the server, so a lock over all of it lets one tenant stall all the others.
func TestGroupIndexRebuildDoesNotBlockOtherOrgs(t *testing.T) {
	be := &stallingBackend{
		Backend: store.NewMemoryBackend(), org: "acme",
		entered: make(chan struct{}), released: make(chan struct{}),
	}
	st := store.NewWithBackend(be)
	acme, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	globex, err := st.CreateOrg("globex")
	if err != nil {
		t.Fatal(err)
	}
	for _, org := range []*store.Org{acme, globex} {
		if err := seedAuthz(org); err != nil {
			t.Fatal(err)
		}
	}
	c := newGroupIndexCache()
	st.Watch(c.observe)
	if _, err := c.get(globex); err != nil {
		t.Fatal(err)
	}

	// Baseline: with nothing stalled, globex is served and patched as usual.
	if err := addClientToOrgGroup(globex, "clients", "node0"); err != nil {
		t.Fatal(err)
	}
	idx, err := c.get(globex)
	if err != nil {
		t.Fatal(err)
	}
	if !idx.membership(Actor{Name: "node0", IsClient: true})["clients"] {
		t.Fatal("baseline: node0 is not in globex's clients group")
	}

	// A group write in acme, then a check in acme that rebuilds and stalls.
	if err := acme.Put("groups", "mygroup", groupJSON("mygroup", "", nil, nil, nil)); err != nil {
		t.Fatal(err)
	}
	be.armed.Store(true)
	stalled := make(chan error, 1)
	go func() {
		_, err := c.get(acme)
		stalled <- err
	}()
	<-be.entered
	defer func() {
		close(be.released)
		if err := <-stalled; err != nil {
			t.Error(err)
		}
	}()

	done := make(chan error, 1)
	go func() {
		// A registration in globex (a membership row) and a check there.
		if err := addClientToOrgGroup(globex, "clients", "node1"); err != nil {
			done <- err
			return
		}
		idx, err := c.get(globex)
		if err == nil && !idx.membership(Actor{Name: "node1", IsClient: true})["clients"] {
			t.Error("node1 is not in globex's clients group")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("globex's registration and check waited on acme's rebuild")
	}
}
