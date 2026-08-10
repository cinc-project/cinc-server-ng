package api

import (
	"fmt"
	"maps"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// The cached reverse index must agree with the uncached scan for every shape of
// group graph, and must notice changes. If those two ever diverge, enforcement
// silently grants or denies the wrong thing.

func TestCachedGroupsMatchUncachedScan(t *testing.T) {
	st := store.New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	api := New(st)

	put := func(name string, users, clients, groups []string) {
		t.Helper()
		if err := org.Put("groups", name, mustEncode(groupDoc(name, users, clients, groups))); err != nil {
			t.Fatal(err)
		}
	}
	put("users", []string{"alice"}, nil, nil)
	put("clients", nil, []string{"node1"}, nil)
	put("admins", []string{"root"}, nil, []string{"users"})  // nests users
	put("everyone", nil, nil, []string{"admins", "clients"}) // nests admins+clients
	put("cycle-a", []string{"loopy"}, nil, []string{"cycle-b"})
	put("cycle-b", nil, nil, []string{"cycle-a"}) // deliberate cycle

	actors := []Actor{
		{Name: "alice"},
		{Name: "root"},
		{Name: "node1", IsClient: true},
		{Name: "node1"}, // same name as a client, but as a user: no membership
		{Name: "alice", IsClient: true},
		{Name: "loopy"},
		{Name: "nobody"},
	}
	for _, actor := range actors {
		want, err := actorGroups(org, actor)
		if err != nil {
			t.Fatal(err)
		}
		got, err := api.actorGroups(org, actor)
		if err != nil {
			t.Fatal(err)
		}
		if !maps.Equal(got, want) {
			t.Errorf("actor %+v: cached %v, uncached %v", actor, got, want)
		}
	}
}

func TestCachedGroupsFollowNestingTransitively(t *testing.T) {
	st := store.New()
	org, _ := st.CreateOrg("acme")
	api := New(st)
	put := func(name string, users, groups []string) {
		if err := org.Put("groups", name, mustEncode(groupDoc(name, users, nil, groups))); err != nil {
			t.Fatal(err)
		}
	}
	put("inner", []string{"alice"}, nil)
	put("middle", nil, []string{"inner"})
	put("outer", nil, []string{"middle"})

	got, err := api.actorGroups(org, Actor{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"inner", "middle", "outer"} {
		if !got[want] {
			t.Errorf("alice should be in %q transitively; got %v", want, got)
		}
	}
}

// The index must be rebuilt when groups change and reused when they do not.
func TestCachedGroupsRebuildOnlyWhenGroupsChange(t *testing.T) {
	st := store.New()
	org, _ := st.CreateOrg("acme")
	api := New(st)
	if err := org.Put("groups", "users", mustEncode(groupDoc("users", []string{"alice"}, nil, nil))); err != nil {
		t.Fatal(err)
	}

	first, err := api.groups.get(org)
	if err != nil {
		t.Fatal(err)
	}
	// A write to another collection must not invalidate the index.
	if err := org.Put("nodes", "web01", []byte(`{"name":"web01"}`)); err != nil {
		t.Fatal(err)
	}
	again, err := api.groups.get(org)
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Error("index rebuilt despite groups being unchanged")
	}

	// A group write must invalidate it.
	if err := org.Put("groups", "users", mustEncode(groupDoc("users", []string{"alice", "bob"}, nil, nil))); err != nil {
		t.Fatal(err)
	}
	after, err := api.groups.get(org)
	if err != nil {
		t.Fatal(err)
	}
	if after == first {
		t.Fatal("index not rebuilt after a group write")
	}
	if got, _ := api.actorGroups(org, Actor{Name: "bob"}); !got["users"] {
		t.Errorf("bob should be in users after the update; got %v", got)
	}
}

// Each organization gets its own membership, never another's.
func TestCachedGroupsAreScopedPerOrg(t *testing.T) {
	st := store.New()
	a, _ := st.CreateOrg("alpha")
	b, _ := st.CreateOrg("beta")
	api := New(st)
	if err := a.Put("groups", "admins", mustEncode(groupDoc("admins", []string{"alice"}, nil, nil))); err != nil {
		t.Fatal(err)
	}
	if err := b.Put("groups", "admins", mustEncode(groupDoc("admins", []string{"bob"}, nil, nil))); err != nil {
		t.Fatal(err)
	}
	if got, _ := api.actorGroups(a, Actor{Name: "alice"}); !got["admins"] {
		t.Errorf("alice should be an alpha admin; got %v", got)
	}
	if got, _ := api.actorGroups(b, Actor{Name: "alice"}); got["admins"] {
		t.Errorf("alice must not be a beta admin; got %v", got)
	}
}

// Membership resolution must not get slower as the fleet grows.
func BenchmarkActorGroupsCached(b *testing.B) {
	for _, fleet := range []int{128, 512, 2048} {
		b.Run(fmt.Sprint(fleet), func(b *testing.B) {
			st := store.New()
			org, _ := st.CreateOrg("acme")
			api := New(st)
			clients := make([]string, fleet)
			for i := range fleet {
				clients[i] = fmt.Sprintf("node%d", i)
			}
			if err := org.Put("groups", "clients", mustEncode(groupDoc("clients", nil, clients, nil))); err != nil {
				b.Fatal(err)
			}
			actor := Actor{Name: "node0", IsClient: true}
			b.ResetTimer()
			for range b.N {
				if _, err := api.actorGroups(org, actor); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
