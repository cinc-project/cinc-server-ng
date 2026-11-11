package api

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
)

// UpgradeACLActors types the untyped actors lists older versions stored, by
// what each name is when it runs: after it, a client created under a user's
// name gets none of the grants the old list gave that user.
func TestUpgradeACLActors(t *testing.T) {
	backends := map[string]func(t *testing.T) *store.Store{
		"memory": func(t *testing.T) *store.Store { return store.New() },
		"sqlite": func(t *testing.T) *store.Store {
			be, err := sqlite.Open(filepath.Join(t.TempDir(), "acl.db"))
			if err != nil {
				t.Fatal(err)
			}
			st := store.NewWithBackend(be)
			t.Cleanup(func() { st.Close() })
			return st
		},
	}
	for name, open := range backends {
		t.Run(name, func(t *testing.T) {
			st := open(t)
			g := st.Global()
			org, err := st.CreateOrg("acme")
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range []string{"alice", "both"} {
				g.Put("users", u, []byte(`{"name":"`+u+`"}`))
			}
			for _, c := range []string{"web01", "both"} {
				org.Put("clients", c, []byte(`{"name":"`+c+`"}`))
			}
			legacy := `{"read":{"actors":["alice","web01","both","ghost"],"groups":["admins"]},` +
				`"update":{"actors":[],"groups":[]}}`
			org.Put("acls", "nodes/n1", []byte(legacy))
			g.Put("acls", "users/alice", []byte(`{"grant":{"actors":["alice","ghost"],"groups":[]}}`))

			// Baseline: an untyped list grants nothing.
			if ok, _ := actorAllowed(org, Actor{Name: "alice"}, "nodes", "n1", "read"); ok {
				t.Fatal("an untyped actors list granted read before the upgrade")
			}

			for range 2 { // idempotent
				if err := UpgradeACLActors(g, nil); err != nil {
					t.Fatal(err)
				}
				if err := UpgradeACLActors(g, org); err != nil {
					t.Fatal(err)
				}
			}

			acl, _ := loadACL(org, "nodes", "n1")
			users, clients, groups := aceMembers(acl["read"].(map[string]any))
			if !slices.Equal(users, []string{"alice", "both"}) || !slices.Equal(clients, []string{"web01", "both"}) ||
				!slices.Equal(groups, []string{"admins"}) {
				t.Errorf("read = users %v clients %v groups %v, want [alice both] [web01 both] [admins]", users, clients, groups)
			}
			if _, has := acl["read"].(map[string]any)["actors"]; has {
				t.Error("the untyped actors list survived the upgrade")
			}
			uacl, _ := loadACL(g, "users", "alice")
			if users, clients, _ := aceMembers(uacl["grant"].(map[string]any)); !slices.Equal(users, []string{"alice"}) || len(clients) != 0 {
				t.Errorf("user ACL grant = users %v clients %v, want [alice] []", users, clients)
			}

			for _, c := range []struct {
				actor Actor
				want  bool
			}{
				{Actor{Name: "alice"}, true},
				{Actor{Name: "web01", IsClient: true}, true},
				{Actor{Name: "both"}, true},
				{Actor{Name: "both", IsClient: true}, true},
				// Created after the upgrade under the user's name.
				{Actor{Name: "alice", IsClient: true}, false},
				{Actor{Name: "web01"}, false},
				{Actor{Name: "ghost"}, false},
			} {
				if got, _ := actorAllowed(org, c.actor, "nodes", "n1", "read"); got != c.want {
					t.Errorf("%+v read = %v, want %v", c.actor, got, c.want)
				}
			}
		})
	}
}
