package api

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
)

// UpgradeValidatorClientACLs takes every validator off the stored ACLs of the
// org's other clients: older versions granted the validator, as creator,
// every permission on each client it registered. Other actors,
// other object types and a validator's own ACL are left alone.
func TestUpgradeValidatorClientACLs(t *testing.T) {
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
			org, err := st.CreateOrg("acme")
			if err != nil {
				t.Fatal(err)
			}
			org.Put("clients", "acme-validator", []byte(`{"name":"acme-validator","validator":true}`))
			org.Put("clients", "val2", []byte(`{"name":"val2","validator":true}`))
			org.Put("clients", "web01", []byte(`{"name":"web01","validator":false}`))
			org.Put("clients", "web02", []byte(`{"name":"web02"}`))

			all := func(clients string) string {
				ace := `{"clients":[` + clients + `],"groups":["admins"],"users":["alice"]}`
				return `{"create":` + ace + `,"delete":` + ace + `,"grant":` + ace + `,"read":` + ace + `,"update":` + ace + `}`
			}
			org.Put("acls", "clients/web01", []byte(all(`"acme-validator","web01"`)))
			org.Put("acls", "clients/web02", []byte(all(`"val2","web02","web01"`)))
			org.Put("acls", "clients/val2", []byte(all(`"val2"`)))
			org.Put("acls", "nodes/web01", []byte(all(`"acme-validator","web01"`)))

			// Baseline: the validator holds update on web01.
			if ok, _ := actorAllowed(org, Actor{Name: "acme-validator", IsClient: true}, "clients", "web01", "update"); !ok {
				t.Fatal("baseline: validator lacks update on web01")
			}

			for range 2 { // idempotent
				if err := UpgradeValidatorClientACLs(org); err != nil {
					t.Fatal(err)
				}
			}

			for _, c := range []struct {
				key  string
				want []string
			}{
				{"clients/web01", []string{"web01"}},
				{"clients/web02", []string{"web02", "web01"}},
				{"clients/val2", []string{"val2"}},
				{"nodes/web01", []string{"acme-validator", "web01"}},
			} {
				typ, obj, _ := strings.Cut(c.key, "/")
				acl, err := loadACL(org, typ, obj)
				if err != nil {
					t.Fatal(err)
				}
				for _, perm := range aclPerms {
					users, clients, groups := aceMembers(acl[perm].(map[string]any))
					if !slices.Equal(clients, c.want) || !slices.Equal(users, []string{"alice"}) || !slices.Equal(groups, []string{"admins"}) {
						t.Errorf("%s %s = users %v clients %v groups %v, want [alice] %v [admins]",
							c.key, perm, users, clients, groups, c.want)
					}
				}
			}
		})
	}
}
