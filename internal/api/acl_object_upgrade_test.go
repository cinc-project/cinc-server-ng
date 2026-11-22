package api

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
)

// legacyClientACLFmt is what versions before 0.21.1 stored for a new client:
// defaultACL() plus the creator, whose kind ("users" or "clients") and name
// fill the verbs.
const legacyClientACLFmt = `{"create":{"%[1]s":["%[2]s"],"%[3]s":[],"groups":["admins","users"]},` +
	`"delete":{"%[1]s":["%[2]s"],"%[3]s":[],"groups":["admins","users"]},` +
	`"grant":{"%[1]s":["%[2]s"],"%[3]s":[],"groups":["admins"]},` +
	`"read":{"%[1]s":["%[2]s"],"%[3]s":[],"groups":["admins","users","clients"]},` +
	`"update":{"%[1]s":["%[2]s"],"%[3]s":[],"groups":["admins","users"]}}`

func legacyByUser(name string) string {
	return fmt.Sprintf(legacyClientACLFmt, "users", name, "clients")
}
func legacyByClient(name string) string {
	return fmt.Sprintf(legacyClientACLFmt, "clients", name, "users")
}

func TestIsLegacyClientACL(t *testing.T) {
	noActors := `{"create":{"users":[],"clients":[],"groups":["users","admins"]},` +
		`"delete":{"users":[],"clients":[],"groups":["admins","users"]},` +
		`"grant":{"users":[],"clients":[],"groups":["admins"]},` +
		`"read":{"users":[],"clients":[],"groups":["admins","users","clients"]},` +
		`"update":{"users":[],"clients":[],"groups":["admins","users"]}}`
	org, err := store.New().CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCreatorACL(org, "clients", "web01", Actor{Name: "pivotal"}); err != nil {
		t.Fatal(err)
	}
	current, _, _ := org.Get("acls", "clients/web01")

	for _, c := range []struct {
		name, raw string
		legacy    bool
		creator   Actor
	}{
		{"created by a user", legacyByUser("pivotal"), true, Actor{Name: "pivotal"}},
		{"created by a client", legacyByClient("acme-validator"), true, Actor{Name: "acme-validator", IsClient: true}},
		{"creator removed, groups reordered", noActors, true, Actor{}},
		{"the shape written now", string(current), false, Actor{}},
		{"a group added to one permission", replaceOnce(legacyByUser("pivotal"), `"grant":{"users":["pivotal"],"clients":[],"groups":["admins"]}`,
			`"grant":{"users":["pivotal"],"clients":[],"groups":["admins","ops"]}`), false, Actor{}},
		{"users taken off update", replaceOnce(legacyByUser("pivotal"), `"update":{"users":["pivotal"],"clients":[],"groups":["admins","users"]}`,
			`"update":{"users":["pivotal"],"clients":[],"groups":["admins"]}`), false, Actor{}},
		{"an actor added to one permission", replaceOnce(legacyByUser("pivotal"), `"update":{"users":["pivotal"]`,
			`"update":{"users":["pivotal","bob"]`), false, Actor{}},
		{"an actor added to every permission", fmt.Sprintf(legacyClientACLFmt, "users", `pivotal","bob`, "clients"), false, Actor{}},
		{"untyped actors", `{"create":{"actors":["pivotal"],"groups":["admins","users"]}}`, false, Actor{}},
		{"a permission missing", `{"create":{"users":[],"clients":[],"groups":["admins","users"]}}`, false, Actor{}},
		{"not JSON", `nope`, false, Actor{}},
	} {
		creator, legacy := isLegacyClientACL([]byte(c.raw))
		if legacy != c.legacy || creator != c.creator {
			t.Errorf("%s: = %+v, %v; want %+v, %v", c.name, creator, legacy, c.creator, c.legacy)
		}
	}
}

// replaceOnce replaces the first old in s, which must be there.
func replaceOnce(s, old, new string) string {
	if !strings.Contains(s, old) {
		panic("replaceOnce: " + old + " not in " + s)
	}
	return strings.Replace(s, old, new, 1)
}

// UpgradeObjectACLs stores the creation ACL of every object that has none and
// of every client still holding the legacy default, on both backends, and is a
// no-op the second time.
func TestUpgradeObjectACLs(t *testing.T) {
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
	for backend, open := range backends {
		t.Run(backend, func(t *testing.T) {
			st := open(t)
			org, err := st.CreateOrg("acme")
			if err != nil {
				t.Fatal(err)
			}
			if err := SeedOrg(org); err != nil {
				t.Fatal(err)
			}
			// An admin narrowed the data container before the upgrade.
			narrowed := mustEncode(policyACL(grant{"admins", aclPerms}))
			put := func(coll, key, val string) {
				t.Helper()
				if err := org.Put(coll, key, []byte(val)); err != nil {
					t.Fatal(err)
				}
			}
			put("acls", "containers/data", string(narrowed))
			for _, c := range []string{"bare", "legacy", "legacy-by-validator", "edited", "current"} {
				put("clients", c, `{"name":"`+c+`"}`)
			}
			put("nodes", "n1", `{"name":"n1"}`)
			put(dataBagsColl, "vault", `{"name":"vault"}`)
			put("cookbooks", "apache/1.0.0", `{}`)
			put("cookbooks", "apache/2.0.0", `{}`)
			put("cookbook_artifacts", "probe/abc", `{}`)
			put(policyRevColl("base"), "r1", `{}`)
			put(policyGroupsColl, "prod", `{"policies":{}}`)
			put("groups", "ops", `{"groupname":"ops"}`)
			put("containers", "custom", `{"containername":"custom"}`)
			edited := replaceOnce(legacyByUser("pivotal"), `"update":{"users":["pivotal"],"clients":[],"groups":["admins","users"]}`,
				`"update":{"users":["pivotal"],"clients":[],"groups":["admins"]}`)
			put("acls", "clients/legacy", legacyByUser("pivotal"))
			put("acls", "clients/legacy-by-validator", legacyByClient("acme-validator"))
			put("acls", "clients/edited", edited)
			if err := writeCreatorACL(org, "clients", "current", Actor{Name: "pivotal"}); err != nil {
				t.Fatal(err)
			}
			current, _, _ := org.Get("acls", "clients/current")

			if err := UpgradeObjectACLs(org); err != nil {
				t.Fatal(err)
			}

			// Every object that had no ACL has one now; the default groups
			// and the custom container still have none.
			for _, key := range []string{"clients/bare", "nodes/n1", "data/vault", "cookbooks/apache",
				"cookbook_artifacts/probe", "policies/base", "policy_groups/prod", "groups/ops"} {
				if _, ok, _ := org.Get("acls", key); !ok {
					t.Errorf("%s has no ACL after the upgrade", key)
				}
			}
			for _, key := range []string{"groups/admins", "groups/users", "containers/custom", "containers/nodes"} {
				if _, ok, _ := org.Get("acls", key); ok {
					t.Errorf("%s was given an ACL", key)
				}
			}
			// The bag took the narrowed container, as stored when upgraded.
			acl, _ := loadACL(org, "data", "vault")
			if _, _, groups := aceMembers(acl["read"].(map[string]any)); !slices.Equal(groups, []string{"admins"}) {
				t.Errorf("vault read groups = %v, want the narrowed container's", groups)
			}
			// Clients: container ACL, the legacy creator kept, and self.
			for _, c := range []struct {
				name           string
				users, clients []string
			}{
				{"bare", []string{}, []string{"bare"}},
				{"legacy", []string{"pivotal"}, []string{"legacy"}},
				{"legacy-by-validator", []string{}, []string{"acme-validator", "legacy-by-validator"}},
			} {
				acl, _ := loadACL(org, "clients", c.name)
				users, clients, groups := aceMembers(acl["update"].(map[string]any))
				slices.Sort(clients)
				if !slices.Equal(users, c.users) || !slices.Equal(clients, c.clients) || !slices.Equal(groups, []string{"admins"}) {
					t.Errorf("%s update = users %v clients %v groups %v, want %v %v [admins]", c.name, users, clients, groups, c.users, c.clients)
				}
			}
			for key, want := range map[string]string{"clients/edited": edited, "clients/current": string(current)} {
				if raw, _, _ := org.Get("acls", key); string(raw) != want {
					t.Errorf("%s rewritten:\n got %s\nwant %s", key, raw, want)
				}
			}

			writes := st.Counts().Writes.Load()
			if err := UpgradeObjectACLs(org); err != nil {
				t.Fatal(err)
			}
			if n := st.Counts().Writes.Load() - writes; n != 0 {
				t.Errorf("second upgrade wrote %d times, want 0", n)
			}
		})
	}
}
