package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
)

// erchef gives every object it creates its container's ACL merged with the
// creator's (oc_chef_authz:create_entity_with_container_acl), whichever handler
// creates it. These pin that for the kinds made by dedicated handlers rather
// than createObject/createActor, and for objects that reach the store without
// a request: loaded from a chef-repo or state directory, or created by an older
// version.

// granularACL reads an object's ACL in the granular view: perm -> users,
// clients and groups, each sorted.
func granularACL(t *testing.T, srv *Server, url string) map[string]map[string][]string {
	t.Helper()
	code, body := signedBody(t, signed(t, srv, "GET", url+"?detail=granular", ""))
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", url, code, body)
	}
	var acl map[string]struct {
		Users   []string `json:"users"`
		Clients []string `json:"clients"`
		Groups  []string `json:"groups"`
	}
	if err := json.Unmarshal(body, &acl); err != nil {
		t.Fatalf("%s: %v", url, err)
	}
	out := map[string]map[string][]string{}
	for perm, ace := range acl {
		m := map[string][]string{"users": ace.Users, "clients": ace.Clients, "groups": ace.Groups}
		for k := range m {
			m[k] = slices.Clone(m[k])
			if m[k] == nil {
				m[k] = []string{}
			}
			slices.Sort(m[k])
		}
		out[perm] = m
	}
	return out
}

// narrowReadUpdate leaves read and update on the named container to the
// admins alone.
func narrowReadUpdate(t *testing.T, srv *Server, base, container string) {
	t.Helper()
	for _, perm := range []string{"read", "update"} {
		mustStatus(t, signed(t, srv, "PUT", base+"/containers/"+container+"/_acl/"+perm,
			fmt.Sprintf(`{%q:{"actors":[],"groups":["admins"]}}`, perm)), http.StatusOK)
	}
}

// TestDedicatedCreatesTakeContainerACL narrows read and update on each
// container to the admins, has a plain member create an object of that kind
// through its dedicated handler, and checks the new object's ACL is the
// narrowed container's plus the member. Before, each fell back to the object
// default, which gives the users group update and the clients group read.
func TestDedicatedCreatesTakeContainerACL(t *testing.T) {
	const ident = "1111111111111111111111111111111111111111"
	cases := []struct {
		container, method, path, body string
		acls                          []string // ACL paths the request creates
	}{
		{"data", "POST", "/data", `{"name":"secrets"}`, []string{"/data/secrets"}},
		{"cookbooks", "PUT", "/cookbooks/apache/1.0.0", cookbook("apache", "1.0.0"), []string{"/cookbooks/apache"}},
		{"cookbook_artifacts", "PUT", "/cookbook_artifacts/probe/" + ident, fmt.Sprintf(artifactBody, ident), []string{"/cookbook_artifacts/probe"}},
		{"policies", "POST", "/policies/base/revisions", fmt.Sprintf(policyBody, "aaaa", "base"), []string{"/policies/base"}},
		{"policy_groups", "PUT", "/policy_groups/prod/policies/web", fmt.Sprintf(policyBody, "bbbb", "web"), []string{"/policy_groups/prod"}},
		// A push that creates the policy too gives the policy its container's ACL.
		{"policies", "PUT", "/policy_groups/dev/policies/db", fmt.Sprintf(policyBody, "cccc", "db"), []string{"/policies/db"}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			srv, base, bob := memberSetup(t)
			narrowReadUpdate(t, srv, base, c.container)
			code, body := signedBody(t, signedAs(t, "bob", bob, c.method, base+c.path, c.body))
			if code != http.StatusCreated && code != http.StatusOK {
				t.Fatalf("%s %s = %d: %s", c.method, c.path, code, body)
			}
			for _, p := range c.acls {
				acl := granularACL(t, srv, base+p+"/_acl")
				for _, perm := range []string{"read", "update"} {
					if !slices.Equal(acl[perm]["groups"], []string{"admins"}) {
						t.Errorf("%s %s groups = %v, want the narrowed container's [admins]", p, perm, acl[perm]["groups"])
					}
				}
				for _, perm := range []string{"create", "read", "update", "delete", "grant"} {
					if !slices.Equal(acl[perm]["users"], []string{"bob"}) {
						t.Errorf("%s %s users = %v, want the creator [bob]", p, perm, acl[perm]["users"])
					}
				}
			}
		})
	}
}

// TestNewDataBagUnreadableByClientsAfterNarrowing: a node's key reads a data
// bag through the clients group's read on the data container. Once an admin
// takes that away, a bag created afterwards is closed to it.
func TestNewDataBagUnreadableByClientsAfterNarrowing(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	node := createClientAndKey(t, srv, base, "web01")
	mustStatus(t, signed(t, srv, "POST", base+"/data", `{"name":"before"}`), http.StatusCreated)
	// Baseline: a client reads a bag under the default ACLs.
	mustStatus(t, signedAs(t, "web01", node, "GET", base+"/data/before", ""), http.StatusOK)

	narrowReadUpdate(t, srv, base, "data")
	mustStatus(t, signed(t, srv, "POST", base+"/data", `{"name":"after"}`), http.StatusCreated)
	mustStatus(t, signedAs(t, "web01", node, "GET", base+"/data/after", ""), http.StatusForbidden)
}

// TestNewGroupTakesStoredGroupsContainerACL: a new group copies the groups
// container's ACL as it is stored now, not erchef's default for it.
func TestNewGroupTakesStoredGroupsContainerACL(t *testing.T) {
	srv, base, bob := memberSetup(t)
	mustStatus(t, signed(t, srv, "POST", base+"/groups", `{"groupname":"before"}`), http.StatusCreated)
	// Baseline: the users group reads a group under the default ACLs.
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/groups/before", ""), http.StatusOK)

	mustStatus(t, signed(t, srv, "PUT", base+"/containers/groups/_acl/read",
		`{"read":{"actors":[],"groups":["admins"]}}`), http.StatusOK)
	mustStatus(t, signed(t, srv, "POST", base+"/groups", `{"groupname":"after"}`), http.StatusCreated)
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/groups/after", ""), http.StatusForbidden)
	acl := granularACL(t, srv, base+"/groups/after/_acl")
	if !slices.Equal(acl["read"]["groups"], []string{"admins"}) {
		t.Errorf("new group read groups = %v, want [admins]", acl["read"]["groups"])
	}
}

// TestCreateGroupIgnoresMembers: erchef's oc_chef_group:create_record keeps
// only the group's name, so a create body's members are not stored. Kept, a
// name that does not exist yet would make whatever is later created under it a
// member.
func TestCreateGroupIgnoresMembers(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	mustStatus(t, signed(t, srv, "POST", base+"/groups",
		`{"groupname":"ops","users":["pivotal"],"clients":["future"],"groups":["admins"]}`), http.StatusCreated)
	createClientAndKey(t, srv, base, "future")

	code, body := signedBody(t, signed(t, srv, "GET", base+"/groups/ops", ""))
	if code != http.StatusOK {
		t.Fatalf("GET group = %d: %s", code, body)
	}
	var g struct {
		Actors, Users, Clients, Groups []string
	}
	if err := json.Unmarshal(body, &g); err != nil {
		t.Fatal(err)
	}
	if len(g.Actors)+len(g.Users)+len(g.Clients)+len(g.Groups) != 0 {
		t.Errorf("new group members = %+v, want none", g)
	}
}

// TestCreateContainerConflicts: erchef answers 409 for a container that
// exists; it must not be overwritten.
func TestCreateContainerConflicts(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	mustStatus(t, signed(t, srv, "POST", base+"/containers", `{"containername":"nodes","containerpath":"elsewhere"}`), http.StatusConflict)
	code, body := signedBody(t, signed(t, srv, "GET", base+"/containers/nodes", ""))
	if code != http.StatusOK {
		t.Fatalf("GET nodes container = %d: %s", code, body)
	}
	var c struct {
		ContainerPath string `json:"containerpath"`
	}
	json.Unmarshal(body, &c)
	if c.ContainerPath != "nodes" {
		t.Errorf("nodes containerpath = %q, want it untouched", c.ContainerPath)
	}
}

// TestNewContainerACLIsItsCreatorOnly: a container does not inherit its
// parent's ACL (merge_acl_from_container skips containers), so bifrost's
// creator grant is all it holds.
func TestNewContainerACLIsItsCreatorOnly(t *testing.T) {
	srv, base, bob := memberSetup(t)
	// Baseline: the users group reads a default container.
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/containers/nodes", ""), http.StatusOK)

	mustStatus(t, signed(t, srv, "POST", base+"/containers", `{"containername":"custom"}`), http.StatusCreated)
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/containers/custom", ""), http.StatusForbidden)
	acl := granularACL(t, srv, base+"/containers/custom/_acl")
	for _, perm := range []string{"create", "read", "update", "delete", "grant"} {
		if len(acl[perm]["groups"]) != 0 || len(acl[perm]["clients"]) != 0 || !slices.Equal(acl[perm]["users"], []string{"pivotal"}) {
			t.Errorf("custom container %s = %v, want only the creator", perm, acl[perm])
		}
	}
}

// TestRepoLoadedClientTakesContainerACL: a client loaded from a chef-repo has
// no creator, but takes the clients container's ACL and holds itself, so a
// plain member cannot add a key to it.
func TestRepoLoadedClientTakesContainerACL(t *testing.T) {
	dir := t.TempDir()
	writeRepoFiles(t, dir, map[string]string{
		"clients/web01.json":     `{"name":"web01"}`,
		"data_bags/vault/x.json": `{"id":"x"}`,
	})
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true, Repo: dir})
	base := srv.URL() + "/organizations/acme"
	bob := createUserKey(t, srv, "bob")
	mustStatus(t, signed(t, srv, "POST", base+"/users", `{"username":"bob"}`), http.StatusCreated)
	// Baseline: bob is a member who can read the client's keys.
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/clients/web01/keys", ""), http.StatusOK)

	mustStatus(t, signedAs(t, "bob", bob, "POST", base+"/clients/web01/keys", `{"name":"bobs","create_key":true,"expiration_date":"infinity"}`), http.StatusForbidden)
	acl := granularACL(t, srv, base+"/clients/web01/_acl")
	for _, perm := range []string{"create", "read", "update", "delete", "grant"} {
		if !slices.Equal(acl[perm]["clients"], []string{"web01"}) {
			t.Errorf("web01 %s clients = %v, want itself", perm, acl[perm]["clients"])
		}
		want := slices.Clone(erchefPolicy["containers/clients"][perm])
		slices.Sort(want)
		if !slices.Equal(acl[perm]["groups"], want) {
			t.Errorf("web01 %s groups = %v, want the clients container's %v", perm, acl[perm]["groups"], want)
		}
	}
	// The bag is stored with its container's ACL too.
	if code, body := signedBody(t, signed(t, srv, "GET", base+"/data/vault/_acl", "")); code != http.StatusOK {
		t.Fatalf("GET bag ACL = %d: %s", code, body)
	}
	org, _, _ := srv.Store().Org("acme")
	if _, ok, _ := org.Get("acls", "data/vault"); !ok {
		t.Error("repo-loaded data bag has no stored ACL")
	}
}

// TestStateLoadedClientTakesContainerACL is the state directory's version.
func TestStateLoadedClientTakesContainerACL(t *testing.T) {
	dir := t.TempDir()
	writeRepoFiles(t, dir, map[string]string{
		"users/bob.json":                        `{"username":"bob"}`,
		"organizations/acme/clients/web01.json": `{"name":"web01"}`,
		"organizations/acme/groups/ops.json":    `{"groupname":"ops"}`,
		"organizations/acme/members.json":       `["bob"]`,
	})
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true, StatePath: dir})
	org, _, _ := srv.Store().Org("acme")
	for _, key := range []string{"clients/web01", "groups/ops"} {
		if _, ok, _ := org.Get("acls", key); !ok {
			t.Errorf("state-loaded %s has no stored ACL", key)
		}
	}
	acl := granularACL(t, srv, srv.URL()+"/organizations/acme/clients/web01/_acl")
	if slices.Contains(acl["update"]["groups"], "users") {
		t.Errorf("state-loaded client update groups = %v, want no users group", acl["update"]["groups"])
	}
}

// legacyClientACL is the ACL versions before 0.21.1 stored for a new client: the
// object default plus its creator, here the user who made it.
const legacyClientACL = `{"create":{"clients":[],"groups":["admins","users"],"users":["%[1]s"]},` +
	`"delete":{"clients":[],"groups":["admins","users"],"users":["%[1]s"]},` +
	`"grant":{"clients":[],"groups":["admins"],"users":["%[1]s"]},` +
	`"read":{"clients":[],"groups":["admins","users","clients"],"users":["%[1]s"]},` +
	`"update":{"clients":[],"groups":["admins","users"],"users":["%[1]s"]}}`

// TestLegacyObjectACLsUpgradedOnStart covers a SQLite store written by an older
// version: a client whose ACL is still the legacy default plus its creator, a
// client and a data bag with no ACL at all, and a client whose legacy ACL an
// admin has since edited. Restarting brings the first three to their
// container's ACL and leaves the edited one as the admin set it.
func TestLegacyObjectACLsUpgradedOnStart(t *testing.T) {
	db := filepath.Join(t.TempDir(), "legacy.db")
	opts := Options{Orgs: []string{"acme"}, Storage: "sqlite", DB: db, EnforceACL: true}
	srv1, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv1.Start(); err != nil {
		t.Fatal(err)
	}
	base := srv1.URL() + "/organizations/acme"
	bob := createUserKey(t, srv1, "bob")
	mustStatus(t, signed(t, srv1, "POST", base+"/users", `{"username":"bob"}`), http.StatusCreated)
	for _, c := range []string{"legacy", "bare", "edited"} {
		mustStatus(t, signed(t, srv1, "POST", base+"/clients", `{"name":"`+c+`"}`), http.StatusCreated)
	}
	mustStatus(t, signed(t, srv1, "POST", base+"/data", `{"name":"vault"}`), http.StatusCreated)
	org, _, _ := srv1.Store().Org("acme")
	edited := `{"create":{"clients":[],"groups":["admins","users"],"users":["pivotal"]},` +
		`"delete":{"clients":[],"groups":["admins","users"],"users":["pivotal"]},` +
		`"grant":{"clients":[],"groups":["admins"],"users":["pivotal"]},` +
		`"read":{"clients":[],"groups":["admins","users","clients"],"users":["pivotal"]},` +
		`"update":{"clients":[],"groups":["admins","users"],"users":["pivotal","bob"]}}`
	for key, raw := range map[string]string{
		"clients/legacy": fmt.Sprintf(legacyClientACL, "pivotal"),
		"clients/edited": edited,
	} {
		if err := org.Put("acls", key, []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"clients/bare", "data/vault"} {
		if _, _, err := org.Delete("acls", key); err != nil {
			t.Fatal(err)
		}
	}
	// Baseline: the legacy client lets a member add a key, and so does the
	// edited one, which names bob. (The bare one already reports its
	// container's ACL, the fallback for an object with none stored.)
	for _, c := range []string{"legacy", "edited"} {
		mustStatus(t, signedAs(t, "bob", bob, "POST", base+"/clients/"+c+"/keys", `{"name":"k1","create_key":true,"expiration_date":"infinity"}`), http.StatusCreated)
	}
	stopServer(t, srv1)

	srv2 := startServer(t, opts)
	base = srv2.URL() + "/organizations/acme"
	for _, c := range []string{"legacy", "bare"} {
		mustStatus(t, signedAs(t, "bob", bob, "POST", base+"/clients/"+c+"/keys", `{"name":"k2","create_key":true,"expiration_date":"infinity"}`), http.StatusForbidden)
		acl := granularACL(t, srv2, base+"/clients/"+c+"/_acl")
		if !slices.Contains(acl["update"]["clients"], c) {
			t.Errorf("%s update clients = %v, want itself", c, acl["update"]["clients"])
		}
	}
	if acl := granularACL(t, srv2, base+"/clients/legacy/_acl"); !slices.Equal(acl["grant"]["users"], []string{"pivotal"}) {
		t.Errorf("legacy grant users = %v, want its creator kept", acl["grant"]["users"])
	}
	mustStatus(t, signedAs(t, "bob", bob, "POST", base+"/clients/edited/keys", `{"name":"k2","create_key":true,"expiration_date":"infinity"}`), http.StatusCreated)
	org2, _, _ := srv2.Store().Org("acme")
	if raw, _, _ := org2.Get("acls", "clients/edited"); string(raw) != edited {
		t.Errorf("edited ACL rewritten:\n got %s\nwant %s", raw, edited)
	}
	for _, key := range []string{"clients/bare", "data/vault"} {
		if _, ok, _ := org2.Get("acls", key); !ok {
			t.Errorf("%s had no ACL and still has none after restart", key)
		}
	}
}

// TestCreationWorkflowsStillWork: the everyday workflows keep working for a
// plain member and a registered node under the default ACLs: bootstrap,
// cookbook upload and re-upload, policy push and re-push, data bag and item
// writes, by the creator and by another member.
func TestCreationWorkflowsStillWork(t *testing.T) {
	srv, base, bob := memberSetup(t)
	alice := createUserKey(t, srv, "alice")
	mustStatus(t, signed(t, srv, "POST", base+"/users", `{"username":"alice"}`), http.StatusCreated)

	for _, who := range []struct {
		name string
		key  []byte
	}{{"bob", bob}, {"alice", alice}} {
		as := func(method, path, body string, want ...int) {
			t.Helper()
			code, out := signedBody(t, signedAs(t, who.name, who.key, method, base+path, body))
			if !slices.Contains(want, code) {
				t.Errorf("%s %s %s = %d, want %v: %s", who.name, method, path, code, want, out)
			}
		}
		// bob creates each object; alice, another member, updates it.
		as("POST", "/data", `{"name":"app"}`, http.StatusCreated, http.StatusConflict)
		as("POST", "/data/app", `{"id":"item-`+who.name+`"}`, http.StatusCreated)
		as("PUT", "/data/app/item-"+who.name, `{"id":"item-`+who.name+`","v":2}`, http.StatusOK)
		as("PUT", "/cookbooks/demo/1.2.3", cookbook("demo", "1.2.3"), http.StatusCreated, http.StatusOK)
		as("PUT", "/policy_groups/prod/policies/base", fmt.Sprintf(policyBody, "rev-"+who.name, "base"), http.StatusOK, http.StatusCreated)
		as("POST", "/policies/base/revisions", fmt.Sprintf(policyBody, "rev2-"+who.name, "base"), http.StatusCreated)
		as("POST", "/roles", `{"name":"web-`+who.name+`"}`, http.StatusCreated)
	}

	// Bootstrap: the validator registers a node's client, which saves its node
	// and reads what it converges from.
	node := createClientAndKey(t, srv, base, "web01")
	mustStatus(t, signedAs(t, "web01", node, "POST", base+"/nodes", `{"name":"web01"}`), http.StatusCreated)
	mustStatus(t, signedAs(t, "web01", node, "PUT", base+"/nodes/web01", `{"name":"web01"}`), http.StatusOK)
	for _, p := range []string{"/data/app", "/data/app/item-bob", "/cookbooks/demo/1.2.3", "/policy_groups/prod/policies/base", "/roles/web-bob"} {
		mustStatus(t, signedAs(t, "web01", node, "GET", base+p, ""), http.StatusOK)
	}
}

// TestCreateExistingGroupKeepsItsMembers: a create that conflicts must leave
// the existing group as it was, incremental membership rows included (a
// registered client joins the clients group through a row).
func TestCreateExistingGroupKeepsItsMembers(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	node := createClientAndKey(t, srv, base, "web01")
	// Baseline: the client creates its node through the clients group.
	mustStatus(t, signedAs(t, "web01", node, "POST", base+"/nodes", `{"name":"web01"}`), http.StatusCreated)

	mustStatus(t, signed(t, srv, "POST", base+"/groups", `{"groupname":"clients"}`), http.StatusConflict)
	mustStatus(t, signedAs(t, "web01", node, "POST", base+"/nodes", `{"name":"web02"}`), http.StatusCreated)
}
