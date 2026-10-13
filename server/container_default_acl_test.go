package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
)

// erchefPolicy is erchef's org creation policy
// (oc_chef_authz_org_creator:DEFAULT_EC_EXPANDED_ORG), written out by hand so
// the server's table is checked against the source rather than against itself:
// object -> perm -> groups holding it. The creating superuser, which erchef also
// names in every one of these ACLs, bypasses ACLs here and is left out.
var erchefPolicy = func() map[string]map[string][]string {
	all := []string{"create", "read", "update", "delete", "grant"}
	p := map[string]map[string][]string{}
	add := func(obj string, perms []string, group string) {
		if p[obj] == nil {
			p[obj] = map[string][]string{}
		}
		for _, perm := range perms {
			p[obj][perm] = append(p[obj][perm], group)
		}
	}
	containers := []string{"clients", "containers", "cookbooks", "data", "environments",
		"groups", "nodes", "roles", "sandboxes", "policies", "policy_groups", "cookbook_artifacts"}
	for _, c := range containers {
		add("containers/"+c, all, "admins")
	}
	add("organization", all, "admins")
	for _, c := range []string{"cookbooks", "data", "nodes", "roles", "environments",
		"policies", "policy_groups", "cookbook_artifacts"} {
		add("containers/"+c, []string{"create", "read", "update", "delete"}, "users")
	}
	add("containers/clients", []string{"read", "delete"}, "users")
	add("containers/groups", []string{"read"}, "users")
	add("containers/containers", []string{"read"}, "users")
	add("organization", []string{"read"}, "users")
	add("containers/sandboxes", []string{"create"}, "users")
	add("containers/nodes", []string{"read", "create"}, "clients")
	for _, c := range []string{"policies", "policy_groups", "cookbook_artifacts", "data",
		"cookbooks", "environments", "roles"} {
		add("containers/"+c, []string{"read"}, "clients")
	}
	for _, g := range []string{"admins", "clients", "users"} {
		add("groups/"+g, all, "admins")
	}
	add("groups/billing-admins", []string{"read", "update"}, "billing-admins")
	add("groups/public_key_read_access", []string{"read", "update"}, "admins")
	return p
}()

// aclPath is the _acl URL of a policy object.
func aclPath(base, obj string) string {
	if obj == "organization" {
		return base + "/organizations/_acl"
	}
	return base + "/" + obj + "/_acl"
}

// TestDefaultACLsMatchErchefOrgPolicy reads back the ACL of every container,
// every default group and the organization in a freshly created org and checks
// each permission names exactly the groups erchef's org policy grants it.
func TestDefaultACLsMatchErchefOrgPolicy(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"

	for obj, want := range erchefPolicy {
		code, body := signedBody(t, signed(t, srv, "GET", aclPath(base, obj), ""))
		if code != http.StatusOK {
			t.Errorf("GET %s ACL = %d: %s", obj, code, body)
			continue
		}
		var acl map[string]struct {
			Groups []string `json:"groups"`
		}
		if err := json.Unmarshal(body, &acl); err != nil {
			t.Fatalf("%s ACL: %v", obj, err)
		}
		for _, perm := range []string{"create", "read", "update", "delete", "grant"} {
			got := slices.Clone(acl[perm].Groups)
			exp := slices.Clone(want[perm])
			slices.Sort(got)
			slices.Sort(exp)
			if !slices.Equal(got, exp) {
				t.Errorf("%s %s groups = %v, want %v", obj, perm, got, exp)
			}
		}
	}
}

// TestPlainClientContainerReadsMatchErchef pins what a registered client (a
// member of the clients group, not an admin, not a validator) may read. erchef
// grants the clients group read on the containers chef-client converges from
// and nothing else: the clients, groups and containers containers and the
// organization itself are a 403.
func TestPlainClientContainerReadsMatchErchef(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	key := createClientAndKey(t, srv, base, "robot1")

	// Baseline: the routes exist and the superuser can read them, so a 403
	// below is the ACL and not a missing route.
	for _, p := range []string{"/clients", "/groups", "/containers", ""} {
		mustStatus(t, signed(t, srv, "GET", base+p, ""), http.StatusOK)
	}

	for _, p := range []string{"/nodes", "/roles", "/environments", "/cookbooks",
		"/cookbook_artifacts", "/data", "/policies", "/policy_groups"} {
		mustStatus(t, signedAs(t, "robot1", key, "GET", base+p, ""), http.StatusOK)
	}
	for _, p := range []string{"/clients", "/groups", "/containers", ""} {
		mustStatus(t, signedAs(t, "robot1", key, "GET", base+p, ""), http.StatusForbidden)
	}
}

// TestOrgUserContainerPermsMatchErchef pins the users group's container
// grants: read on clients, groups, containers and the organization, but no
// create on clients (only admins may register a client by hand) and full
// object CRUD on the data containers.
func TestOrgUserContainerPermsMatchErchef(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	key := createUserKey(t, srv, "bob")
	mustStatus(t, signed(t, srv, "POST", base+"/users", `{"username":"bob"}`), http.StatusCreated)

	// Baseline: the superuser may register a client, so bob's 403 is the ACL.
	mustStatus(t, signed(t, srv, "POST", base+"/clients", `{"name":"by-admin"}`), http.StatusCreated)

	for _, p := range []string{"/clients", "/groups", "/containers", "", "/nodes", "/data"} {
		mustStatus(t, signedAs(t, "bob", key, "GET", base+p, ""), http.StatusOK)
	}
	mustStatus(t, signedAs(t, "bob", key, "POST", base+"/roles", `{"name":"web"}`), http.StatusCreated)
	mustStatus(t, signedAs(t, "bob", key, "POST", base+"/clients", `{"name":"by-bob"}`), http.StatusForbidden)
}

// TestPublicKeyReadAccessGroupSeeded checks the org is created with erchef's
// public_key_read_access group, whose members are the users and clients
// groups.
func TestPublicKeyReadAccessGroupSeeded(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	code, body := signedBody(t, signed(t, srv, "GET",
		srv.URL()+"/organizations/acme/groups/public_key_read_access", ""))
	if code != http.StatusOK {
		t.Fatalf("GET public_key_read_access = %d: %s", code, body)
	}
	var g struct {
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(body, &g); err != nil {
		t.Fatal(err)
	}
	slices.Sort(g.Groups)
	if !slices.Equal(g.Groups, []string{"clients", "users"}) {
		t.Errorf("public_key_read_access groups = %v, want [clients users]", g.Groups)
	}
}

// legacyClientsContainerACL is the clients container ACL that versions before
// the erchef policy table stored at org creation: the old permissive default
// with the validator added to create.
const legacyClientsContainerACL = `{"create":{"actors":["acme-validator"],"groups":["admins","users"]},` +
	`"delete":{"actors":[],"groups":["admins","users"]},` +
	`"grant":{"actors":[],"groups":["admins"]},` +
	`"read":{"actors":[],"groups":["admins","users","clients"]},` +
	`"update":{"actors":[],"groups":["admins","users"]}}`

// TestLegacyClientsContainerACLUpgradedOnStart covers an org created by an
// older version in a SQLite database: its stored clients container ACL still
// gives the clients group read. Restarting on that database must bring it to
// erchef's policy, while the validator keeps create (so bootstrap still
// works).
func TestLegacyClientsContainerACLUpgradedOnStart(t *testing.T) {
	db := filepath.Join(t.TempDir(), "legacy.db")
	opts := Options{Orgs: []string{"acme"}, Storage: "sqlite", DB: db, EnforceACL: true}

	srv1, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	org, _, err := srv1.Store().Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := org.Put("acls", "containers/clients", []byte(legacyClientsContainerACL)); err != nil {
		t.Fatal(err)
	}
	if err := srv1.Start(); err != nil {
		t.Fatal(err)
	}
	base := srv1.URL() + "/organizations/acme"
	key := createClientAndKey(t, srv1, base, "robot1")
	// Baseline: under the legacy ACL the plain client can list clients.
	mustStatus(t, signedAs(t, "robot1", key, "GET", base+"/clients", ""), http.StatusOK)
	stopServer(t, srv1)

	srv2, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv2.Start(); err != nil {
		t.Fatal(err)
	}
	defer stopServer(t, srv2)
	base = srv2.URL() + "/organizations/acme"

	mustStatus(t, signedAs(t, "robot1", key, "GET", base+"/clients", ""), http.StatusForbidden)
	// The validator can still register a client.
	createClientAndKey(t, srv2, base, "robot2")
}

// TestCustomizedClientsContainerACLKeptOnStart checks the upgrade only
// rewrites the exact legacy form: an ACL an operator changed is theirs.
func TestCustomizedClientsContainerACLKeptOnStart(t *testing.T) {
	db := filepath.Join(t.TempDir(), "custom.db")
	opts := Options{Orgs: []string{"acme"}, Storage: "sqlite", DB: db, EnforceACL: true}

	srv1, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	custom := `{"create":{"actors":["acme-validator"],"groups":["admins"]},` +
		`"delete":{"actors":[],"groups":["admins"]},"grant":{"actors":[],"groups":["admins"]},` +
		`"read":{"actors":[],"groups":["admins","clients"]},"update":{"actors":[],"groups":["admins"]}}`
	org, _, err := srv1.Store().Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := org.Put("acls", "containers/clients", []byte(custom)); err != nil {
		t.Fatal(err)
	}
	if err := srv1.Start(); err != nil {
		t.Fatal(err)
	}
	stopServer(t, srv1)

	srv2, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv2.Start(); err != nil {
		t.Fatal(err)
	}
	defer stopServer(t, srv2)
	org, _, err = srv2.Store().Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := org.Get("acls", "containers/clients")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != custom {
		t.Errorf("customized clients container ACL rewritten:\n got %s\nwant %s", raw, custom)
	}
}
