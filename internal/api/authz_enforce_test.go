package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// testOrg returns a fresh, seeded org "acme" for authorization unit tests.
func testOrg(t *testing.T) *store.Org {
	t.Helper()
	st := store.New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	SeedOrg(org)
	return org
}

// putGroup writes a group document with the given members.
func putGroup(t *testing.T, org *store.Org, name string, users, clients, groups []string) {
	t.Helper()
	if err := org.Put("groups", name, mustEncode(groupDoc(name, users, clients, groups))); err != nil {
		t.Fatal(err)
	}
}

func TestActorGroupsDirectMembership(t *testing.T) {
	org := testOrg(t)
	putGroup(t, org, "users", []string{"alice"}, nil, nil)

	got, err := actorGroups(org, Actor{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if !got["users"] {
		t.Fatalf("alice should be in users group; got %v", got)
	}
	if got["admins"] {
		t.Fatalf("alice should not be in admins; got %v", got)
	}
}

func TestActorGroupsDistinguishesUsersFromClients(t *testing.T) {
	org := testOrg(t)
	// "bob" is listed only as a client, not a user.
	putGroup(t, org, "clients", nil, []string{"bob"}, nil)

	asClient, err := actorGroups(org, Actor{Name: "bob", IsClient: true})
	if err != nil {
		t.Fatal(err)
	}
	if !asClient["clients"] {
		t.Fatalf("client bob should be in clients group; got %v", asClient)
	}
	asUser, err := actorGroups(org, Actor{Name: "bob", IsClient: false})
	if err != nil {
		t.Fatal(err)
	}
	if asUser["clients"] {
		t.Fatalf("user bob should not match the client membership; got %v", asUser)
	}
}

func TestActorGroupsTransitive(t *testing.T) {
	org := testOrg(t)
	putGroup(t, org, "users", []string{"alice"}, nil, nil)
	// superusers contains the users group; alice is therefore a superuser too.
	putGroup(t, org, "superusers", nil, nil, []string{"users"})

	got, err := actorGroups(org, Actor{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if !got["users"] || !got["superusers"] {
		t.Fatalf("alice should be in users and superusers; got %v", got)
	}
}

func TestActorGroupsCycleTerminates(t *testing.T) {
	org := testOrg(t)
	putGroup(t, org, "a", []string{"alice"}, nil, []string{"b"})
	putGroup(t, org, "b", nil, nil, []string{"a"})

	got, err := actorGroups(org, Actor{Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if !got["a"] || !got["b"] {
		t.Fatalf("alice should be in both cyclic groups; got %v", got)
	}
}

func TestActorAllowedDirectActor(t *testing.T) {
	org := testOrg(t)
	if err := org.Put("acls", aclKey("nodes", "web01"), mustEncode(map[string]any{
		"read": map[string]any{"actors": []string{"alice"}, "groups": []string{}},
	})); err != nil {
		t.Fatal(err)
	}
	allowed, err := actorAllowed(org, Actor{Name: "alice"}, "nodes", "web01", "read")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("alice is a direct actor on read and should be allowed")
	}
	allowed, err = actorAllowed(org, Actor{Name: "mallory"}, "nodes", "web01", "read")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("mallory is not on the ACE and should be denied")
	}
}

func TestActorAllowedViaGroupDefaultACL(t *testing.T) {
	org := testOrg(t)
	// Default ACL grants read to admins,users,clients. Put alice in users.
	putGroup(t, org, "users", []string{"alice"}, nil, nil)

	allowed, err := actorAllowed(org, Actor{Name: "alice"}, "nodes", "web01", "read")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("alice (in users) should get default read")
	}
	// A non-member is denied even though the object has the permissive default.
	allowed, err = actorAllowed(org, Actor{Name: "stranger"}, "nodes", "web01", "read")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("stranger is in no group and should be denied")
	}
	// Default ACL does not grant create to clients.
	putGroup(t, org, "clients", nil, []string{"node1"}, nil)
	allowed, err = actorAllowed(org, Actor{Name: "node1", IsClient: true}, "nodes", "web01", "create")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("clients are not granted create by the default ACL")
	}
}

func TestClassifyRequest(t *testing.T) {
	cases := []struct {
		method, path string
		want         *authzCheck // nil means "unclassified / allow-through"
	}{
		// Generic object collection: container ACL governs list/create.
		{"GET", "/organizations/acme/nodes", &authzCheck{aclType: "containers", aclName: "nodes", perm: "read"}},
		{"POST", "/organizations/acme/nodes", &authzCheck{aclType: "containers", aclName: "nodes", perm: "create"}},
		// Generic object item: object ACL governs, existence checked first.
		{"GET", "/organizations/acme/nodes/web01", &authzCheck{aclType: "nodes", aclName: "web01", perm: "read", existColl: "nodes", existKey: "web01", existMsg: "Cannot find nodes web01"}},
		{"HEAD", "/organizations/acme/nodes/web01", &authzCheck{aclType: "nodes", aclName: "web01", perm: "read", existColl: "nodes", existKey: "web01", existMsg: "Cannot find nodes web01"}},
		{"PUT", "/organizations/acme/roles/web", &authzCheck{aclType: "roles", aclName: "web", perm: "update", existColl: "roles", existKey: "web", existMsg: "Cannot find roles web"}},
		{"DELETE", "/organizations/acme/environments/prod", &authzCheck{aclType: "environments", aclName: "prod", perm: "delete", existColl: "environments", existKey: "prod", existMsg: "Cannot find environments prod"}},
		// _acl endpoints require grant on the target object; no existence check.
		{"GET", "/organizations/acme/nodes/web01/_acl", &authzCheck{aclType: "nodes", aclName: "web01", perm: "grant"}},
		{"PUT", "/organizations/acme/nodes/web01/_acl/grant", &authzCheck{aclType: "nodes", aclName: "web01", perm: "grant"}},
		{"GET", "/organizations/acme/_acl", &authzCheck{aclType: "organizations", aclName: "acme", perm: "grant"}},
		// Organization read.
		{"GET", "/organizations/acme", &authzCheck{aclType: "organizations", aclName: "acme", perm: "read"}},
		// Data bags: container governs the collection; the bag ACL governs items.
		{"GET", "/organizations/acme/data", &authzCheck{aclType: "containers", aclName: "data", perm: "read"}},
		{"POST", "/organizations/acme/data", &authzCheck{aclType: "containers", aclName: "data", perm: "create"}},
		{"GET", "/organizations/acme/data/secrets", &authzCheck{aclType: "data", aclName: "secrets", perm: "read", existColl: "data_bags", existKey: "secrets", existMsg: "Cannot find data bag secrets"}},
		{"POST", "/organizations/acme/data/secrets", &authzCheck{aclType: "data", aclName: "secrets", perm: "update", existColl: "data_bags", existKey: "secrets", existMsg: "Cannot find data bag secrets"}},
		{"DELETE", "/organizations/acme/data/secrets", &authzCheck{aclType: "data", aclName: "secrets", perm: "delete", existColl: "data_bags", existKey: "secrets", existMsg: "Cannot find data bag secrets"}},
		{"PUT", "/organizations/acme/data/secrets/item1", &authzCheck{aclType: "data", aclName: "secrets", perm: "update", existColl: "data_bags", existKey: "secrets", existMsg: "Cannot find data bag secrets"}},
		// Cookbooks: versioned; the cookbook object ACL governs versions.
		{"GET", "/organizations/acme/cookbooks", &authzCheck{aclType: "containers", aclName: "cookbooks", perm: "read"}},
		{"GET", "/organizations/acme/cookbooks/apache2", &authzCheck{aclType: "cookbooks", aclName: "apache2", perm: "read"}},
		{"GET", "/organizations/acme/cookbooks/apache2/1.0.0", &authzCheck{aclType: "cookbooks", aclName: "apache2", perm: "read"}},
		{"PUT", "/organizations/acme/cookbooks/apache2/1.0.0", &authzCheck{aclType: "cookbooks", aclName: "apache2", perm: "update"}},
		{"DELETE", "/organizations/acme/cookbooks/apache2/1.0.0", &authzCheck{aclType: "cookbooks", aclName: "apache2", perm: "delete"}},
		// Cookbook pseudo-endpoints fall back to the container.
		{"GET", "/organizations/acme/cookbooks/_latest", &authzCheck{aclType: "containers", aclName: "cookbooks", perm: "read"}},
		{"PUT", "/organizations/acme/cookbook_artifacts/foo/abc123", &authzCheck{aclType: "cookbook_artifacts", aclName: "foo", perm: "update"}},
		// Global users collection: superuser-only (list/create).
		{"GET", "/users", &authzCheck{superuserOnly: true, perm: "read"}},
		{"POST", "/users", &authzCheck{superuserOnly: true, perm: "create"}},
		// Global single user: superuser-only, but the user may act on itself.
		{"GET", "/users/bob", &authzCheck{superuserOnly: true, perm: "read", allowSelf: "bob"}},
		{"PUT", "/users/bob", &authzCheck{superuserOnly: true, perm: "update", allowSelf: "bob"}},
		{"DELETE", "/users/bob", &authzCheck{superuserOnly: true, perm: "delete", allowSelf: "bob"}},
		// Global user ACLs: grant on the user object, evaluated in the global space.
		{"GET", "/users/bob/_acl", &authzCheck{global: true, aclType: "users", aclName: "bob", perm: "grant"}},
		{"PUT", "/users/bob/_acl/grant", &authzCheck{global: true, aclType: "users", aclName: "bob", perm: "grant"}},
		// Org membership changes are gated by the org's groups container, so a
		// non-member cannot associate itself in (see authz_gaps_test.go).
		{"POST", "/organizations/acme/users", &authzCheck{aclType: "containers", aclName: "groups", perm: "update"}},
		// An actor's keys are its credential, so they are gated like the actor.
		{"GET", "/users/bob/keys", &authzCheck{superuserOnly: true, perm: "read", allowSelf: "bob"}},
		// Provisioning an org is server-level; listing them stays open.
		{"POST", "/organizations", &authzCheck{superuserOnly: true, perm: "create"}},
		// Policy sub-resources collapse onto the policy object's ACL.
		{"GET", "/organizations/acme/policies/app/revisions/1.0.0", &authzCheck{aclType: "policies", aclName: "app", perm: "read"}},
		// Unclassified: allow-through (no ACL restrictions or out of scope).
		{"GET", "/organizations/acme/search/node", nil},
		{"GET", "/organizations/acme/sandboxes", nil},
		{"GET", "/organizations", nil},
	}
	for _, c := range cases {
		got, ok := classifyRequest(c.method, c.path)
		if c.want == nil {
			if ok {
				t.Errorf("%s %s: classified %+v, want allow-through", c.method, c.path, got)
			}
			continue
		}
		if !ok {
			t.Errorf("%s %s: allow-through, want %+v", c.method, c.path, *c.want)
			continue
		}
		if *got != *c.want {
			t.Errorf("%s %s:\n got %+v\nwant %+v", c.method, c.path, *got, *c.want)
		}
	}
}

// enforcingHandler builds an API handler with ACL enforcement enabled, backed
// by a store with a seeded org "acme" and a single node "web01".
func enforcingHandler(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	st := store.New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	SeedOrg(org)
	if err := org.Put("nodes", "web01", []byte(`{"name":"web01"}`)); err != nil {
		t.Fatal(err)
	}
	return New(st, WithACLEnforcement(true)).Handler(), st
}

// authzReq sends a request through h as actor and returns status and body.
func authzReq(t *testing.T, h http.Handler, actor Actor, method, target, body string) (int, string) {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r = r.WithContext(WithActor(r.Context(), actor))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code, rec.Body.String()
}

func TestEnforceDeniesWithoutPermission(t *testing.T) {
	h, _ := enforcingHandler(t)
	// "stranger" is a user in no group, so the default ACL denies read.
	code, body := authzReq(t, h, Actor{Name: "stranger"}, "GET", "/organizations/acme/nodes/web01", "")
	if code != http.StatusForbidden {
		t.Fatalf("denied read = %d, want 403; body %s", code, body)
	}
	var errObj struct {
		Error []string `json:"error"`
	}
	json.Unmarshal([]byte(body), &errObj)
	if len(errObj.Error) == 0 {
		t.Fatalf("403 should carry a Chef error array, got %s", body)
	}
}

func TestEnforceAllowsViaGroup(t *testing.T) {
	h, st := enforcingHandler(t)
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	putGroup(t, org, "users", []string{"alice"}, nil, nil)
	code, body := authzReq(t, h, Actor{Name: "alice"}, "GET", "/organizations/acme/nodes/web01", "")
	if code != http.StatusOK {
		t.Fatalf("alice (in users) read = %d, want 200; body %s", code, body)
	}
}

func TestEnforceSuperuserBypass(t *testing.T) {
	h, _ := enforcingHandler(t)
	// A global admin belongs to no group but bypasses ACL checks (pivotal).
	code, _ := authzReq(t, h, Actor{Name: "pivotal", IsGlobalAdmin: true}, "GET", "/organizations/acme/nodes/web01", "")
	if code != http.StatusOK {
		t.Fatalf("superuser read = %d, want 200", code)
	}
}

func TestEnforceExistenceBeforeAuthz(t *testing.T) {
	h, _ := enforcingHandler(t)
	// A missing object reports 404 even though the actor also lacks read — the
	// existence check precedes authorization.
	code, _ := authzReq(t, h, Actor{Name: "stranger"}, "GET", "/organizations/acme/nodes/ghost", "")
	if code != http.StatusNotFound {
		t.Fatalf("missing object = %d, want 404 (existence before authz)", code)
	}
}

func TestEnforceAllowsUnclassifiedRoutes(t *testing.T) {
	h, _ := enforcingHandler(t)
	// Search carries no ACL restriction in Chef; enforcement must not 403 it.
	code, _ := authzReq(t, h, Actor{Name: "stranger"}, "GET", "/organizations/acme/search", "")
	if code == http.StatusForbidden {
		t.Fatalf("search should be allowed through, got 403")
	}
}

func TestEnforceDisabledAllowsEverything(t *testing.T) {
	st := store.New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	SeedOrg(org)
	if err := org.Put("nodes", "web01", []byte(`{"name":"web01"}`)); err != nil {
		t.Fatal(err)
	}
	h := New(st).Handler() // enforcement off (default)
	code, _ := authzReq(t, h, Actor{Name: "stranger"}, "GET", "/organizations/acme/nodes/web01", "")
	if code != http.StatusOK {
		t.Fatalf("enforcement off: stranger read = %d, want 200", code)
	}
}

func TestSeedGrantsValidatorClientCreate(t *testing.T) {
	st := store.New()
	if _, err := CreateOrganization(st, "acme", "acme"); err != nil {
		t.Fatal(err)
	}
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := actorAllowed(org, Actor{Name: "acme-validator", IsClient: true}, "containers", "clients", "create")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("the org validator should be granted create on the clients container")
	}
	// A non-validator client is still denied create.
	allowed, err = actorAllowed(org, Actor{Name: "node1", IsClient: true}, "containers", "clients", "create")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("an ordinary client should not be granted create on clients")
	}
}

func TestEnforceValidatorCreatesClient(t *testing.T) {
	st := store.New()
	if _, err := CreateOrganization(st, "acme", "acme"); err != nil {
		t.Fatal(err)
	}
	h := New(st, WithACLEnforcement(true)).Handler()
	code, body := authzReq(t, h, Actor{Name: "acme-validator", IsClient: true},
		"POST", "/organizations/acme/clients", `{"name":"node1"}`)
	if code != http.StatusCreated {
		t.Fatalf("validator create client = %d, want 201; body %s", code, body)
	}
}

// TestEnforceGroupsAndContainers locks in that the authz/{groups,containers}
// endpoints are gated: a stranger (in no group) is denied, while an actor
// granted the relevant ACE succeeds.
func TestEnforceGroupsAndContainers(t *testing.T) {
	h, st := enforcingHandler(t)
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := org.Put("groups", "grp1", mustEncode(groupDoc("grp1", nil, nil, nil))); err != nil {
		t.Fatal(err)
	}
	if err := org.Put("containers", "cont1", []byte(`{"containername":"cont1"}`)); err != nil {
		t.Fatal(err)
	}
	stranger := Actor{Name: "stranger"}

	denied := []struct{ method, path, body string }{
		{"GET", "/organizations/acme/groups", ""},
		{"POST", "/organizations/acme/groups", `{"groupname":"g2"}`},
		{"GET", "/organizations/acme/groups/grp1", ""},
		{"PUT", "/organizations/acme/groups/grp1", `{"groupname":"grp1"}`},
		{"DELETE", "/organizations/acme/groups/grp1", ""},
		{"GET", "/organizations/acme/containers", ""},
		{"POST", "/organizations/acme/containers", `{"containername":"c2"}`},
		{"GET", "/organizations/acme/containers/cont1", ""},
		{"DELETE", "/organizations/acme/containers/cont1", ""},
	}
	for _, c := range denied {
		if code, body := authzReq(t, h, stranger, c.method, c.path, c.body); code != http.StatusForbidden {
			t.Errorf("stranger %s %s = %d, want 403; body %s", c.method, c.path, code, body)
		}
	}

	// A normal user granted update on the group's ACL may PUT it.
	if err := org.Put("acls", aclKey("groups", "grp1"), mustEncode(map[string]any{
		"update": map[string]any{"actors": []string{"editor"}, "groups": []string{}},
	})); err != nil {
		t.Fatal(err)
	}
	if code, body := authzReq(t, h, Actor{Name: "editor"}, "PUT", "/organizations/acme/groups/grp1", `{"groupname":"grp1"}`); code != http.StatusOK {
		t.Errorf("editor PUT group with update ACE = %d, want 200; body %s", code, body)
	}
}

// TestEnforceGlobalUsersSuperuserOnly covers the global /users collection:
// non-superusers are denied list/create and operations on other users, but a
// user may act on its own record and the superuser may act on any.
func TestEnforceGlobalUsersSuperuserOnly(t *testing.T) {
	h, st := enforcingHandler(t)
	if err := st.Global().Put("users", "bob", []byte(`{"username":"bob"}`)); err != nil {
		t.Fatal(err)
	}
	if err := st.Global().Put("users", "carol", []byte(`{"username":"carol"}`)); err != nil {
		t.Fatal(err)
	}

	// A normal org admin is not a global admin: denied list/create and acting
	// on another user.
	admin := Actor{Name: "orgadmin"}
	denied := []struct{ method, path, body string }{
		{"GET", "/users", ""},
		{"POST", "/users", `{"name":"new"}`},
		{"GET", "/users/bob", ""},
		{"PUT", "/users/bob", `{"username":"bob"}`},
		{"DELETE", "/users/bob", ""},
	}
	for _, c := range denied {
		if code, body := authzReq(t, h, admin, c.method, c.path, c.body); code != http.StatusForbidden {
			t.Errorf("orgadmin %s %s = %d, want 403; body %s", c.method, c.path, code, body)
		}
	}

	// bob may read and update its own record.
	if code, body := authzReq(t, h, Actor{Name: "bob"}, "GET", "/users/bob", ""); code != http.StatusOK {
		t.Errorf("bob GET self = %d, want 200; body %s", code, body)
	}
	if code, body := authzReq(t, h, Actor{Name: "bob"}, "PUT", "/users/bob", `{"username":"bob"}`); code != http.StatusOK {
		t.Errorf("bob PUT self = %d, want 200; body %s", code, body)
	}
	// ...but not another user's record.
	if code, _ := authzReq(t, h, Actor{Name: "bob"}, "PUT", "/users/carol", `{"username":"carol"}`); code != http.StatusForbidden {
		t.Errorf("bob PUT carol = %d, want 403", code)
	}

	// The superuser may do anything.
	su := Actor{Name: "pivotal", IsGlobalAdmin: true}
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/users", ""},
		{"PUT", "/users/bob", `{"username":"bob"}`},
	} {
		if code, body := authzReq(t, h, su, c.method, c.path, c.body); code == http.StatusForbidden {
			t.Errorf("superuser %s %s = 403, want allowed; body %s", c.method, c.path, body)
		}
	}
}

// TestEnforceUserACL covers /users/<name>/_acl: an unauthorized normal user is
// denied, an actor named directly on the grant ACE succeeds, and the superuser
// bypasses.
func TestEnforceUserACL(t *testing.T) {
	h, st := enforcingHandler(t)
	if err := st.Global().Put("users", "bob", []byte(`{"username":"bob"}`)); err != nil {
		t.Fatal(err)
	}

	stranger := Actor{Name: "stranger"}
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/users/bob/_acl", ""},
		{"GET", "/users/bob/_acl/grant", ""},
		{"PUT", "/users/bob/_acl/grant", `{"grant":{"actors":[],"groups":[]}}`},
	} {
		if code, body := authzReq(t, h, stranger, c.method, c.path, c.body); code != http.StatusForbidden {
			t.Errorf("stranger %s %s = %d, want 403; body %s", c.method, c.path, code, body)
		}
	}

	// Grant "granter" the grant permission on bob's user object (global space).
	if err := st.Global().Put("acls", aclKey("users", "bob"), mustEncode(map[string]any{
		"grant": map[string]any{"actors": []string{"granter"}, "groups": []string{}},
	})); err != nil {
		t.Fatal(err)
	}
	if code, body := authzReq(t, h, Actor{Name: "granter"}, "GET", "/users/bob/_acl", ""); code != http.StatusOK {
		t.Errorf("granter GET user acl = %d, want 200; body %s", code, body)
	}
	if code, body := authzReq(t, h, Actor{Name: "pivotal", IsGlobalAdmin: true}, "GET", "/users/bob/_acl", ""); code != http.StatusOK {
		t.Errorf("superuser GET user acl = %d, want 200; body %s", code, body)
	}
}

// TestEnforceOrgACL locks in that the organization's own ACL endpoint evaluates
// the grant permission rather than returning 404: a grant-holder is allowed and
// others are denied.
func TestEnforceOrgACL(t *testing.T) {
	h, st := enforcingHandler(t)
	org, _, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := org.Put("acls", aclKey("organizations", "acme"), mustEncode(map[string]any{
		"grant": map[string]any{"actors": []string{"granter"}, "groups": []string{}},
	})); err != nil {
		t.Fatal(err)
	}

	if code, body := authzReq(t, h, Actor{Name: "stranger"}, "GET", "/organizations/acme/_acl", ""); code != http.StatusForbidden {
		t.Errorf("stranger GET org acl = %d, want 403; body %s", code, body)
	}
	if code, body := authzReq(t, h, Actor{Name: "granter"}, "GET", "/organizations/acme/_acl", ""); code != http.StatusOK {
		t.Errorf("granter GET org acl = %d, want 200; body %s", code, body)
	}
	if code, body := authzReq(t, h, Actor{Name: "granter"}, "PUT", "/organizations/acme/_acl/grant",
		`{"grant":{"actors":["granter"],"groups":[]}}`); code != http.StatusOK {
		t.Errorf("granter PUT org acl grant = %d, want 200; body %s", code, body)
	}
}
