package server

import (
	"bytes"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// Renaming through PUT, as erchef's oc_chef_wm_base:update_from_json does when
// the body names another object than the path (handle_rename): 201 with a
// Location for the new name, and the old name is gone. erchef refers to
// clients, users and groups by authz id in ACLs and group membership, so
// every grant follows the renamed object and none stays with the old name.

// renameBackends runs a rename test on both store backends: the move touches
// many collections, and SQLite's transaction and Range differ from memory's.
func renameBackends(t *testing.T, run func(t *testing.T, opts Options)) {
	t.Run("memory", func(t *testing.T) {
		run(t, Options{Orgs: []string{"acme", "beta"}, EnforceACL: true})
	})
	t.Run("sqlite", func(t *testing.T) {
		run(t, Options{Orgs: []string{"acme", "beta"}, EnforceACL: true, Storage: "sqlite", DB: t.TempDir() + "/x.db"})
	})
}

// doFull sends req and returns the response (body closed) and its body.
func doFull(t *testing.T, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, bytes.TrimSpace(body)
}

// expectStatus sends req and fails unless it answers want.
func expectStatus(t *testing.T, what string, req *http.Request, want int) []byte {
	t.Helper()
	resp, body := doFull(t, req)
	if resp.StatusCode != want {
		t.Fatalf("%s = %d, want %d: %s", what, resp.StatusCode, want, body)
	}
	return body
}

// rawGranularACL returns an object's ACL in the users/clients form, as the
// superuser reads it.
func rawGranularACL(t *testing.T, srv *Server, url string) string {
	t.Helper()
	return string(expectStatus(t, "GET "+url, signed(t, srv, "GET", url+"/_acl?detail=granular", ""), 200))
}

// renameOnlyReader stores an ACL on node "secret" whose read is granted to
// exactly one actor or group, so only the renamed object can read it.
func renameOnlyReader(t *testing.T, srv *Server, ace string) {
	t.Helper()
	base := srv.URL() + "/organizations/acme"
	expectStatus(t, "create node secret", signed(t, srv, "POST", base+"/nodes", `{"name":"secret"}`), 201)
	expectStatus(t, "narrow secret's read", signed(t, srv, "PUT", base+"/nodes/secret/_acl/read", `{"read":`+ace+`}`), 200)
}

func groupDoc(t *testing.T, srv *Server, org, group string) (users, clients, groups []string) {
	t.Helper()
	var g struct {
		Users   []string `json:"users"`
		Clients []string `json:"clients"`
		Groups  []string `json:"groups"`
	}
	getJSON(t, srv, srv.URL()+"/organizations/"+org+"/groups/"+group, &g)
	return g.Users, g.Clients, g.Groups
}

func searchTotal(t *testing.T, srv *Server, index, q string) int {
	t.Helper()
	var out struct {
		Total int `json:"total"`
	}
	getJSON(t, srv, srv.URL()+"/organizations/acme/search/"+index+"?q="+q, &out)
	return out.Total
}

func TestRenameClientViaPut(t *testing.T) {
	renameBackends(t, func(t *testing.T, opts Options) {
		srv := startServer(t, opts)
		base := srv.URL() + "/organizations/acme"
		oldKey := createClientAndKey(t, srv, base, "web01")
		otherKey := createClientAndKey(t, srv, base, "other")
		expectStatus(t, "create group ops", signed(t, srv, "POST", base+"/groups", `{"groupname":"ops"}`), 201)
		expectStatus(t, "add web01 to ops", signed(t, srv, "PUT", base+"/groups/ops",
			`{"groupname":"ops","actors":{"users":[],"clients":["web01"],"groups":[]}}`), 200)
		renameOnlyReader(t, srv, `{"actors":[],"users":[],"clients":["web01"],"groups":[]}`)
		secret := base + "/nodes/secret"

		// Baseline: only web01 reads the secret node, and it is in both groups.
		wantAuth(t, "baseline web01 read", statusOf(t, signedAs(t, "web01", oldKey, "GET", secret, "")), 200)
		wantAuth(t, "baseline other read", statusOf(t, signedAs(t, "other", otherKey, "GET", secret, "")), 403)
		if _, c, _ := groupDoc(t, srv, "acme", "clients"); !slices.Contains(c, "web01") {
			t.Fatalf("baseline: web01 not in the clients group: %v", c)
		}
		beforeACL := rawGranularACL(t, srv, base+"/clients/web01")
		if !strings.Contains(beforeACL, "web01") {
			t.Fatalf("baseline: web01's ACL does not name it: %s", beforeACL)
		}

		resp, body := doFull(t, signed(t, srv, "PUT", base+"/clients/web01", `{"name":"web02"}`))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("rename = %d, want 201: %s", resp.StatusCode, body)
		}
		if loc := resp.Header.Get("Location"); loc != base+"/clients/web02" {
			t.Errorf("Location = %q, want %s", loc, base+"/clients/web02")
		}
		if !strings.Contains(string(body), `"name":"web02"`) {
			t.Errorf("rename body = %s, want the renamed client", body)
		}

		expectStatus(t, "GET old name", signed(t, srv, "GET", base+"/clients/web01", ""), 404)
		var got map[string]any
		getJSON(t, srv, base+"/clients/web02", &got)
		if got["name"] != "web02" || got["clientname"] != "web02" {
			t.Errorf("renamed client = %v, want name and clientname web02", got)
		}

		// erchef keeps no key for a renamed client: neither name
		// authenticates until a key is added.
		if keys := string(expectStatus(t, "list keys", signed(t, srv, "GET", base+"/clients/web02/keys", ""), 200)); keys != "[]" {
			t.Errorf("renamed client's keys = %s, want []", keys)
		}
		wantAuth(t, "old key as web02", statusOf(t, signedAs(t, "web02", oldKey, "GET", secret, "")), 401)
		wantAuth(t, "old key as web01", statusOf(t, signedAs(t, "web01", oldKey, "GET", secret, "")), 401)

		// Its ACL, its grants and its memberships moved with it.
		if after := rawGranularACL(t, srv, base+"/clients/web02"); after != strings.ReplaceAll(beforeACL, "web01", "web02") {
			t.Errorf("renamed client's ACL = %s, want the old one renamed: %s", after, beforeACL)
		}
		if acl := rawGranularACL(t, srv, secret); strings.Contains(acl, "web01") || !strings.Contains(acl, "web02") {
			t.Errorf("secret's ACL = %s, want web02 in place of web01", acl)
		}
		for _, g := range []string{"clients", "ops"} {
			if _, c, _ := groupDoc(t, srv, "acme", g); slices.Contains(c, "web01") || !slices.Contains(c, "web02") {
				t.Errorf("group %s clients = %v, want web02 in place of web01", g, c)
			}
		}
		if n := searchTotal(t, srv, "client", "name:web02"); n != 1 {
			t.Errorf("search name:web02 = %d, want 1", n)
		}
		if n := searchTotal(t, srv, "client", "name:web01"); n != 0 {
			t.Errorf("search name:web01 = %d, want 0", n)
		}

		newKey := addKey(t, srv, base+"/clients/web02/keys", `{"name":"default","create_key":true,"expiration_date":"infinity"}`)
		wantAuth(t, "web02 with its new key", statusOf(t, signedAs(t, "web02", newKey, "GET", secret, "")), 200)

		// A new client under the old name inherits nothing.
		reusedKey := createClientAndKey(t, srv, base, "web01")
		wantAuth(t, "new web01 read", statusOf(t, signedAs(t, "web01", reusedKey, "GET", secret, "")), 403)
		if _, c, _ := groupDoc(t, srv, "acme", "ops"); slices.Contains(c, "web01") {
			t.Errorf("new web01 inherited ops membership: %v", c)
		}
		wantAuth(t, "web02 after web01 is reused", statusOf(t, signedAs(t, "web02", newKey, "GET", secret, "")), 200)
	})
}

// A rename to a taken name is a 409 that changes nothing; the body's name and
// clientname must agree and be a valid client name, as chef_client checks.
func TestRenameClientRefusals(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	key := createClientAndKey(t, srv, base, "web01")
	createClientAndKey(t, srv, base, "web02")

	body := expectStatus(t, "rename onto web02", signed(t, srv, "PUT", base+"/clients/web01", `{"name":"web02"}`), 409)
	if string(body) != `{"error":["Client already exists"]}` {
		t.Errorf("conflict body = %s", body)
	}
	body = expectStatus(t, "mismatched names", signed(t, srv, "PUT", base+"/clients/web01", `{"name":"web03","clientname":"web04"}`), 400)
	if string(body) != `{"error":["name and clientname must match"]}` {
		t.Errorf("mismatch body = %s", body)
	}
	expectStatus(t, "invalid name", signed(t, srv, "PUT", base+"/clients/web01", `{"name":"bad name"}`), 400)
	wantAuth(t, "web01 after refused renames", statusOf(t, signedAs(t, "web01", key, "GET", base+"/nodes", "")), 200)
	expectStatus(t, "web01 still there", signed(t, srv, "GET", base+"/clients/web01", ""), 200)
	// clientname alone names the destination too.
	resp, _ := doFull(t, signed(t, srv, "PUT", base+"/clients/web01", `{"clientname":"web05"}`))
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("Location") != base+"/clients/web05" {
		t.Errorf("rename by clientname = %d at %q, want 201 at web05", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestRenameUserViaPut(t *testing.T) {
	renameBackends(t, func(t *testing.T, opts Options) {
		srv := startServer(t, opts)
		root := srv.URL() + "/organizations/"
		bobKey := []byte(createUser(t, srv, `{"name":"bob"}`))
		malloryKey := []byte(createUser(t, srv, `{"name":"mallory"}`))
		for _, u := range []string{"bob", "mallory"} {
			expectStatus(t, "associate "+u, signed(t, srv, "POST", root+"acme/users", `{"username":"`+u+`"}`), 201)
		}
		expectStatus(t, "invite bob to beta", signed(t, srv, "POST", root+"beta/association_requests", `{"user":"bob"}`), 201)
		expectStatus(t, "bob server-admin", signed(t, srv, "PUT", srv.URL()+"/_cinc/server_admins/bob", ""), 201)
		renameOnlyReader(t, srv, `{"actors":[],"users":["bob"],"clients":[],"groups":[]}`)
		secret := root + "acme/nodes/secret"

		wantAuth(t, "baseline bob read", statusOf(t, signedAs(t, "bob", bobKey, "GET", secret, "")), 200)
		wantAuth(t, "baseline mallory read", statusOf(t, signedAs(t, "mallory", malloryKey, "GET", secret, "")), 403)
		beforeACL := rawGranularACL(t, srv, srv.URL()+"/users/bob")

		// A user may rename itself; erchef reads the new name from "name",
		// then "username".
		resp, body := doFull(t, signedAs(t, "bob", bobKey, "PUT", srv.URL()+"/users/bob",
			validUserBody(t, `{"username":"robert","display_name":"Robert","email":"bob@example.test"}`)))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("rename = %d, want 201: %s", resp.StatusCode, body)
		}
		if loc := resp.Header.Get("Location"); loc != srv.URL()+"/users/robert" {
			t.Errorf("Location = %q, want %s/users/robert", loc, srv.URL())
		}
		if string(body) != `{"uri":"`+srv.URL()+`/users/robert"}` {
			t.Errorf("rename body = %s, want the new URI alone", body)
		}

		expectStatus(t, "GET old name", signed(t, srv, "GET", srv.URL()+"/users/bob", ""), 404)
		var got map[string]any
		getJSON(t, srv, srv.URL()+"/users/robert", &got)
		if got["username"] != "robert" || got["display_name"] != "Robert" {
			t.Errorf("renamed user = %v", got)
		}

		// User keys survive (erchef keys them by the user's id), and only the
		// new name authenticates.
		wantAuth(t, "bob's key as robert", statusOf(t, signedAs(t, "robert", bobKey, "GET", secret, "")), 200)
		wantAuth(t, "bob's key as bob", statusOf(t, signedAs(t, "bob", bobKey, "GET", secret, "")), 401)
		if after := rawGranularACL(t, srv, srv.URL()+"/users/robert"); after != strings.ReplaceAll(beforeACL, `"bob"`, `"robert"`) {
			t.Errorf("renamed user's ACL = %s, want the old one renamed: %s", after, beforeACL)
		}
		if acl := rawGranularACL(t, srv, secret); strings.Contains(acl, `"bob"`) || !strings.Contains(acl, `"robert"`) {
			t.Errorf("secret's ACL = %s, want robert in place of bob", acl)
		}
		members := orgMemberNames(t, srv, "acme")
		if slices.Contains(members, "bob") || !slices.Contains(members, "robert") {
			t.Errorf("acme members = %v, want robert in place of bob", members)
		}
		if u, _, _ := groupDoc(t, srv, "acme", "users"); slices.Contains(u, "bob") || !slices.Contains(u, "robert") {
			t.Errorf("acme users group = %v, want robert in place of bob", u)
		}
		if invites := orgInviteUsers(t, srv, "beta"); slices.Contains(invites, "bob") || !slices.Contains(invites, "robert") {
			t.Errorf("beta invitations = %v, want robert in place of bob", invites)
		}
		admins := string(expectStatus(t, "list server-admins", signed(t, srv, "GET", srv.URL()+"/_cinc/server_admins", ""), 200))
		if strings.Contains(admins, `"bob"`) || !strings.Contains(admins, `"robert"`) {
			t.Errorf("server-admins = %s, want robert in place of bob", admins)
		}
		expectStatus(t, "robert's password", signed(t, srv, "POST", srv.URL()+"/authenticate_user",
			`{"username":"robert","password":"pw-123456"}`), 200)
		expectStatus(t, "robert accepts beta", signedAs(t, "robert", bobKey, "PUT",
			srv.URL()+"/users/robert/association_requests/robert-beta", `{"response":"accept"}`), 200)

		// A new user under the old name inherits nothing.
		newBobKey := []byte(createUser(t, srv, `{"name":"bob"}`))
		expectStatus(t, "associate new bob", signed(t, srv, "POST", root+"acme/users", `{"username":"bob"}`), 201)
		wantAuth(t, "new bob read", statusOf(t, signedAs(t, "bob", newBobKey, "GET", secret, "")), 403)
		if invites := orgInviteUsers(t, srv, "beta"); slices.Contains(invites, "bob") {
			t.Errorf("new bob inherited an invitation: %v", invites)
		}
		if strings.Contains(string(expectStatus(t, "list server-admins", signed(t, srv, "GET", srv.URL()+"/_cinc/server_admins", ""), 200)), `"bob"`) {
			t.Error("new bob inherited server-admins membership")
		}
	})
}

func TestRenameUserConflict(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	createUser(t, srv, `{"name":"bob"}`)
	createUser(t, srv, `{"name":"alice"}`)
	body := expectStatus(t, "rename onto alice", signed(t, srv, "PUT", srv.URL()+"/users/bob",
		validUserBody(t, `{"username":"alice","email":"bob@example.test"}`)), 409)
	if string(body) != `{"error":["User 'alice' already exists"]}` {
		t.Errorf("conflict body = %s", body)
	}
	var got map[string]any
	getJSON(t, srv, srv.URL()+"/users/bob", &got)
	getJSON(t, srv, srv.URL()+"/users/alice", &got)
	if got["email"] != "alice@example.test" {
		t.Errorf("alice changed by a refused rename: %v", got)
	}
}

func TestRenameGroupViaPut(t *testing.T) {
	renameBackends(t, func(t *testing.T, opts Options) {
		srv := startServer(t, opts)
		base := srv.URL() + "/organizations/acme"
		webKey := createClientAndKey(t, srv, base, "web01")
		otherKey := createClientAndKey(t, srv, base, "other")
		for _, g := range []string{"ops", "parent"} {
			expectStatus(t, "create group "+g, signed(t, srv, "POST", base+"/groups", `{"groupname":"`+g+`"}`), 201)
		}
		expectStatus(t, "fill ops", signed(t, srv, "PUT", base+"/groups/ops",
			`{"groupname":"ops","actors":{"users":[],"clients":["web01"],"groups":[]}}`), 200)
		expectStatus(t, "nest ops", signed(t, srv, "PUT", base+"/groups/parent",
			`{"groupname":"parent","actors":{"users":[],"clients":[],"groups":["ops"]}}`), 200)
		renameOnlyReader(t, srv, `{"actors":[],"users":[],"clients":[],"groups":["ops"]}`)
		secret := base + "/nodes/secret"

		wantAuth(t, "baseline web01 read", statusOf(t, signedAs(t, "web01", webKey, "GET", secret, "")), 200)
		wantAuth(t, "baseline other read", statusOf(t, signedAs(t, "other", otherKey, "GET", secret, "")), 403)
		beforeACL := rawGranularACL(t, srv, base+"/groups/ops")

		// A rename without "actors" keeps the membership.
		resp, body := doFull(t, signed(t, srv, "PUT", base+"/groups/ops", `{"groupname":"sre"}`))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("rename = %d, want 201: %s", resp.StatusCode, body)
		}
		if loc := resp.Header.Get("Location"); loc != base+"/groups/sre" {
			t.Errorf("Location = %q, want %s/groups/sre", loc, base)
		}
		expectStatus(t, "GET old name", signed(t, srv, "GET", base+"/groups/ops", ""), 404)
		var g map[string]any
		getJSON(t, srv, base+"/groups/sre", &g)
		if g["groupname"] != "sre" || g["name"] != "sre" {
			t.Errorf("renamed group = %v", g)
		}
		if _, c, _ := groupDoc(t, srv, "acme", "sre"); !slices.Equal(c, []string{"web01"}) {
			t.Errorf("sre clients = %v, want [web01]", c)
		}
		if _, _, gs := groupDoc(t, srv, "acme", "parent"); !slices.Equal(gs, []string{"sre"}) {
			t.Errorf("parent groups = %v, want [sre]", gs)
		}
		if after := rawGranularACL(t, srv, base+"/groups/sre"); after != beforeACL {
			t.Errorf("renamed group's ACL = %s, want %s", after, beforeACL)
		}
		if acl := rawGranularACL(t, srv, secret); strings.Contains(acl, `"ops"`) || !strings.Contains(acl, `"sre"`) {
			t.Errorf("secret's ACL = %s, want sre in place of ops", acl)
		}
		wantAuth(t, "web01 read via sre", statusOf(t, signedAs(t, "web01", webKey, "GET", secret, "")), 200)

		// A new group under the old name inherits nothing.
		expectStatus(t, "create new ops", signed(t, srv, "POST", base+"/groups", `{"groupname":"ops"}`), 201)
		expectStatus(t, "fill new ops", signed(t, srv, "PUT", base+"/groups/ops",
			`{"groupname":"ops","actors":{"users":[],"clients":["other"],"groups":[]}}`), 200)
		wantAuth(t, "other via new ops", statusOf(t, signedAs(t, "other", otherKey, "GET", secret, "")), 403)
		if _, _, gs := groupDoc(t, srv, "acme", "parent"); slices.Contains(gs, "ops") {
			t.Errorf("new ops inherited parent membership: %v", gs)
		}
	})
}

// A group rename onto a taken name is erchef's 409, whose error is a string
// (oc_chef_wm_named_group:conflict_message); a malformed groupname or id is
// refused as on create.
func TestRenameGroupRefusals(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	expectStatus(t, "create ops", signed(t, srv, "POST", base+"/groups", `{"groupname":"ops"}`), 201)
	body := expectStatus(t, "rename onto admins", signed(t, srv, "PUT", base+"/groups/ops", `{"groupname":"admins"}`), 409)
	if string(body) != `{"error":"Group already exists"}` {
		t.Errorf("conflict body = %s", body)
	}
	for _, b := range []string{`{"groupname":"Bad Name"}`, `{"id":"bad name"}`} {
		body = expectStatus(t, "invalid "+b, signed(t, srv, "PUT", base+"/groups/ops", b), 400)
		if string(body) != `{"error":["Invalid group name."]}` {
			t.Errorf("invalid %s body = %s", b, body)
		}
	}
	expectStatus(t, "ops still there", signed(t, srv, "GET", base+"/groups/ops", ""), 200)
}

// erchef refuses to rename an organization (oc_chef_organization's update
// constraint requires the existing name).
func TestRenameOrganizationRefused(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	expectStatus(t, "rename org", signed(t, srv, "PUT", srv.URL()+"/organizations/acme", `{"name":"other","full_name":"Other"}`), 400)
	expectStatus(t, "acme still there", signed(t, srv, "GET", srv.URL()+"/organizations/acme", ""), 200)
	expectStatus(t, "no org other", signed(t, srv, "GET", srv.URL()+"/organizations/other", ""), 404)
}

// storedKeyNames lists the key rows stored for an actor, straight from the
// store, so keys left behind under a name no endpoint shows are still seen.
func storedKeyNames(t *testing.T, srv *Server, org, segment, actor string) []string {
	t.Helper()
	space := srv.Store().Global()
	if org != "" {
		o, ok, err := srv.Store().Org(org)
		if err != nil || !ok {
			t.Fatalf("org %s: %v", org, err)
		}
		space = o
	}
	names, err := space.Keys(segment + "_keys:" + actor)
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// A rename moves every key but a client's default to the new name, and
// leaves none under the old one: a key left there would authenticate whoever
// is later created under that name.
func TestRenameMovesKeys(t *testing.T) {
	renameBackends(t, func(t *testing.T, opts Options) {
		srv := startServer(t, opts)
		base := srv.URL() + "/organizations/acme"
		probe := base + "/nodes"
		const second = `{"name":"second","create_key":true,"expiration_date":"infinity"}`

		// A client with its default key and a second one.
		createClientAndKey(t, srv, base, "web01")
		clientSecond := addKey(t, srv, base+"/clients/web01/keys", second)
		wantAuth(t, "baseline client second key", statusOf(t, signedAs(t, "web01", clientSecond, "GET", probe, "")), 200)
		expectStatus(t, "rename client", signed(t, srv, "PUT", base+"/clients/web01", `{"name":"web02"}`), 201)
		wantAuth(t, "second key as web02", statusOf(t, signedAs(t, "web02", clientSecond, "GET", probe, "")), 200)
		if names := storedKeyNames(t, srv, "acme", "clients", "web01"); len(names) != 0 {
			t.Errorf("keys left under web01: %v", names)
		}
		if names := storedKeyNames(t, srv, "acme", "clients", "web02"); !slices.Equal(names, []string{"second"}) {
			t.Errorf("web02's keys = %v, want [second]", names)
		}
		createClientAndKey(t, srv, base, "web01")
		wantAuth(t, "old second key as new web01", statusOf(t, signedAs(t, "web01", clientSecond, "GET", probe, "")), 401)

		// A user with its default key and a second one: both move.
		bobKey := []byte(createUser(t, srv, `{"name":"bob"}`))
		userSecond := addKey(t, srv, srv.URL()+"/users/bob/keys", second)
		bobURL := srv.URL() + "/users/bob"
		wantAuth(t, "baseline user default key", statusOf(t, signedAs(t, "bob", bobKey, "GET", bobURL, "")), 200)
		wantAuth(t, "baseline user second key", statusOf(t, signedAs(t, "bob", userSecond, "GET", bobURL, "")), 200)
		expectStatus(t, "rename user", signed(t, srv, "PUT", bobURL,
			validUserBody(t, `{"username":"robert","email":"bob@example.test"}`)), 201)
		robertURL := srv.URL() + "/users/robert"
		wantAuth(t, "default key as robert", statusOf(t, signedAs(t, "robert", bobKey, "GET", robertURL, "")), 200)
		wantAuth(t, "second key as robert", statusOf(t, signedAs(t, "robert", userSecond, "GET", robertURL, "")), 200)
		if names := storedKeyNames(t, srv, "", "users", "bob"); len(names) != 0 {
			t.Errorf("keys left under bob: %v", names)
		}
		createUser(t, srv, `{"name":"bob"}`)
		wantAuth(t, "old default key as new bob", statusOf(t, signedAs(t, "bob", bobKey, "GET", bobURL, "")), 401)
		wantAuth(t, "old second key as new bob", statusOf(t, signedAs(t, "bob", userSecond, "GET", bobURL, "")), 401)
	})
}

// The name a group is renamed to is always checked, whichever of "id" and
// "groupname" the body carries. erchef checks "id" when present and then
// renames to "groupname" unchecked; here both are checked.
func TestRenameGroupChecksDestination(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	expectStatus(t, "create ops", signed(t, srv, "POST", base+"/groups", `{"groupname":"ops"}`), 201)
	for _, b := range []string{`{"id":"ok","groupname":"a/b"}`, `{"id":"a/b","groupname":"ok"}`} {
		body := expectStatus(t, "PUT "+b, signed(t, srv, "PUT", base+"/groups/ops", b), 400)
		if string(body) != `{"error":["Invalid group name."]}` {
			t.Errorf("PUT %s body = %s", b, body)
		}
	}
	expectStatus(t, "ops still there", signed(t, srv, "GET", base+"/groups/ops", ""), 200)
	expectStatus(t, "no group ok", signed(t, srv, "GET", base+"/groups/ok", ""), 404)
}

// The org's default groups and its validator client are found by name here
// (erchef finds them by authz id), so renaming one is refused: a deliberate
// difference from erchef.
func TestRenameRefusesNamedByCode(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	for _, g := range []string{"admins", "billing-admins", "clients", "users", "public_key_read_access"} {
		body := expectStatus(t, "rename "+g, signed(t, srv, "PUT", base+"/groups/"+g, `{"groupname":"renamed"}`), 400)
		if want := `{"error":["Cannot rename the default group '` + g + `'"]}`; string(body) != want {
			t.Errorf("rename %s body = %s, want %s", g, body, want)
		}
		expectStatus(t, g+" still there", signed(t, srv, "GET", base+"/groups/"+g, ""), 200)
	}
	// An update that keeps the name still works.
	expectStatus(t, "update admins in place", signed(t, srv, "PUT", base+"/groups/admins", `{"groupname":"admins"}`), 200)

	body := expectStatus(t, "rename validator", signed(t, srv, "PUT", base+"/clients/acme-validator",
		`{"name":"other-validator","validator":true}`), 400)
	if want := `{"error":["Cannot rename the validator client 'acme-validator'"]}`; string(body) != want {
		t.Errorf("rename validator body = %s, want %s", body, want)
	}
	expectStatus(t, "validator still there", signed(t, srv, "GET", base+"/clients/acme-validator", ""), 200)
	wantAuth(t, "validator still registers", statusOf(t, signedAs(t, "acme-validator", srv.ValidatorKey("acme"), "POST", base+"/clients",
		`{"name":"web09","create_key":true}`)), 201)
}
