package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
)

// getJSON fetches url as the superuser and decodes the body into out.
func getJSON(t *testing.T, srv *Server, url string, out any) {
	t.Helper()
	code, body := signedBody(t, signed(t, srv, "GET", url, ""))
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", url, code, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("decode %s: %v (%s)", url, err, body)
	}
}

func orgMemberNames(t *testing.T, srv *Server, org string) []string {
	t.Helper()
	var rows []struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	getJSON(t, srv, srv.URL()+"/organizations/"+org+"/users", &rows)
	var out []string
	for _, r := range rows {
		out = append(out, r.User.Username)
	}
	return out
}

func orgInviteUsers(t *testing.T, srv *Server, org string) []string {
	t.Helper()
	var rows []struct {
		Username string `json:"username"`
	}
	getJSON(t, srv, srv.URL()+"/organizations/"+org+"/association_requests", &rows)
	var out []string
	for _, r := range rows {
		out = append(out, r.Username)
	}
	return out
}

func groupUsers(t *testing.T, srv *Server, org, group string) []string {
	t.Helper()
	var g struct {
		Users []string `json:"users"`
	}
	getJSON(t, srv, srv.URL()+"/organizations/"+org+"/groups/"+group, &g)
	return g.Users
}

// Deleting a user takes its org memberships, its group memberships and its
// pending invitations with it, as erchef's ON DELETE CASCADE and authz actor
// deletion do. Otherwise the org keeps listing a user that no longer exists,
// and a user later created under the same name inherits all of it.
func TestDeleteUserCascadesMembership(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme", "beta", "gamma"}, EnforceACL: true})
	bobKey := []byte(createUser(t, srv, `{"name":"bob"}`))
	root := srv.URL() + "/organizations/"

	// bob joins acme directly and beta by invitation, is an admin of acme, and
	// has a pending invitation to gamma.
	if code := statusOf(t, signed(t, srv, "POST", root+"acme/users", `{"username":"bob"}`)); code != http.StatusCreated {
		t.Fatalf("associate bob with acme = %d, want 201", code)
	}
	if code := statusOf(t, signed(t, srv, "PUT", root+"acme/groups/admins",
		`{"groupname":"admins","actors":{"users":["bob"],"clients":[],"groups":[]}}`)); code != http.StatusOK {
		t.Fatalf("add bob to acme admins = %d, want 200", code)
	}
	if code := statusOf(t, signed(t, srv, "POST", root+"beta/association_requests", `{"user":"bob"}`)); code != http.StatusCreated {
		t.Fatalf("invite bob to beta = %d, want 201", code)
	}
	if code := statusOf(t, signedAs(t, "bob", bobKey, "PUT", srv.URL()+"/users/bob/association_requests/bob-beta", `{"response":"accept"}`)); code != http.StatusOK {
		t.Fatalf("bob accepts beta = %d, want 200", code)
	}
	if code := statusOf(t, signed(t, srv, "POST", root+"gamma/association_requests", `{"user":"bob"}`)); code != http.StatusCreated {
		t.Fatalf("invite bob to gamma = %d, want 201", code)
	}

	// Premise: all of it is in place.
	for _, org := range []string{"acme", "beta"} {
		if !slices.Contains(orgMemberNames(t, srv, org), "bob") {
			t.Fatalf("bob should be a member of %s before the delete", org)
		}
		if !slices.Contains(groupUsers(t, srv, org, "users"), "bob") {
			t.Fatalf("bob should be in %s's users group before the delete", org)
		}
	}
	if !slices.Contains(groupUsers(t, srv, "acme", "admins"), "bob") {
		t.Fatal("bob should be in acme's admins group before the delete")
	}
	if !slices.Contains(orgInviteUsers(t, srv, "gamma"), "bob") {
		t.Fatal("bob should have a pending gamma invitation before the delete")
	}

	if code := statusOf(t, signed(t, srv, "DELETE", srv.URL()+"/users/bob", "")); code != http.StatusOK {
		t.Fatalf("delete bob = %d, want 200", code)
	}

	for _, org := range []string{"acme", "beta"} {
		if slices.Contains(orgMemberNames(t, srv, org), "bob") {
			t.Errorf("%s still lists deleted user bob as a member", org)
		}
		if slices.Contains(groupUsers(t, srv, org, "users"), "bob") {
			t.Errorf("deleted user bob is still in %s's users group", org)
		}
	}
	if slices.Contains(groupUsers(t, srv, "acme", "admins"), "bob") {
		t.Error("deleted user bob is still in acme's admins group")
	}
	if slices.Contains(orgInviteUsers(t, srv, "gamma"), "bob") {
		t.Error("gamma still lists an invitation for deleted user bob")
	}

	// A new user under the same name starts with none of it.
	newKey := []byte(createUser(t, srv, `{"name":"bob"}`))
	var orgs []any
	getJSON(t, srv, srv.URL()+"/users/bob/organizations", &orgs)
	if len(orgs) != 0 {
		t.Errorf("recreated bob belongs to %v, want no orgs", orgs)
	}
	if code := statusOf(t, signedAs(t, "bob", newKey, "GET", root+"acme/nodes", "")); code != http.StatusForbidden {
		t.Errorf("recreated bob lists acme nodes = %d, want 403", code)
	}
	var count struct {
		Value int `json:"value"`
	}
	getJSON(t, srv, srv.URL()+"/users/bob/association_requests/count", &count)
	if count.Value != 0 {
		t.Errorf("recreated bob has %d pending invitations, want 0", count.Value)
	}
}
