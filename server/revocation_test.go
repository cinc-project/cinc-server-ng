package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Association puts a user in the org's "users" group, which the default ACL
// grants read/update/delete on every object. Disassociation has to undo that:
// otherwise the membership view says the user is gone while every object
// permission the group carries is still live.
func TestDisassociateRevokesObjectAccess(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	key := []byte(createUser(t, srv, `{"name":"bob"}`))

	if code := statusOf(t, signed(t, srv, "POST", acme+"/nodes", `{"name":"web01"}`)); code != 201 {
		t.Fatalf("create node = %d, want 201", code)
	}
	if code := statusOf(t, signed(t, srv, "POST", acme+"/users", `{"username":"bob"}`)); code != 201 {
		t.Fatalf("associate = %d, want 201", code)
	}
	// Premise: as a member, bob can read the node.
	if code := statusOf(t, signedAs(t, "bob", key, "GET", acme+"/nodes/web01", "")); code != http.StatusOK {
		t.Fatalf("member read node = %d, want 200", code)
	}

	if code := statusOf(t, signed(t, srv, "DELETE", acme+"/users/bob", "")); code != http.StatusOK {
		t.Fatalf("disassociate = %d, want 200", code)
	}

	for _, c := range []struct {
		what, method, body string
	}{
		{"read", "GET", ""},
		{"update", "PUT", `{"name":"web01","pwned":true}`},
		{"delete", "DELETE", ""},
	} {
		got := statusOf(t, signedAs(t, "bob", key, c.method, acme+"/nodes/web01", c.body))
		if got != http.StatusForbidden {
			t.Errorf("ex-member %s node = %d, want 403", c.what, got)
		}
	}
}

// Deleting a client has to revoke its group membership for the same reason: a
// registered client joins the org's "clients" group, and re-registering a name
// must not inherit what the previous holder of that name was granted.
func TestDeleteClientRevokesGroupMembership(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	vkey := srv.ValidatorKey("acme")

	if code := statusOf(t, signedAs(t, "acme-validator", vkey, "POST", acme+"/clients", `{"name":"node1"}`)); code != 201 {
		t.Fatalf("register client = %d, want 201", code)
	}
	if !groupHasClient(t, srv, "clients", "node1") {
		t.Fatal("registered client is not in the org clients group")
	}
	if code := statusOf(t, signed(t, srv, "DELETE", acme+"/clients/node1", "")); code != http.StatusOK {
		t.Fatalf("delete client = %d, want 200", code)
	}
	if groupHasClient(t, srv, "clients", "node1") {
		t.Error("deleted client is still a member of the org clients group")
	}
}

// groupHasClient reports whether an org group lists the named client, reading
// through the API so document and incremental-row membership are both folded in.
func groupHasClient(t *testing.T, srv *Server, group, client string) bool {
	t.Helper()
	code, body := signedBody(t, signed(t, srv, "GET",
		srv.URL()+"/organizations/acme/groups/"+group, ""))
	if code != http.StatusOK {
		t.Fatalf("read group %s = %d: %s", group, code, body)
	}
	var g struct {
		Clients []string `json:"clients"`
	}
	if err := json.Unmarshal(body, &g); err != nil {
		t.Fatalf("decode group %s: %v", group, err)
	}
	for _, c := range g.Clients {
		if c == client {
			return true
		}
	}
	return false
}
