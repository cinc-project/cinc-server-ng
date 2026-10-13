package server

import (
	"net/http"
	"testing"
)

// A group PUT that leaves a member kind out keeps that kind's members, as
// erchef does, so a group used for authorization keeps granting to them. A
// PUT that names the kind replaces it and revokes the grant.
func TestGroupPartialPutKeepsGrants(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	nodeKey := createActor(t, srv, base+"/clients", `{"name":"node1"}`)
	readWeb01 := func() int {
		return statusOf(t, signedAs(t, "node1", nodeKey, "GET", base+"/nodes/web01", ""))
	}
	put := func(body string) {
		t.Helper()
		if code := statusOf(t, signed(t, srv, "PUT", base+"/groups/auditors", body)); code != http.StatusOK {
			t.Fatalf("PUT auditors %s = %d, want 200", body, code)
		}
	}

	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes", `{"name":"web01"}`)); code != 201 {
		t.Fatalf("create node = %d, want 201", code)
	}
	if code := statusOf(t, signed(t, srv, "POST", base+"/groups", `{"groupname":"auditors"}`)); code != 201 {
		t.Fatalf("create group = %d, want 201", code)
	}
	if code := statusOf(t, signed(t, srv, "PUT", base+"/nodes/web01/_acl/read",
		`{"read":{"actors":[],"groups":["auditors"]}}`)); code != 200 {
		t.Fatalf("grant read to auditors = %d, want 200", code)
	}
	if code := readWeb01(); code != http.StatusForbidden {
		t.Fatalf("baseline: node1 outside auditors reads web01 = %d, want 403", code)
	}

	put(`{"groupname":"auditors","actors":{"users":[],"clients":["node1"],"groups":[]}}`)
	if code := readWeb01(); code != http.StatusOK {
		t.Fatalf("node1 in auditors reads web01 = %d, want 200", code)
	}

	put(`{"groupname":"auditors","actors":{"users":["pivotal"]}}`)
	if code := readWeb01(); code != http.StatusOK {
		t.Fatalf("after a users-only PUT, node1 reads web01 = %d, want 200 (clients kept)", code)
	}

	put(`{"groupname":"auditors","actors":{"clients":[]}}`)
	if code := readWeb01(); code != http.StatusForbidden {
		t.Fatalf("after clients replaced with [], node1 reads web01 = %d, want 403", code)
	}
}

// The same holds for membership recorded as rows: a registered client joins
// the org's "clients" group incrementally, and a PUT that omits clients must
// not drop it, while one that replaces clients must.
func TestGroupPartialPutKeepsRowMembers(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	nodeKey := createActor(t, srv, base+"/clients", `{"name":"node1"}`)
	createNode := func(name string) int {
		return statusOf(t, signedAs(t, "node1", nodeKey, "POST", base+"/nodes", `{"name":"`+name+`"}`))
	}
	put := func(body string) {
		t.Helper()
		if code := statusOf(t, signed(t, srv, "PUT", base+"/groups/clients", body)); code != http.StatusOK {
			t.Fatalf("PUT clients %s = %d, want 200", body, code)
		}
	}

	if code := createNode("n1"); code != http.StatusCreated {
		t.Fatalf("baseline: registered node1 creates a node = %d, want 201", code)
	}

	put(`{"groupname":"clients","actors":{"users":[]}}`)
	if code := createNode("n2"); code != http.StatusCreated {
		t.Fatalf("after a users-only PUT on clients, node1 creates a node = %d, want 201", code)
	}

	put(`{"groupname":"clients","actors":{"clients":[]}}`)
	if code := createNode("n3"); code != http.StatusForbidden {
		t.Fatalf("after clients replaced with [], node1 creates a node = %d, want 403", code)
	}
}
