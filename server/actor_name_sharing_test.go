package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// Real Chef Infra Server lets an org client and a global user share a name:
// a node's hostname often matches a username. erchef keys authorization on
// authz ids and authenticates whichever same-named requestor's key verifies
// (oc_chef_wm_base verify_request_signature), so neither inherits the other's
// grants or displaces it. These tests pin that the name may be shared and that
// sharing it grants nothing across the two.

// A client registered with a validator key under a user's name gets none of
// that user's grants, and the user is not displaced by it.
func TestClientNamedLikeUserInheritsNothing(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	aliceKey := []byte(createUser(t, srv, `{"name":"alice"}`))
	mustStatus(t, signed(t, srv, "POST", acme+"/users", `{"username":"alice"}`), http.StatusCreated)

	// A node only alice (and the admins) may read.
	mustStatus(t, signed(t, srv, "POST", acme+"/nodes", `{"name":"secret01"}`), http.StatusCreated)
	mustStatus(t, signed(t, srv, "PUT", acme+"/nodes/secret01/_acl/read",
		`{"read":{"actors":["alice"],"groups":["admins"]}}`), http.StatusOK)
	mustStatus(t, signedAs(t, "alice", aliceKey, "GET", acme+"/nodes/secret01", ""), http.StatusOK)

	// Baseline: an unrelated client may not read it.
	otherKey := createClientAndKey(t, srv, acme, "web01")
	mustStatus(t, signedAs(t, "web01", otherKey, "GET", acme+"/nodes/secret01", ""), http.StatusForbidden)

	// The validator may now register a client named alice.
	clientKey := createClientAndKey(t, srv, acme, "alice")

	// It holds nothing granted to the user alice, directly or through search,
	// and is not taken for an org member.
	mustStatus(t, signedAs(t, "alice", clientKey, "GET", acme+"/nodes/secret01", ""), http.StatusForbidden)
	if rows := searchNodeNames(t, signedAs(t, "alice", clientKey, "GET", acme+"/search/node?q=*:*", "")); contains(rows, "secret01") {
		t.Errorf("client alice finds secret01 through search: %v", rows)
	}
	mustStatus(t, signedAs(t, "alice", clientKey, "GET", acme+"/users", ""), http.StatusForbidden)

	// The user alice still authenticates as herself, with her grants, signed
	// with her key and through the webui.
	mustStatus(t, signedAs(t, "alice", aliceKey, "GET", acme+"/nodes/secret01", ""), http.StatusOK)
	mustStatus(t, signedAs(t, "alice", aliceKey, "GET", acme+"/users", ""), http.StatusOK)
	mustStatus(t, webuiSignedAs(t, srv, "alice", "GET", acme+"/nodes/secret01", ""), http.StatusOK)

	// And the client keeps what registration gives any client: its own record.
	mustStatus(t, signedAs(t, "alice", clientKey, "GET", acme+"/clients/alice", ""), http.StatusOK)
}

// The reverse order: a user created under a client's name gets none of the
// client's grants (the client owns the node it registered), and the client
// keeps working.
func TestUserNamedLikeClientInheritsNothing(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	clientKey := createClientAndKey(t, srv, acme, "node1")
	mustStatus(t, signedAs(t, "node1", clientKey, "POST", acme+"/nodes", `{"name":"node1"}`), http.StatusCreated)
	// Update and delete for node1 and the admins only. While only the client
	// exists, the merged form's "node1" names the client.
	for _, perm := range []string{"update", "delete"} {
		mustStatus(t, signed(t, srv, "PUT", acme+"/nodes/node1/_acl/"+perm,
			`{"`+perm+`":{"actors":["node1"],"groups":["admins"]}}`), http.StatusOK)
	}

	userKey := []byte(createUser(t, srv, `{"name":"node1"}`))
	mustStatus(t, signed(t, srv, "POST", acme+"/users", `{"username":"node1"}`), http.StatusCreated)
	// Baseline: the user is an org member, with what the users group holds.
	mustStatus(t, signedAs(t, "node1", userKey, "GET", acme+"/nodes/node1", ""), http.StatusOK)

	// Now "node1" is ambiguous in the merged form, as on erchef.
	mustStatus(t, signed(t, srv, "PUT", acme+"/nodes/node1/_acl/update",
		`{"update":{"actors":["node1"],"groups":["admins"]}}`), http.StatusUnprocessableEntity)

	// The client's grant is the client's.
	mustStatus(t, signedAs(t, "node1", userKey, "PUT", acme+"/nodes/node1", `{"name":"node1"}`), http.StatusForbidden)
	mustStatus(t, signedAs(t, "node1", userKey, "DELETE", acme+"/nodes/node1", ""), http.StatusForbidden)
	mustStatus(t, signedAs(t, "node1", clientKey, "PUT", acme+"/nodes/node1", `{"name":"node1"}`), http.StatusOK)
}

// Deleting one of two same-named actors removes its grants only.
func TestDeletingSameNamedActorKeepsTheOthersGrants(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	userKey := []byte(createUser(t, srv, `{"name":"dual"}`))
	mustStatus(t, signed(t, srv, "POST", acme+"/users", `{"username":"dual"}`), http.StatusCreated)
	createClientAndKey(t, srv, acme, "dual")

	mustStatus(t, signed(t, srv, "POST", acme+"/nodes", `{"name":"secret01"}`), http.StatusCreated)
	mustStatus(t, signed(t, srv, "PUT", acme+"/nodes/secret01/_acl/read",
		`{"read":{"actors":[],"users":["dual"],"clients":["dual"],"groups":["admins"]}}`), http.StatusOK)
	mustStatus(t, signedAs(t, "dual", userKey, "GET", acme+"/nodes/secret01", ""), http.StatusOK)

	mustStatus(t, signed(t, srv, "DELETE", acme+"/clients/dual", ""), http.StatusOK)
	mustStatus(t, signedAs(t, "dual", userKey, "GET", acme+"/nodes/secret01", ""), http.StatusOK)

	resp, err := http.DefaultClient.Do(signed(t, srv, "GET", acme+"/nodes/secret01/_acl?detail=granular", ""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var acl map[string]struct {
		Users   []string `json:"users"`
		Clients []string `json:"clients"`
	}
	json.NewDecoder(resp.Body).Decode(&acl)
	if r := acl["read"]; len(r.Clients) != 0 || len(r.Users) != 1 || r.Users[0] != "dual" {
		t.Errorf("read after deleting client dual = %+v, want users [dual] and no clients", r)
	}
}

func searchNodeNames(t *testing.T, req *http.Request) []string {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("search = %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		Rows []struct {
			Name string `json:"name"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode search %s: %v", raw, err)
	}
	names := make([]string, 0, len(out.Rows))
	for _, r := range out.Rows {
		names = append(names, r.Name)
	}
	return names
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
