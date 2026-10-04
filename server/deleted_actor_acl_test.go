package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// createdKey POSTs a client to the org and returns the private key it was
// issued.
func createdClientKey(t *testing.T, srv *Server, base, name string) []byte {
	t.Helper()
	resp, err := http.DefaultClient.Do(signed(t, srv, "POST", base+"/clients", `{"name":"`+name+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var created struct {
		ChefKey struct {
			PrivateKey string `json:"private_key"`
		} `json:"chef_key"`
	}
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(raw, &created) != nil || created.ChefKey.PrivateKey == "" {
		t.Fatalf("create client %s = %d: %s", name, resp.StatusCode, raw)
	}
	return []byte(created.ChefKey.PrivateKey)
}

// In Chef an ACL names an actor by its authz id, and deleting a client or a
// user deletes that actor and every reference to it. Here ACLs name actors by
// bare name, so a reference left behind would hand the deleted actor's grants
// to the next one created under the same name.
func TestDeletedClientsGrantsAreNotInherited(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"

	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes", `{"name":"secret"}`)); code != 201 {
		t.Fatalf("create node = %d", code)
	}
	key := createdClientKey(t, srv, base, "c1")
	// Only c1 may read the node.
	if code := statusOf(t, signed(t, srv, "PUT", base+"/nodes/secret/_acl/read",
		`{"read":{"actors":["c1"],"groups":[]}}`)); code != 200 {
		t.Fatalf("narrow read ACL = %d", code)
	}
	// Baseline: the grant works.
	if code := statusOf(t, signedAs(t, "c1", key, "GET", base+"/nodes/secret", "")); code != 200 {
		t.Fatalf("c1 read with its grant = %d, want 200", code)
	}

	if code := statusOf(t, signed(t, srv, "DELETE", base+"/clients/c1", "")); code != 200 {
		t.Fatalf("delete client = %d", code)
	}
	key = createdClientKey(t, srv, base, "c1")
	if code := statusOf(t, signedAs(t, "c1", key, "GET", base+"/nodes/secret", "")); code != 403 {
		t.Fatalf("a new client named c1 read the node the deleted c1 was granted = %d, want 403", code)
	}
}

func TestDeletedUsersGrantsAreNotInherited(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"

	addToOrg := func(name string) []byte {
		t.Helper()
		key := createUserKey(t, srv, name)
		if code := statusOf(t, signed(t, srv, "POST", base+"/users", `{"username":"`+name+`"}`)); code != 201 {
			t.Fatalf("add %s to org = %d", name, code)
		}
		return key
	}
	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes", `{"name":"secret"}`)); code != 201 {
		t.Fatalf("create node = %d", code)
	}
	key := addToOrg("dave")
	if code := statusOf(t, signed(t, srv, "PUT", base+"/nodes/secret/_acl/read",
		`{"read":{"actors":["dave"],"groups":[]}}`)); code != 200 {
		t.Fatalf("narrow read ACL = %d", code)
	}
	if code := statusOf(t, signedAs(t, "dave", key, "GET", base+"/nodes/secret", "")); code != 200 {
		t.Fatalf("dave read with his grant = %d, want 200", code)
	}

	if code := statusOf(t, signed(t, srv, "DELETE", srv.URL()+"/users/dave", "")); code != 200 {
		t.Fatalf("delete user = %d", code)
	}
	key = addToOrg("dave")
	if code := statusOf(t, signedAs(t, "dave", key, "GET", base+"/nodes/secret", "")); code != 403 {
		t.Fatalf("a new user named dave read the node the deleted dave was granted = %d, want 403", code)
	}
}

// A user's own ACL lives outside any org, and can name another user. Deleting
// that other user must take the entry with it there too. (Today a user's ACL
// does not gate reads of the user record, so the entry grants nothing yet;
// the test checks the reference is gone rather than an effect.)
func TestDeletedUserLeavesOtherUsersACLs(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	users := srv.URL() + "/users"
	createUserKey(t, srv, "yan")
	createUserKey(t, srv, "xia")

	if code := statusOf(t, signed(t, srv, "PUT", users+"/yan/_acl/read",
		`{"read":{"actors":["xia","yan","pivotal"],"groups":[]}}`)); code != 200 {
		t.Fatalf("grant xia read on yan = %d", code)
	}
	readActors := func() string {
		t.Helper()
		resp, err := http.DefaultClient.Do(signed(t, srv, "GET", users+"/yan/_acl", ""))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var acl struct {
			Read struct {
				Actors []string `json:"actors"`
			} `json:"read"`
		}
		if err := json.Unmarshal(raw, &acl); err != nil {
			t.Fatalf("read yan's ACL: %v: %s", err, raw)
		}
		return strings.Join(acl.Read.Actors, ",")
	}
	if got := readActors(); !strings.Contains(got, "xia") {
		t.Fatalf("baseline: yan's read ACL = %s, want xia in it", got)
	}
	if code := statusOf(t, signed(t, srv, "DELETE", users+"/xia", "")); code != 200 {
		t.Fatalf("delete xia = %d", code)
	}
	if got := readActors(); strings.Contains(got, "xia") {
		t.Errorf("yan's read ACL still names the deleted xia: %s", got)
	}
}
