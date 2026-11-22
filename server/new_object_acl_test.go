package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
)

// erchef gives a new object its container's ACL merged with the creator's
// (oc_chef_authz:create_entity_with_container_acl, merge_acl_from_container),
// not a fixed default. These pin that for each kind created through the generic
// object and actor handlers.

// objectACLGroups reads an object's ACL and returns perm -> groups.
func objectACLGroups(t *testing.T, srv *Server, url string) map[string][]string {
	t.Helper()
	code, body := signedBody(t, signed(t, srv, "GET", url, ""))
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", url, code, body)
	}
	var acl map[string]struct {
		Groups  []string `json:"groups"`
		Actors  []string `json:"actors"`
		Clients []string `json:"clients"`
	}
	if err := json.Unmarshal(body, &acl); err != nil {
		t.Fatalf("%s: %v", url, err)
	}
	out := map[string][]string{}
	for perm, ace := range acl {
		g := slices.Clone(ace.Groups)
		slices.Sort(g)
		out[perm] = g
	}
	return out
}

// TestNewClientTakesClientsContainerACL: erchef's clients container gives the
// users group read and delete only, so a new client's ACL does too. With the
// permissive object default instead, every org member held update on every
// client, which is what authorizes adding, changing and deleting its keys.
func TestNewClientTakesClientsContainerACL(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	if code, body := signedBody(t, signed(t, srv, "POST", base+"/clients", `{"name":"web01","create_key":true}`)); code != http.StatusCreated {
		t.Fatalf("create client = %d: %s", code, body)
	}

	got := objectACLGroups(t, srv, base+"/clients/web01/_acl")
	for _, perm := range []string{"create", "read", "update", "delete", "grant"} {
		want := slices.Clone(erchefPolicy["containers/clients"][perm])
		slices.Sort(want)
		if !slices.Equal(got[perm], want) {
			t.Errorf("client %s groups = %v, want the clients container's %v", perm, got[perm], want)
		}
	}
}

// TestOrgMemberCannotManageAnotherClientsKeys: erchef authorizes a client's key
// writes with update on the client (oc_chef_wm_keys:auth_info), which a plain
// member doesn't hold; reading them stays open to the org.
func TestOrgMemberCannotManageAnotherClientsKeys(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	bobKey := createUserKey(t, srv, "bob")
	if s := respStatus(t, signed(t, srv, "POST", base+"/users", `{"username":"bob"}`)); s != http.StatusCreated {
		t.Fatalf("associate bob = %d", s)
	}
	if code, body := signedBody(t, signed(t, srv, "POST", base+"/clients", `{"name":"web01","create_key":true}`)); code != http.StatusCreated {
		t.Fatalf("create client = %d: %s", code, body)
	}

	if s := respStatus(t, signedAs(t, "bob", bobKey, "POST", base+"/clients/web01/keys", `{"name":"bobs","create_key":true}`)); s != http.StatusForbidden {
		t.Errorf("member adds a key to web01 = %d, want 403", s)
	}
	if s := respStatus(t, signedAs(t, "bob", bobKey, "DELETE", base+"/clients/web01/keys/default", "")); s != http.StatusForbidden {
		t.Errorf("member deletes web01's default key = %d, want 403", s)
	}
	if s := respStatus(t, signedAs(t, "bob", bobKey, "GET", base+"/clients/web01/keys", "")); s != http.StatusOK {
		t.Errorf("member lists web01's keys = %d, want 200", s)
	}
}

// TestNewObjectInheritsNarrowedContainerACL: the container's ACL as it is now,
// not erchef's default for it, is what a new object takes. An admin who takes
// update on the nodes container away from users narrows every node created
// afterwards.
func TestNewObjectInheritsNarrowedContainerACL(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	if code, body := signedBody(t, signed(t, srv, "PUT", base+"/containers/nodes/_acl/update",
		`{"update":{"actors":[],"groups":["admins"]}}`)); code != http.StatusOK {
		t.Fatalf("narrow nodes container = %d: %s", code, body)
	}
	if code, body := signedBody(t, signed(t, srv, "POST", base+"/nodes", `{"name":"db01"}`)); code != http.StatusCreated {
		t.Fatalf("create node = %d: %s", code, body)
	}
	got := objectACLGroups(t, srv, base+"/nodes/db01/_acl")
	if !slices.Equal(got["update"], []string{"admins"}) {
		t.Errorf("new node update groups = %v, want [admins]", got["update"])
	}
}

// TestNewClientDoesNotListTheValidator: the clients container ACL stored here
// names the org's validator on create (erchef special-cases the validator in
// its handler instead), and that entry must not be copied onto every client.
func TestNewClientDoesNotListTheValidator(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	if code, body := signedBody(t, signed(t, srv, "POST", base+"/clients", `{"name":"web01","create_key":true}`)); code != http.StatusCreated {
		t.Fatalf("create client = %d: %s", code, body)
	}
	code, body := signedBody(t, signed(t, srv, "GET", base+"/clients/web01/_acl?detail=granular", ""))
	if code != http.StatusOK {
		t.Fatalf("GET ACL = %d: %s", code, body)
	}
	var acl map[string]struct {
		Clients []string `json:"clients"`
	}
	json.Unmarshal(body, &acl)
	for perm, ace := range acl {
		if slices.Contains(ace.Clients, "acme-validator") {
			t.Errorf("client %s lists acme-validator: %v", perm, ace.Clients)
		}
	}
}

// TestNewClientHoldsItsOwnRecord: bifrost puts a new actor in its own ACL with
// every permission (create_and_add_permissions.sql), so a client created by the
// validator may read itself and rotate its own keys, though the clients group
// holds nothing on the clients container.
func TestNewClientHoldsItsOwnRecord(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	key := createClientAndKey(t, srv, acme, "web01")
	mustStatus(t, signedAs(t, "web01", key, "GET", acme+"/clients/web01", ""), http.StatusOK)
	mustStatus(t, signedAs(t, "web01", key, "POST", acme+"/clients/web01/keys", `{"name":"rotated","create_key":true}`), http.StatusCreated)

	// But not another client's.
	createClientAndKey(t, srv, acme, "web02")
	mustStatus(t, signedAs(t, "web01", key, "POST", acme+"/clients/web02/keys", `{"name":"mine","create_key":true}`), http.StatusForbidden)
}
