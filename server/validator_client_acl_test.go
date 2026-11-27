package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// erchef creates a client the validator registers as the authz superuser
// (oc_chef_wm_base:create_in_container(client, ...) with a validator requestor
// calls do_create_in_container(client, ..., superuser)), so the validator holds
// nothing on it: the new client's ACL is the clients container's plus the
// client itself. Granted every permission as its creator, anyone with the
// validator key could add a key to any client it registered and act as it.

// TestValidatorHoldsNothingOnClientsItRegisters: the validator gets 403 on the
// keys, ACL, record and delete of a client it registered, while the client
// still reads itself and manages its own keys.
func TestValidatorHoldsNothingOnClientsItRegisters(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	vkey := srv.ValidatorKey("acme")

	// Baseline: the validator key is valid and may register clients.
	webKey := createClientAndKey(t, srv, acme, "web01")

	mustStatus(t, signedAs(t, "acme-validator", vkey, "POST", acme+"/clients/web01/keys", `{"name":"stolen","create_key":true,"expiration_date":"infinity"}`), http.StatusForbidden)
	mustStatus(t, signedAs(t, "acme-validator", vkey, "GET", acme+"/clients/web01/_acl", ""), http.StatusForbidden)
	mustStatus(t, signedAs(t, "acme-validator", vkey, "PUT", acme+"/clients/web01/_acl/update",
		`{"update":{"actors":["acme-validator"],"groups":[]}}`), http.StatusForbidden)
	mustStatus(t, signedAs(t, "acme-validator", vkey, "PUT", acme+"/clients/web01", `{"name":"web01","admin":true}`), http.StatusForbidden)
	mustStatus(t, signedAs(t, "acme-validator", vkey, "DELETE", acme+"/clients/web01", ""), http.StatusForbidden)

	// The client itself keeps full control of its own record.
	mustStatus(t, signedAs(t, "web01", webKey, "GET", acme+"/clients/web01", ""), http.StatusOK)
	mustStatus(t, signedAs(t, "web01", webKey, "POST", acme+"/clients/web01/keys", `{"name":"rotated","create_key":true,"expiration_date":"infinity"}`), http.StatusCreated)
	mustStatus(t, signedAs(t, "web01", webKey, "GET", acme+"/clients/web01/keys/stolen", ""), http.StatusNotFound)

	// Its ACL names the client itself and no other actor.
	assertClientACLActors(t, srv, acme+"/clients/web01/_acl?detail=granular", "web01")
}

// assertClientACLActors checks every permission of the ACL at url lists exactly
// the client self, and no users.
func assertClientACLActors(t *testing.T, srv *Server, url, self string) {
	t.Helper()
	code, body := signedBody(t, signed(t, srv, "GET", url, ""))
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", url, code, body)
	}
	var acl map[string]struct {
		Users   []string `json:"users"`
		Clients []string `json:"clients"`
	}
	if err := json.Unmarshal(body, &acl); err != nil {
		t.Fatal(err)
	}
	for _, perm := range []string{"create", "read", "update", "delete", "grant"} {
		if ace := acl[perm]; !slices.Equal(ace.Clients, []string{self}) || len(ace.Users) != 0 {
			t.Errorf("%s: users %v clients %v, want [] [%s]", perm, ace.Users, ace.Clients, self)
		}
	}
}

// TestValidatorBootstrapStillWorks: the standard chef-client bootstrap, the
// validator registering a client that then creates and saves its own node, is
// untouched by the validator holding nothing on the client.
func TestValidatorBootstrapStillWorks(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	key := createClientAndKey(t, srv, acme, "web01")
	mustStatus(t, signedAs(t, "web01", key, "POST", acme+"/nodes", `{"name":"web01"}`), http.StatusCreated)
	mustStatus(t, signedAs(t, "web01", key, "PUT", acme+"/nodes/web01", `{"name":"web01","normal":{"a":1}}`), http.StatusOK)
	mustStatus(t, signedAs(t, "web01", key, "GET", acme+"/nodes/web01", ""), http.StatusOK)
}

// TestValidatorCannotCreateValidator: erchef refuses a validator's request to
// create another validator with 403 (create_in_container, "NOT IN MY HOUSE"),
// and creates nothing.
func TestValidatorCannotCreateValidator(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	vkey := srv.ValidatorKey("acme")

	// Baseline: an admin may create a validator, and the validator a client.
	mustStatus(t, signed(t, srv, "POST", acme+"/clients", `{"name":"val2","validator":true}`), http.StatusCreated)
	createClientAndKey(t, srv, acme, "web01")

	code, body := signedBody(t, signedAs(t, "acme-validator", vkey, "POST", acme+"/clients", `{"name":"evil","validator":true,"create_key":true}`))
	if code != http.StatusForbidden {
		t.Fatalf("validator creates a validator = %d, want 403: %s", code, body)
	}
	if want := `{"error":["missing create permission"]}`; strings.TrimSpace(string(body)) != want {
		t.Errorf("body = %s, want %s", body, want)
	}
	mustStatus(t, signed(t, srv, "GET", acme+"/clients/evil", ""), http.StatusNotFound)
}

// TestOtherValidatorHoldsNothingOnClientsItRegisters: erchef recognizes a
// validator by its client record's validator flag, not by its name, so a second
// validator an admin lets create clients is treated the same way. (The create
// entry the admin gave it on the clients container is copied onto the new
// client, as erchef copies it; create on a client grants nothing.)
func TestOtherValidatorHoldsNothingOnClientsItRegisters(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"

	code, body := signedBody(t, signed(t, srv, "POST", acme+"/clients", `{"name":"val2","validator":true,"create_key":true}`))
	if code != http.StatusCreated {
		t.Fatalf("create val2 = %d: %s", code, body)
	}
	var created struct {
		ChefKey struct {
			PrivateKey string `json:"private_key"`
		} `json:"chef_key"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	vkey := []byte(created.ChefKey.PrivateKey)
	// Baseline: val2 may not register clients until an admin lets it.
	mustStatus(t, signedAs(t, "val2", vkey, "POST", acme+"/clients", `{"name":"web00"}`), http.StatusForbidden)
	mustStatus(t, signed(t, srv, "PUT", acme+"/containers/clients/_acl/create",
		`{"create":{"actors":["acme-validator","val2"],"groups":["admins"]}}`), http.StatusOK)
	mustStatus(t, signedAs(t, "val2", vkey, "POST", acme+"/clients", `{"name":"web01"}`), http.StatusCreated)

	mustStatus(t, signedAs(t, "val2", vkey, "POST", acme+"/clients/web01/keys", `{"name":"stolen","create_key":true,"expiration_date":"infinity"}`), http.StatusForbidden)
	mustStatus(t, signedAs(t, "val2", vkey, "PUT", acme+"/clients/web01", `{"name":"web01"}`), http.StatusForbidden)
	mustStatus(t, signedAs(t, "val2", vkey, "DELETE", acme+"/clients/web01", ""), http.StatusForbidden)
	mustStatus(t, signedAs(t, "val2", vkey, "POST", acme+"/clients", `{"name":"evil","validator":true}`), http.StatusForbidden)
}

// TestValidatorRemovedFromRegisteredClientACLsOnStart covers a durable store
// written by a version that gave the validator every permission on each client
// it registered: restarting on it takes the validator off those ACLs.
func TestValidatorRemovedFromRegisteredClientACLsOnStart(t *testing.T) {
	db := filepath.Join(t.TempDir(), "validator.db")
	opts := Options{Orgs: []string{"acme"}, Storage: "sqlite", DB: db, EnforceACL: true}

	srv1, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv1.Start(); err != nil {
		t.Fatal(err)
	}
	acme := srv1.URL() + "/organizations/acme"
	vkey := srv1.ValidatorKey("acme")
	createClientAndKey(t, srv1, acme, "web01")
	// The ACL the older version wrote: the validator, as creator, on every
	// permission alongside the client itself.
	const legacy = `{"create":{"clients":["acme-validator","web01"],"groups":["admins"],"users":[]},` +
		`"delete":{"clients":["acme-validator","web01"],"groups":["admins","users"],"users":[]},` +
		`"grant":{"clients":["acme-validator","web01"],"groups":["admins"],"users":[]},` +
		`"read":{"clients":["acme-validator","web01"],"groups":["admins","users"],"users":[]},` +
		`"update":{"clients":["acme-validator","web01"],"groups":["admins"],"users":[]}}`
	org, _, err := srv1.Store().Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := org.Put("acls", "clients/web01", []byte(legacy)); err != nil {
		t.Fatal(err)
	}
	// Baseline: under that ACL the validator reads the client's ACL.
	mustStatus(t, signedAs(t, "acme-validator", vkey, "GET", acme+"/clients/web01/_acl", ""), http.StatusOK)
	stopServer(t, srv1)

	srv2, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv2.Start(); err != nil {
		t.Fatal(err)
	}
	defer stopServer(t, srv2)
	acme = srv2.URL() + "/organizations/acme"
	mustStatus(t, signedAs(t, "acme-validator", vkey, "GET", acme+"/clients/web01/_acl", ""), http.StatusForbidden)
	mustStatus(t, signedAs(t, "acme-validator", vkey, "POST", acme+"/clients/web01/keys", `{"name":"stolen","create_key":true,"expiration_date":"infinity"}`), http.StatusForbidden)
	assertClientACLActors(t, srv2, acme+"/clients/web01/_acl?detail=granular", "web01")
}
