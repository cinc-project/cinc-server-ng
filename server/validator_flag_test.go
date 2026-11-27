package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
)

const stealKeyBody = `{"name":"stolen","create_key":true,"expiration_date":"infinity"}`

// clientValidatorFlag reads a client's stored validator flag as the superuser
// sees it.
func clientValidatorFlag(t *testing.T, srv *Server, url string) any {
	t.Helper()
	code, body := signedBody(t, signed(t, srv, "GET", url, ""))
	if code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", url, code, body)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	return doc["validator"]
}

// TestValidatorCannotClearItsOwnFlag: the validator's own ACL lets it update
// its record, but not drop the validator flag, which would make every client
// it registers afterwards its own.
func TestValidatorCannotClearItsOwnFlag(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	vkey := srv.ValidatorKey("acme")

	// Baseline: the validator holds nothing on a client it registers.
	createClientAndKey(t, srv, acme, "web00")
	mustStatus(t, signedAs(t, "acme-validator", vkey, "POST", acme+"/clients/web00/keys", stealKeyBody), http.StatusForbidden)

	for _, body := range []string{
		`{"name":"acme-validator","validator":false}`,
		`{"name":"acme-validator","Validator":true,"validator":false}`,
		// erchef keeps a stored flag the update omits
		// (chef_client:set_values_from_current_client).
		`{"name":"acme-validator"}`,
	} {
		mustStatus(t, signedAs(t, "acme-validator", vkey, "PUT", acme+"/clients/acme-validator", body), http.StatusOK)
		if got := clientValidatorFlag(t, srv, acme+"/clients/acme-validator"); got != true {
			t.Fatalf("after PUT %s validator = %v, want true", body, got)
		}
	}

	createClientAndKey(t, srv, acme, "web01")
	mustStatus(t, signedAs(t, "acme-validator", vkey, "POST", acme+"/clients/web01/keys", stealKeyBody), http.StatusForbidden)
	mustStatus(t, signedAs(t, "acme-validator", vkey, "PUT", acme+"/clients/web01", `{"name":"web01"}`), http.StatusForbidden)
	assertClientACLActors(t, srv, acme+"/clients/web01/_acl?detail=granular", "web01")
}

// TestClientCannotMakeItselfAValidator: a client may update its own record,
// but the validator flag stays the org admins' to set.
func TestClientCannotMakeItselfAValidator(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	key := createClientAndKey(t, srv, acme, "web01")

	mustStatus(t, signedAs(t, "web01", key, "PUT", acme+"/clients/web01", `{"name":"web01","validator":true}`), http.StatusOK)
	if got := clientValidatorFlag(t, srv, acme+"/clients/web01"); got == true {
		t.Fatalf("web01 validator = %v after its own update, want unset", got)
	}
}

// TestOrgAdminSetsValidatorFlag: an org admin who is not the superuser may still
// set and clear a client's validator flag, as on erchef.
func TestOrgAdminSetsValidatorFlag(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	boss := createUserKey(t, srv, "boss")
	mustStatus(t, signed(t, srv, "POST", acme+"/users", `{"username":"boss"}`), http.StatusCreated)
	mustStatus(t, signed(t, srv, "PUT", acme+"/groups/admins",
		`{"groupname":"admins","actors":{"users":["boss"],"clients":[],"groups":[]}}`), http.StatusOK)
	createClientAndKey(t, srv, acme, "web01")

	mustStatus(t, signedAs(t, "boss", boss, "PUT", acme+"/clients/web01", `{"name":"web01","validator":true}`), http.StatusOK)
	if got := clientValidatorFlag(t, srv, acme+"/clients/web01"); got != true {
		t.Fatalf("web01 validator = %v after the admin set it, want true", got)
	}
	mustStatus(t, signedAs(t, "boss", boss, "PUT", acme+"/clients/web01", `{"name":"web01","validator":false}`), http.StatusOK)
	if got := clientValidatorFlag(t, srv, acme+"/clients/web01"); got != false {
		t.Fatalf("web01 validator = %v after the admin cleared it, want false", got)
	}
}

// TestOrgValidatorWithoutFlagHoldsNothingOnClientsItRegisters: the org's
// validator is granted create on the clients container by name, so it is
// treated as the validator by that name too. With its flag cleared (here by
// the superuser), it still holds nothing on the clients it registers, and
// still may not create a validator.
func TestOrgValidatorWithoutFlagHoldsNothingOnClientsItRegisters(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	vkey := srv.ValidatorKey("acme")

	mustStatus(t, signed(t, srv, "PUT", acme+"/clients/acme-validator", `{"name":"acme-validator","validator":false}`), http.StatusOK)
	if got := clientValidatorFlag(t, srv, acme+"/clients/acme-validator"); got != false {
		t.Fatalf("validator = %v after the superuser cleared it, want false", got)
	}

	createClientAndKey(t, srv, acme, "web01")
	mustStatus(t, signedAs(t, "acme-validator", vkey, "POST", acme+"/clients/web01/keys", stealKeyBody), http.StatusForbidden)
	assertClientACLActors(t, srv, acme+"/clients/web01/_acl?detail=granular", "web01")
	mustStatus(t, signedAs(t, "acme-validator", vkey, "POST", acme+"/clients", `{"name":"evil","validator":true}`), http.StatusForbidden)
}

// TestUnflaggedOrgValidatorRemovedFromClientACLsOnStart: a durable store where
// the org's validator had lost its flag and was granted, as creator, every
// permission on the clients it registered is repaired on restart.
func TestUnflaggedOrgValidatorRemovedFromClientACLsOnStart(t *testing.T) {
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
	mustStatus(t, signed(t, srv1, "PUT", acme+"/clients/acme-validator", `{"name":"acme-validator","validator":false}`), http.StatusOK)
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
	mustStatus(t, signedAs(t, "acme-validator", vkey, "POST", acme+"/clients/web01/keys", stealKeyBody), http.StatusForbidden)
	assertClientACLActors(t, srv2, acme+"/clients/web01/_acl?detail=granular", "web01")
}
