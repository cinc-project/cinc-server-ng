package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func decodeStringError(t *testing.T, body string) string {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("error body not a JSON object with a string error: %v (%s)", err, body)
	}
	return e.Error
}

// Duplicate association / invitation are 409 conflicts with string error bodies.
func TestAssociationConflicts(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/users", `{"name":"dave"}`)

	resp, body := do(t, "POST", srv.URL+"/organizations/acme/users", `{"username":"dave"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("associate = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, "POST", srv.URL+"/organizations/acme/users", `{"username":"dave"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("dup associate = %d, want 409: %s", resp.StatusCode, body)
	}
	if msg := decodeStringError(t, body); msg != "The association already exists." {
		t.Fatalf("dup associate body = %q", msg)
	}

	do(t, "POST", srv.URL+"/users", `{"name":"erin"}`)
	resp, body = do(t, "POST", srv.URL+"/organizations/acme/association_requests", `{"user":"erin"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("invite = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, "POST", srv.URL+"/organizations/acme/association_requests", `{"user":"erin"}`)
	if resp.StatusCode != 409 {
		t.Fatalf("dup invite = %d, want 409: %s", resp.StatusCode, body)
	}
	if msg := decodeStringError(t, body); msg != "The invitation already exists." {
		t.Fatalf("dup invite body = %q", msg)
	}
}

// A rescinded / consumed / nonexistent invite returns 404 with a string body.
func TestInviteConsumed(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/users", `{"name":"frank"}`)
	do(t, "POST", srv.URL+"/organizations/acme/association_requests", `{"user":"frank"}`)
	id := "frank-acme"

	resp, body := do(t, "PUT", srv.URL+"/users/frank/association_requests/"+id, `{"response":"reject"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("reject = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, "PUT", srv.URL+"/users/frank/association_requests/"+id, `{"response":"accept"}`)
	if resp.StatusCode != 404 {
		t.Fatalf("respond consumed = %d, want 404: %s", resp.StatusCode, body)
	}
	if msg := decodeStringError(t, body); !strings.Contains(msg, "Cannot find association request") {
		t.Fatalf("consumed body = %q", msg)
	}
	resp, body = do(t, "DELETE", srv.URL+"/organizations/acme/association_requests/"+id, "")
	if resp.StatusCode != 404 {
		t.Fatalf("rescind consumed = %d, want 404: %s", resp.StatusCode, body)
	}
	if msg := decodeStringError(t, body); !strings.Contains(msg, "Cannot find association request") {
		t.Fatalf("rescind body = %q", msg)
	}
}

// An invite whose recorded inviter has lost the authority to invite cannot be
// accepted.
func TestInviterLostAuthority(t *testing.T) {
	srv, st := newTestAPI(t)
	do(t, "POST", srv.URL+"/users", `{"name":"grace"}`)
	org, ok, err := st.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("acme org missing")
	}
	id := "grace-acme"
	if err := org.Put(assocReqColl, id, []byte(`{"id":"grace-acme","username":"grace","orgname":"acme","inviter":"ghostboss"}`)); err != nil {
		t.Fatal(err)
	}

	resp, body := do(t, "PUT", srv.URL+"/users/grace/association_requests/"+id, `{"response":"accept"}`)
	if resp.StatusCode != 403 {
		t.Fatalf("accept stale invite = %d, want 403: %s", resp.StatusCode, body)
	}
}

// A member of the org's admins group cannot be removed from the org until they
// have left the group: erchef refuses with a 403 naming the group, and knife
// matches that message to offer --force. Nothing is removed on the refusal.
func TestDisassociateAdminRefused(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/users", `{"name":"dave"}`)
	if resp, body := do(t, "POST", srv.URL+"/organizations/acme/users", `{"username":"dave"}`); resp.StatusCode != 201 {
		t.Fatalf("associate = %d: %s", resp.StatusCode, body)
	}
	if resp, body := do(t, "POST", srv.URL+"/organizations/acme/groups",
		`{"groupname":"admins","actors":{"users":["dave"],"clients":[],"groups":[]}}`); resp.StatusCode != 201 {
		t.Fatalf("create admins = %d: %s", resp.StatusCode, body)
	}

	resp, body := do(t, "DELETE", srv.URL+"/organizations/acme/users/dave", "")
	if resp.StatusCode != 403 {
		t.Fatalf("remove admin member = %d, want 403: %s", resp.StatusCode, body)
	}
	want := "Please remove dave from this organization's admins group before removing him or her from the organization."
	if msg := decodeStringError(t, body); msg != want {
		t.Fatalf("remove admin member body = %q, want %q", msg, want)
	}
	if resp, body := do(t, "GET", srv.URL+"/organizations/acme/users/dave", ""); resp.StatusCode != 200 {
		t.Fatalf("dave should still be a member after the refusal: %d %s", resp.StatusCode, body)
	}

	// Once out of admins, the removal goes through.
	if resp, body := do(t, "PUT", srv.URL+"/organizations/acme/groups/admins",
		`{"groupname":"admins","actors":{"users":[],"clients":[],"groups":[]}}`); resp.StatusCode != 200 {
		t.Fatalf("leave admins = %d: %s", resp.StatusCode, body)
	}
	if resp, body := do(t, "DELETE", srv.URL+"/organizations/acme/users/dave", ""); resp.StatusCode != 200 {
		t.Fatalf("remove former admin = %d, want 200: %s", resp.StatusCode, body)
	}
}

// Membership of admins counts through a nested group too, as erchef resolves
// it through authz.
func TestDisassociateNestedAdminRefused(t *testing.T) {
	srv, _ := newTestAPI(t)
	do(t, "POST", srv.URL+"/users", `{"name":"dave"}`)
	do(t, "POST", srv.URL+"/organizations/acme/users", `{"username":"dave"}`)
	do(t, "POST", srv.URL+"/organizations/acme/groups",
		`{"groupname":"ops","actors":{"users":["dave"],"clients":[],"groups":[]}}`)
	do(t, "POST", srv.URL+"/organizations/acme/groups",
		`{"groupname":"admins","actors":{"users":[],"clients":[],"groups":["ops"]}}`)
	if resp, body := do(t, "DELETE", srv.URL+"/organizations/acme/users/dave", ""); resp.StatusCode != 403 {
		t.Fatalf("remove nested admin = %d, want 403: %s", resp.StatusCode, body)
	}
}
