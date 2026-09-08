package server

import (
	"net/http"
	"testing"
)

// Deleting an organization wipes every object and blob it holds, and no ACL is
// ever stored for the organization object — so the check falls back to
// defaultACL(), which grants update and delete to the org's "users" group. That
// hands the whole org to any member. Creating one is already superuser-only;
// destroying one must be too.
func TestOrgUpdateAndDeleteRequireSuperuser(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	key := []byte(createUser(t, srv, `{"name":"carol"}`))

	if code := statusOf(t, signed(t, srv, "POST", acme+"/users", `{"username":"carol"}`)); code != 201 {
		t.Fatalf("associate carol = %d, want 201", code)
	}

	// An ordinary member may still read the org's metadata.
	if code := statusOf(t, signedAs(t, "carol", key, "GET", acme, "")); code != http.StatusOK {
		t.Errorf("member GET org = %d, want 200", code)
	}
	if code := statusOf(t, signedAs(t, "carol", key, "PUT", acme, `{"full_name":"pwned"}`)); code != http.StatusForbidden {
		t.Errorf("member PUT org = %d, want 403", code)
	}
	if code := statusOf(t, signedAs(t, "carol", key, "DELETE", acme, "")); code != http.StatusForbidden {
		t.Errorf("member DELETE org = %d, want 403", code)
	}
	// The org survived.
	if code := statusOf(t, signed(t, srv, "GET", acme, "")); code != http.StatusOK {
		t.Errorf("org GET after denied delete = %d, want 200", code)
	}
}

// The superuser retains the full organization lifecycle.
func TestSuperuserRetainsOrgLifecycle(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"

	if code := statusOf(t, signed(t, srv, "PUT", acme, `{"full_name":"Acme, Inc."}`)); code != http.StatusOK {
		t.Errorf("superuser PUT org = %d, want 200", code)
	}
	if code := statusOf(t, signed(t, srv, "DELETE", acme, "")); code != http.StatusOK {
		t.Errorf("superuser DELETE org = %d, want 200", code)
	}
	if code := statusOf(t, signed(t, srv, "GET", acme, "")); code != http.StatusNotFound {
		t.Errorf("GET deleted org = %d, want 404", code)
	}
}
