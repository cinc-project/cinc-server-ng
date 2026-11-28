package server

import (
	"net/http"
	"testing"
)

// GET /users/{user}/organizations lists the orgs a user belongs to. As erchef
// serves it from the named-user resource, it is gated like GET /users/{user}:
// the user itself or the superuser, not any authenticated caller.
func TestUserOrganizationsIsSelfOrSuperuser(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	aliceKey := createUserKey(t, srv, "alice")
	malloryKey := createUserKey(t, srv, "mallory")
	url := srv.URL() + "/users/alice/organizations"

	// Baseline: mallory cannot read alice's record.
	if code := statusOf(t, signedAs(t, "mallory", malloryKey, "GET", srv.URL()+"/users/alice", "")); code != http.StatusForbidden {
		t.Fatalf("mallory GET /users/alice = %d, want 403", code)
	}
	if code := statusOf(t, signedAs(t, "mallory", malloryKey, "GET", url, "")); code != http.StatusForbidden {
		t.Errorf("mallory GET /users/alice/organizations = %d, want 403", code)
	}
	if code := statusOf(t, signedAs(t, "alice", aliceKey, "GET", url, "")); code != http.StatusOK {
		t.Errorf("alice GET own organizations = %d, want 200", code)
	}
	if code := statusOf(t, signed(t, srv, "GET", url, "")); code != http.StatusOK {
		t.Errorf("superuser GET /users/alice/organizations = %d, want 200", code)
	}
}
