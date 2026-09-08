package server

import (
	"net/http"
	"testing"
)

// Pending invitations name who an organization is trying to recruit, and which
// organizations are courting a given user. classifyOrgMembership leaves the read
// routes to the handler's own membership check — so the handlers have to make
// one.
func TestInvitationListingsRequireStanding(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	createUser(t, srv, `{"name":"frank"}`)
	outsider := []byte(createUser(t, srv, `{"name":"outsider"}`))

	if code := statusOf(t, signed(t, srv, "POST", acme+"/association_requests", `{"user":"frank"}`)); code != 201 {
		t.Fatalf("invite = %d, want 201", code)
	}

	for _, c := range []struct{ what, path string }{
		{"org invitations", acme + "/association_requests"},
		{"another user's invitations", srv.URL() + "/users/frank/association_requests"},
		{"another user's invitation count", srv.URL() + "/users/frank/association_requests/count"},
	} {
		if code := statusOf(t, signedAs(t, "outsider", outsider, "GET", c.path, "")); code != http.StatusForbidden {
			t.Errorf("outsider reads %s = %d, want 403", c.what, code)
		}
	}
}

// The people who legitimately need these listings still get them: the invited
// user sees their own, an org member sees the org's, and the superuser sees both.
func TestInvitationListingsAllowedForStanding(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	frank := []byte(createUser(t, srv, `{"name":"frank"}`))
	member := []byte(createUser(t, srv, `{"name":"grace"}`))

	if code := statusOf(t, signed(t, srv, "POST", acme+"/users", `{"username":"grace"}`)); code != 201 {
		t.Fatalf("associate grace = %d, want 201", code)
	}
	if code := statusOf(t, signed(t, srv, "POST", acme+"/association_requests", `{"user":"frank"}`)); code != 201 {
		t.Fatalf("invite = %d, want 201", code)
	}

	cases := []struct {
		what, actor, path string
		key               []byte
	}{
		{"invitee reads own invitations", "frank", srv.URL() + "/users/frank/association_requests", frank},
		{"invitee reads own count", "frank", srv.URL() + "/users/frank/association_requests/count", frank},
		{"member reads org invitations", "grace", acme + "/association_requests", member},
	}
	for _, c := range cases {
		if code := statusOf(t, signedAs(t, c.actor, c.key, "GET", c.path, "")); code != http.StatusOK {
			t.Errorf("%s = %d, want 200", c.what, code)
		}
	}
	// The superuser reaches both.
	for _, path := range []string{
		acme + "/association_requests",
		srv.URL() + "/users/frank/association_requests",
	} {
		if code := statusOf(t, signed(t, srv, "GET", path, "")); code != http.StatusOK {
			t.Errorf("superuser reads %s = %d, want 200", path, code)
		}
	}
}
