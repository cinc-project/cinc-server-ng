package server

import (
	"net/http"
	"testing"
)

// ACLs match actors by bare name and resolveAuth prefers an org client over a
// global user on any org-scoped path. A client named after a user therefore
// inherits every grant naming that user — and displaces them entirely, since
// their signature is then checked against the client's key. Anyone holding an
// org validator key can create clients, and validator keys are distributed to
// every node, so the collision must be refused at creation.
func TestClientCannotShadowGlobalUser(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	admin := srv.AdminName()
	vkey := srv.ValidatorKey("acme")

	// The admin creates a node; writeCreatorACL grants the admin full control.
	if code := statusOf(t, signed(t, srv, "POST", acme+"/nodes", `{"name":"secret01"}`)); code != 201 {
		t.Fatalf("admin create node = %d, want 201", code)
	}

	code := statusOf(t, signedAs(t, "acme-validator", vkey, "POST", acme+"/clients",
		`{"name":"`+admin+`"}`))
	if code != http.StatusConflict {
		t.Fatalf("create client named %q = %d, want 409", admin, code)
	}

	// The real admin still reaches the org.
	if code := statusOf(t, signed(t, srv, "GET", acme+"/nodes/secret01", "")); code != http.StatusOK {
		t.Errorf("admin read node = %d, want 200", code)
	}
}

// The reverse collision is refused too: a user created after a client of that
// name would be shadowed by it on every org path.
func TestUserCannotShadowOrgClient(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"

	if code := statusOf(t, signed(t, srv, "POST", acme+"/clients", `{"name":"node1"}`)); code != 201 {
		t.Fatalf("create client = %d, want 201", code)
	}
	if code := statusOf(t, signed(t, srv, "POST", srv.URL()+"/users", `{"name":"node1"}`)); code != http.StatusConflict {
		t.Errorf("create user colliding with a client = %d, want 409", code)
	}
}

// Names that do not collide are unaffected, and the same name may be reused as
// a client in two different organizations — clients are org-scoped, so those
// two never resolve on the same path.
func TestNonCollidingActorNamesStillCreate(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme", "beta"}, EnforceACL: true})

	if code := statusOf(t, signed(t, srv, "POST", srv.URL()+"/users", `{"name":"alice"}`)); code != 201 {
		t.Errorf("create user = %d, want 201", code)
	}
	for _, org := range []string{"acme", "beta"} {
		code := statusOf(t, signed(t, srv, "POST",
			srv.URL()+"/organizations/"+org+"/clients", `{"name":"node1"}`))
		if code != 201 {
			t.Errorf("create client in %s = %d, want 201", org, code)
		}
	}
}
