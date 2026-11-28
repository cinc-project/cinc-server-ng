package server

import (
	"net/http"
	"strings"
	"testing"
)

// sameButForPath reports whether two responses are the same once the path
// each one echoes back (the router's 404 and 405 name it) is set aside.
func sameButForPath(present, missing []byte, presentPath, missingPath string) bool {
	return strings.ReplaceAll(string(missing), missingPath, presentPath) == string(present)
}

// webmachine decides 404 and 405 before is_authorized, and the org membership
// gate follows it by letting an unrouted request through to the router. The
// authorization that follows must do the same: if it classified the request
// anyway, its existence check would tell a user outside the org which objects
// exist (a 404 for a missing one, a 403 for one that is there).
func TestUnroutedRequestsDoNotRevealExistenceToNonMembers(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	key := []byte(createUser(t, srv, `{"name":"outsider"}`))
	mustStatus(t, signed(t, srv, "POST", acme+"/nodes", `{"name":"web01"}`), http.StatusCreated)

	// Baseline: on a routed path the outsider is refused whether or not the
	// node exists.
	wantNotAssociated(t, "outsider GET node _acl", signedAs(t, "outsider", key, "GET", acme+"/nodes/web01/_acl", ""), "outsider")
	wantNotAssociated(t, "outsider GET missing node _acl", signedAs(t, "outsider", key, "GET", acme+"/nodes/ghost/_acl", ""), "outsider")

	for _, tc := range []struct {
		method, present, missing, body string
		want                           int
	}{
		{"POST", "/nodes/web01/_acl", "/nodes/ghost/_acl", "{}", http.StatusMethodNotAllowed},
		{"GET", "/nodes/web01/_acl/read/extra", "/nodes/ghost/_acl/read/extra", "", http.StatusNotFound},
		{"PUT", "/containers/nodes", "/containers/ghost", `{"containername":"x"}`, http.StatusMethodNotAllowed},
	} {
		pc, pb := signedBody(t, signedAs(t, "outsider", key, tc.method, acme+tc.present, tc.body))
		mc, mb := signedBody(t, signedAs(t, "outsider", key, tc.method, acme+tc.missing, tc.body))
		if pc != tc.want || mc != tc.want || !sameButForPath(pb, mb, tc.present, tc.missing) {
			t.Errorf("outsider %s %s = %d %s, %s = %d %s; want %d for both, same body",
				tc.method, tc.present, pc, pb, tc.missing, mc, mb, tc.want)
		}
	}
}

// An object may be named "_acl". Its routes are its own, and must be
// authorized like any other object's rather than read as an ACL endpoint
// that does not match and so is waved through unchecked.
func TestObjectNamedACLIsAuthorized(t *testing.T) {
	srv, base, bob := memberSetup(t)
	mustStatus(t, signed(t, srv, "POST", base+"/nodes", `{"name":"_acl"}`), http.StatusCreated)
	mustStatus(t, signed(t, srv, "POST", base+"/nodes", `{"name":"plain"}`), http.StatusCreated)
	mustStatus(t, signed(t, srv, "POST", base+"/data", `{"name":"_acl"}`), http.StatusCreated)
	mustStatus(t, signed(t, srv, "POST", base+"/data/_acl", `{"id":"secret"}`), http.StatusCreated)
	mustStatus(t, signed(t, srv, "PUT", base+"/cookbooks/_acl/1.0.0", cookbook("_acl", "1.0.0")), http.StatusCreated)
	for _, obj := range []string{"nodes/_acl", "nodes/plain", "data/_acl", "cookbooks/_acl"} {
		narrowRead(t, srv, base, obj)
	}

	// Baseline: bob, a plain member, is refused a node whose read is narrowed,
	// and the superuser reads every object named "_acl".
	if code := statusOf(t, signedAs(t, "bob", bob, "GET", base+"/nodes/plain", "")); code != http.StatusForbidden {
		t.Fatalf("bob GET narrowed node = %d, want 403", code)
	}
	for _, path := range []string{"/nodes/_acl", "/nodes/_acl/_acl", "/data/_acl", "/data/_acl/secret",
		"/cookbooks/_acl", "/cookbooks/_acl/1.0.0"} {
		if code := statusOf(t, signed(t, srv, "GET", base+path, "")); code != http.StatusOK {
			t.Fatalf("superuser GET %s = %d, want 200", path, code)
		}
	}

	for _, path := range []string{
		"/nodes/_acl",
		"/nodes/_acl/_acl",
		"/nodes/_acl/_acl/read",
		"/data/_acl",
		"/data/_acl/secret",
		"/cookbooks/_acl/1.0.0",
	} {
		if code := statusOf(t, signedAs(t, "bob", bob, "GET", base+path, "")); code != http.StatusForbidden {
			t.Errorf("bob GET %s = %d, want 403", path, code)
		}
	}
}

// Only the object types with ACL routes have an _acl endpoint. A path naming
// some other store collection before /_acl matches no route and must get the
// router's 404 whether or not a record by that name exists.
func TestACLPathOnNonACLTypeIsNotAnExistenceOracle(t *testing.T) {
	srv, base, bob := memberSetup(t)
	mustStatus(t, signed(t, srv, "POST", base+"/data", `{"name":"secrets"}`), http.StatusCreated)
	mustStatus(t, signed(t, srv, "POST", base+"/data/secrets", `{"id":"pw"}`), http.StatusCreated)
	narrowRead(t, srv, base, "data/secrets")
	mustStatus(t, signed(t, srv, "POST", base+"/clients", `{"name":"node1"}`), http.StatusCreated)

	// Baseline: bob cannot read the bag's items.
	if code := statusOf(t, signedAs(t, "bob", bob, "GET", base+"/data/secrets/pw", "")); code != http.StatusForbidden {
		t.Fatalf("bob GET narrowed item = %d, want 403", code)
	}

	for _, pair := range [][2]string{
		{"/databag_items:secrets/pw/_acl", "/databag_items:secrets/ghost/_acl"},
		{"/clients_keys:node1/default/_acl", "/clients_keys:node1/ghost/_acl"},
		{"/databag_items:secrets/pw/_acl/read", "/databag_items:secrets/ghost/_acl/read"},
	} {
		pc, pb := signedBody(t, signedAs(t, "bob", bob, "GET", base+pair[0], ""))
		mc, mb := signedBody(t, signedAs(t, "bob", bob, "GET", base+pair[1], ""))
		if pc != http.StatusNotFound || mc != http.StatusNotFound || !sameButForPath(pb, mb, pair[0], pair[1]) {
			t.Errorf("bob GET %s = %d %s, %s = %d %s; want 404 for both, same body",
				pair[0], pc, pb, pair[1], mc, mb)
		}
	}
}
