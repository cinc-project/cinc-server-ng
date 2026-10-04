package server

import "testing"

// Chef Infra Server ignores a trailing slash when routing (webmachine splits
// the path into tokens), and real clients send one: knife user create posts to
// "/users/". The slash has to be gone before authorization classifies the
// request, or "/nodes/web01/" would be an unrecognized read, which is allowed
// through, and then route to the node.
func TestTrailingSlashRoutesAndStaysAuthorized(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	const validator = "acme-validator"
	vkey := srv.ValidatorKey("acme")

	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes/", `{"name":"web01"}`)); code != 201 {
		t.Fatalf("admin create node with trailing slash = %d, want 201", code)
	}
	if code := statusOf(t, signed(t, srv, "GET", base+"/nodes/web01/", "")); code != 200 {
		t.Fatalf("admin read node with trailing slash = %d, want 200", code)
	}

	// Baseline: the validator may not read the node...
	if code := statusOf(t, signedAs(t, validator, vkey, "GET", base+"/nodes/web01", "")); code != 403 {
		t.Fatalf("validator read node = %d, want 403", code)
	}
	// ...and a trailing slash must not change that.
	if code := statusOf(t, signedAs(t, validator, vkey, "GET", base+"/nodes/web01/", "")); code != 403 {
		t.Fatalf("validator read node with trailing slash = %d, want 403", code)
	}

	// The file store is authorized by the pre-signed grant in its URL, not by
	// a Mixlib signature: a trailing slash must still be treated as a file
	// store request, so a signed request without a grant cannot fetch a blob.
	const sum = "0123456789abcdef0123456789abcdef"
	if code := statusOf(t, signed(t, srv, "GET", base+"/file_store/"+sum+"/", "")); code != 401 {
		t.Fatalf("signed file store read without a grant, trailing slash = %d, want 401", code)
	}

	if code := statusOf(t, signed(t, srv, "POST", srv.URL()+"/users/", validUserBody(t, `{"name":"bob"}`))); code != 201 {
		t.Fatalf("admin create user at /users/ = %d, want 201", code)
	}
}
