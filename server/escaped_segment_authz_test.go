package server

import (
	"net/http"
	"testing"
)

// A percent-encoded slash inside a path segment is one segment to the router
// (http.ServeMux matches the escaped path and unescapes each wildcard), so
// /nodes/sec%2Fret reaches the node named "sec/ret". Authorization must split
// the path the same way: splitting the decoded path instead saw
// /nodes/sec/ret, an unknown sub-resource, and let the read through
// unclassified. No name erchef accepts contains a "/", but a store written
// before names were validated may hold one, and its ACL must still protect it.

// plantLegacy writes an object straight into the store under coll/key, with a
// copy of the ACL stored for aclFrom, as a store from before name validation
// could hold it.
func plantLegacy(t *testing.T, srv *Server, coll, key, doc, aclFrom, aclTo string) {
	t.Helper()
	org, _, err := srv.Store().Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := org.Put(coll, key, []byte(doc)); err != nil {
		t.Fatal(err)
	}
	acl, ok, err := org.Get("acls", aclFrom)
	if err != nil || !ok {
		t.Fatalf("read ACL %s: ok=%v err=%v", aclFrom, ok, err)
	}
	if err := org.Put("acls", aclTo, acl); err != nil {
		t.Fatal(err)
	}
}

func TestEscapedSlashNodeIsProtectedByItsACL(t *testing.T) {
	srv, base, bob := memberSetup(t)
	mustStatus(t, signed(t, srv, "POST", base+"/nodes", `{"name":"plain"}`), http.StatusCreated)
	restrictRead(t, srv, base+"/nodes/plain/_acl/read")
	// Baseline: the restricted ACL denies bob a node with an ordinary name.
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/nodes/plain", ""), http.StatusForbidden)

	plantLegacy(t, srv, "nodes", "sec/ret", `{"name":"sec/ret","json_class":"Chef::Node","chef_type":"node"}`,
		"nodes/plain", "nodes/sec/ret")

	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/nodes/sec%2Fret", ""), http.StatusForbidden)
	mustStatus(t, signedAs(t, "bob", bob, "HEAD", base+"/nodes/sec%2Fret", ""), http.StatusForbidden)
	// An actor the ACL grants still reaches it.
	mustStatus(t, signed(t, srv, "GET", base+"/nodes/sec%2Fret", ""), http.StatusOK)
}

// TestEscapedDotDotNodeIsProtectedByItsACL: ".." is a valid node name, and
// /nodes/%2E%2E reaches it (the router cleans a literal "..", not an escaped
// one), so it is authorized against that node's ACL.
func TestEscapedDotDotNodeIsProtectedByItsACL(t *testing.T) {
	srv, base, bob := memberSetup(t)
	mustStatus(t, signed(t, srv, "POST", base+"/nodes", `{"name":".."}`), http.StatusCreated)
	restrictRead(t, srv, base+"/nodes/%2E%2E/_acl/read")
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/nodes/%2E%2E", ""), http.StatusForbidden)
	mustStatus(t, signed(t, srv, "GET", base+"/nodes/%2E%2E", ""), http.StatusOK)
}

func TestEscapedSlashDataBagItemIsProtectedByItsBag(t *testing.T) {
	srv, base, bob := memberSetup(t)
	mustStatus(t, signed(t, srv, "POST", base+"/data", `{"name":"secrets"}`), http.StatusCreated)
	mustStatus(t, signed(t, srv, "POST", base+"/data/secrets", `{"id":"plain"}`), http.StatusCreated)
	restrictRead(t, srv, base+"/data/secrets/_acl/read")
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/data/secrets/plain", ""), http.StatusForbidden)

	org, _, err := srv.Store().Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := org.Put("databag_items:secrets", "it/em", []byte(`{"id":"it/em"}`)); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/data/secrets/it%2Fem", ""), http.StatusForbidden)
	mustStatus(t, signed(t, srv, "GET", base+"/data/secrets/it%2Fem", ""), http.StatusOK)
}

// TestEscapedSlashNodeRefusesNonMember: the org membership gate splits the
// path as the router does too, so a user outside the org is refused an
// object addressed with an encoded slash, as for any other org route.
func TestEscapedSlashNodeRefusesNonMember(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	outKey := []byte(createUser(t, srv, `{"name":"outsider"}`))
	mustStatus(t, signed(t, srv, "POST", base+"/nodes", `{"name":"plain"}`), http.StatusCreated)
	plantLegacy(t, srv, "nodes", "sec/ret", `{"name":"sec/ret","json_class":"Chef::Node","chef_type":"node"}`,
		"nodes/plain", "nodes/sec/ret")

	wantNotAssociated(t, "outsider GET node plain", signedAs(t, "outsider", outKey, "GET", base+"/nodes/plain", ""), "outsider")
	wantNotAssociated(t, "outsider GET node sec/ret", signedAs(t, "outsider", outKey, "GET", base+"/nodes/sec%2Fret", ""), "outsider")
}
