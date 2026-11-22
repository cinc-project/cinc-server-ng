package server

import (
	"net/http"
	"strings"
	"testing"
)

// erchef refuses any org-scoped request from a user who is not associated
// with the org before it looks at an ACL (oc_chef_wm_base:is_authorized →
// authorized_by_org_membership_check). Clients belong to their org and the
// superuser bypasses it. It exists because removing a user from an org leaves
// ACL entries naming the user behind; these tests pin that ACL entries and
// group membership grant nothing to a user outside the org.

// notAssociated is erchef's forbidden_message(not_member_of_org, ...).
func notAssociated(user, org string) string {
	return `{"error":["'` + user + `' not associated with organization '` + org + `'"]}`
}

func wantNotAssociated(t *testing.T, what string, req *http.Request, user string) {
	t.Helper()
	code, body := signedBody(t, req)
	if code != http.StatusForbidden || strings.TrimSpace(string(body)) != notAssociated(user, "acme") {
		t.Errorf("%s = %d %s, want 403 %s", what, code, body, notAssociated(user, "acme"))
	}
}

// A removed member keeps the creator entries on objects it made. erchef's
// membership check is what stops those from granting anything.
func TestRemovedMemberLosesAccessToOwnObjects(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	key := []byte(createUser(t, srv, `{"name":"bob"}`))
	if code := statusOf(t, signed(t, srv, "POST", acme+"/users", `{"username":"bob"}`)); code != http.StatusCreated {
		t.Fatalf("associate bob = %d", code)
	}
	if code := statusOf(t, signedAs(t, "bob", key, "POST", acme+"/nodes", `{"name":"bobs"}`)); code != http.StatusCreated {
		t.Fatalf("bob creates node = %d", code)
	}
	// Baseline: as a member, bob owns the node, _acl included.
	for _, url := range []string{acme + "/nodes/bobs", acme + "/nodes/bobs/_acl"} {
		if code := statusOf(t, signedAs(t, "bob", key, "GET", url, "")); code != http.StatusOK {
			t.Fatalf("member GET %s = %d, want 200", url, code)
		}
	}

	if code := statusOf(t, signed(t, srv, "DELETE", acme+"/users/bob", "")); code != http.StatusOK {
		t.Fatalf("disassociate bob = %d", code)
	}

	wantNotAssociated(t, "ex-member GET own node", signedAs(t, "bob", key, "GET", acme+"/nodes/bobs", ""), "bob")
	wantNotAssociated(t, "ex-member PUT own node", signedAs(t, "bob", key, "PUT", acme+"/nodes/bobs", `{"name":"bobs","pwned":true}`), "bob")
	wantNotAssociated(t, "ex-member GET own node _acl", signedAs(t, "bob", key, "GET", acme+"/nodes/bobs/_acl", ""), "bob")
	wantNotAssociated(t, "ex-member PUT own node _acl", signedAs(t, "bob", key, "PUT", acme+"/nodes/bobs/_acl/read",
		`{"read":{"actors":["bob"],"groups":[]}}`), "bob")
	wantNotAssociated(t, "ex-member DELETE own node", signedAs(t, "bob", key, "DELETE", acme+"/nodes/bobs", ""), "bob")

	// The node is untouched.
	if code := statusOf(t, signed(t, srv, "GET", acme+"/nodes/bobs", "")); code != http.StatusOK {
		t.Errorf("superuser GET node after the refused DELETE = %d, want 200", code)
	}
}

// A user who was never associated gets nothing from being named in a group,
// even the admins group.
func TestNonMemberInAdminsGroupIsRefused(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	bossKey := []byte(createUser(t, srv, `{"name":"boss"}`))
	malKey := []byte(createUser(t, srv, `{"name":"mallory"}`))
	if code := statusOf(t, signed(t, srv, "POST", acme+"/users", `{"username":"boss"}`)); code != http.StatusCreated {
		t.Fatalf("associate boss = %d", code)
	}
	if code := statusOf(t, signed(t, srv, "PUT", acme+"/groups/admins",
		`{"groupname":"admins","actors":{"users":["pivotal","boss"],"clients":[],"groups":[]}}`)); code != http.StatusOK {
		t.Fatalf("add boss to admins = %d", code)
	}
	// Baseline: mallory is refused before anything names her.
	wantNotAssociated(t, "outsider GET nodes", signedAs(t, "mallory", malKey, "GET", acme+"/nodes", ""), "mallory")

	if code, body := signedBody(t, signedAs(t, "boss", bossKey, "PUT", acme+"/groups/admins",
		`{"groupname":"admins","actors":{"users":["pivotal","boss","mallory"],"clients":[],"groups":[]}}`)); code != http.StatusOK {
		t.Fatalf("org admin adds mallory to admins = %d: %s", code, body)
	}

	wantNotAssociated(t, "outsider in admins GET nodes", signedAs(t, "mallory", malKey, "GET", acme+"/nodes", ""), "mallory")
	wantNotAssociated(t, "outsider in admins POST nodes", signedAs(t, "mallory", malKey, "POST", acme+"/nodes", `{"name":"x"}`), "mallory")
	wantNotAssociated(t, "outsider in admins GET org _acl", signedAs(t, "mallory", malKey, "GET", acme+"/organizations/_acl", ""), "mallory")
}

// The gate covers routes classifyRequest does not, and the org itself.
func TestNonMemberRefusedOnUnclassifiedReads(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	memberKey := []byte(createUser(t, srv, `{"name":"member"}`))
	outKey := []byte(createUser(t, srv, `{"name":"outsider"}`))
	if code := statusOf(t, signed(t, srv, "POST", acme+"/users", `{"username":"member"}`)); code != http.StatusCreated {
		t.Fatalf("associate member = %d", code)
	}
	for _, path := range []string{
		"/environments/_default/nodes",
		"/environments/_default/cookbooks",
		"/search",
		"/search/node",
		"/universe",
		"",
		"/users",
		"/association_requests",
	} {
		if code := statusOf(t, signedAs(t, "member", memberKey, "GET", acme+path, "")); code != http.StatusOK {
			t.Errorf("member GET %q = %d, want 200", path, code)
		}
		wantNotAssociated(t, "outsider GET "+path, signedAs(t, "outsider", outKey, "GET", acme+path, ""), "outsider")
	}
	// is_authorized precedes resource_exists in webmachine: a non-member learns
	// nothing about which objects exist.
	if code := statusOf(t, signedAs(t, "member", memberKey, "GET", acme+"/nodes/ghost", "")); code != http.StatusNotFound {
		t.Errorf("member GET missing node = %d, want 404", code)
	}
	wantNotAssociated(t, "outsider GET missing node", signedAs(t, "outsider", outKey, "GET", acme+"/nodes/ghost", ""), "outsider")
}

// The superuser bypasses the check; clients are members of their org by
// definition. A client sharing a user's name doesn't make the user a member.
func TestMembershipGateExemptsSuperuserAndClients(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	if code := statusOf(t, signed(t, srv, "GET", acme+"/environments/_default/nodes", "")); code != http.StatusOK {
		t.Errorf("superuser (not associated) GET = %d, want 200", code)
	}

	userKey := []byte(createUser(t, srv, `{"name":"carol"}`))
	clientKey := createdClientKey(t, srv, acme, "carol")
	if code := statusOf(t, signedAs(t, "carol", clientKey, "GET", acme+"/nodes", "")); code != http.StatusOK {
		t.Errorf("client GET nodes = %d, want 200", code)
	}
	if code := statusOf(t, signedAs(t, "carol", clientKey, "POST", acme+"/nodes", `{"name":"carol"}`)); code != http.StatusCreated {
		t.Errorf("client POST node = %d, want 201", code)
	}
	wantNotAssociated(t, "user named like a client GET nodes", signedAs(t, "carol", userKey, "GET", acme+"/nodes", ""), "carol")
}

// The webui acts as the user it names, so an impersonated non-member is
// refused like the user itself, while the impersonated superuser bypasses.
func TestMembershipGateAppliesToWebUIImpersonation(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	createUser(t, srv, `{"name":"outsider"}`)
	wantNotAssociated(t, "webui as outsider GET nodes", webuiSignedAs(t, srv, "outsider", "GET", acme+"/nodes", ""), "outsider")
	if code := statusOf(t, webuiSignedAs(t, srv, "pivotal", "GET", acme+"/nodes", "")); code != http.StatusOK {
		t.Errorf("webui as superuser GET nodes = %d, want 200", code)
	}
}

// Routes erchef answers without is_authorized keep answering a non-member:
// principals (chef_wm_named_principal has no is_authorized) and required_recipe
// (served by nginx). /users/... routes carry no org, so an invitee accepts an
// invitation before it is a member. A path no route matches stays 404, and a
// wrong method 405, as webmachine decides both before is_authorized.
func TestMembershipGateExemptions(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	key := []byte(createUser(t, srv, `{"name":"invitee"}`))

	if code := statusOf(t, signedAs(t, "invitee", key, "GET", acme+"/principals/invitee", "")); code != http.StatusOK {
		t.Errorf("non-member GET principal = %d, want 200", code)
	}
	if code := statusOf(t, signedAs(t, "invitee", key, "GET", acme+"/required_recipe", "")); code != http.StatusNotFound {
		t.Errorf("non-member GET required_recipe = %d, want 404", code)
	}
	if code := statusOf(t, signedAs(t, "invitee", key, "GET", acme+"/no_such_endpoint", "")); code != http.StatusNotFound {
		t.Errorf("non-member GET unrouted path = %d, want 404", code)
	}
	if code := statusOf(t, signedAs(t, "invitee", key, "PATCH", acme+"/nodes", "{}")); code != http.StatusMethodNotAllowed {
		t.Errorf("non-member PATCH nodes = %d, want 405", code)
	}

	if code := statusOf(t, signed(t, srv, "POST", acme+"/association_requests", `{"user":"invitee"}`)); code != http.StatusCreated {
		t.Fatalf("invite = %d", code)
	}
	wantNotAssociated(t, "invitee GET nodes before accepting", signedAs(t, "invitee", key, "GET", acme+"/nodes", ""), "invitee")
	if code := statusOf(t, signedAs(t, "invitee", key, "GET", srv.URL()+"/users/invitee/association_requests", "")); code != http.StatusOK {
		t.Errorf("invitee lists own invitations = %d, want 200", code)
	}
	if code := statusOf(t, signedAs(t, "invitee", key, "PUT", srv.URL()+"/users/invitee/association_requests/invitee-acme",
		`{"response":"accept"}`)); code != http.StatusOK {
		t.Fatalf("invitee accepts = %d, want 200", code)
	}
	if code := statusOf(t, signedAs(t, "invitee", key, "GET", acme+"/nodes", "")); code != http.StatusOK {
		t.Errorf("new member GET nodes = %d, want 200", code)
	}
}
