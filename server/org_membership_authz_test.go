package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

// orgMembershipFixture is an enforcing server whose acme org has a plain
// member ("member"), a second plain member ("other"), an org admin ("boss", in
// the admins group), a user who belongs to no org ("outsider"), and a pending
// invitation for "invitee". Everything is set up by the superuser.
type orgMembershipFixture struct {
	srv                   *Server
	acme                  string
	memberKey, bossKey    []byte
	otherKey, outsiderKey []byte
}

func newOrgMembershipFixture(t *testing.T) orgMembershipFixture {
	t.Helper()
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	acme := srv.URL() + "/organizations/acme"
	f := orgMembershipFixture{
		srv:         srv,
		acme:        acme,
		memberKey:   []byte(createUser(t, srv, `{"name":"member"}`)),
		otherKey:    []byte(createUser(t, srv, `{"name":"other"}`)),
		bossKey:     []byte(createUser(t, srv, `{"name":"boss"}`)),
		outsiderKey: []byte(createUser(t, srv, `{"name":"outsider"}`)),
	}
	createUser(t, srv, `{"name":"invitee"}`)
	for _, u := range []string{"member", "other", "boss"} {
		if code := statusOf(t, signed(t, srv, "POST", acme+"/users", `{"username":"`+u+`"}`)); code != http.StatusCreated {
			t.Fatalf("superuser associates %s = %d, want 201", u, code)
		}
	}
	if code := statusOf(t, signed(t, srv, "PUT", acme+"/groups/admins",
		`{"groupname":"admins","actors":{"users":["boss"],"clients":[],"groups":[]}}`)); code != http.StatusOK {
		t.Fatalf("superuser adds boss to admins = %d, want 200", code)
	}
	if code := statusOf(t, signed(t, srv, "POST", acme+"/association_requests", `{"user":"invitee"}`)); code != http.StatusCreated {
		t.Fatalf("superuser invites invitee = %d, want 201", code)
	}
	return f
}

func (f orgMembershipFixture) as(t *testing.T, name string, key []byte, method, url, body string) int {
	t.Helper()
	return statusOf(t, signedAs(t, name, key, method, url, body))
}

// A plain org member is refused every membership change erchef reserves to the
// superuser or to holders of update on the organization: force-adding a user,
// removing another member, inviting, and rescinding an invitation.
func TestEnforceACLPlainMemberCannotManageMembership(t *testing.T) {
	f := newOrgMembershipFixture(t)

	// Baseline: the member is in the org and can read its membership, so a 403
	// below is the membership gate, not a failure to authenticate.
	if code := f.as(t, "member", f.memberKey, "GET", f.acme+"/users", ""); code != http.StatusOK {
		t.Fatalf("member lists org users = %d, want 200", code)
	}

	cases := []struct{ what, method, url, body string }{
		{"force-adds a user", "POST", f.acme + "/users", `{"username":"outsider"}`},
		{"removes another member", "DELETE", f.acme + "/users/other", ""},
		{"invites a user", "POST", f.acme + "/association_requests", `{"user":"outsider"}`},
		{"rescinds an invitation", "DELETE", f.acme + "/association_requests/invitee-acme", ""},
	}
	for _, c := range cases {
		if code := f.as(t, "member", f.memberKey, c.method, c.url, c.body); code != http.StatusForbidden {
			t.Errorf("member %s = %d, want 403", c.what, code)
		}
	}

	// Nothing changed.
	if code := statusOf(t, signed(t, f.srv, "GET", f.acme+"/users/outsider", "")); code != http.StatusNotFound {
		t.Errorf("outsider membership after refused add = %d, want 404", code)
	}
	if code := statusOf(t, signed(t, f.srv, "GET", f.acme+"/users/other", "")); code != http.StatusOK {
		t.Errorf("other membership after refused removal = %d, want 200", code)
	}
	if code := statusOf(t, signed(t, f.srv, "GET", f.srv.URL()+"/users/invitee/association_requests/count", "")); code != http.StatusOK {
		t.Errorf("invitee invitation count = %d, want 200", code)
	}
	resp, err := http.DefaultClient.Do(signed(t, f.srv, "GET", f.acme+"/association_requests", ""))
	if err != nil {
		t.Fatal(err)
	}
	var invites []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&invites); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(invites) != 1 || invites[0]["username"] != "invitee" {
		t.Errorf("invitations after refused invite and rescind = %v, want only invitee's", invites)
	}
}

// Denying the membership routes is worthless if a plain member can simply write
// themselves into admins, or an outsider into users, first. erchef gives the
// users group no permission on the default groups at all.
func TestEnforceACLPlainMemberCannotRewriteDefaultGroups(t *testing.T) {
	f := newOrgMembershipFixture(t)

	for _, c := range []struct{ group, body string }{
		{"admins", `{"groupname":"admins","actors":{"users":["boss","member"],"clients":[],"groups":[]}}`},
		{"users", `{"groupname":"users","actors":{"users":["member","other","boss","outsider"],"clients":[],"groups":[]}}`},
		{"clients", `{"groupname":"clients","actors":{"users":["member"],"clients":[],"groups":[]}}`},
		{"billing-admins", `{"groupname":"billing-admins","actors":{"users":["member"],"clients":[],"groups":[]}}`},
	} {
		if code := f.as(t, "member", f.memberKey, "PUT", f.acme+"/groups/"+c.group, c.body); code != http.StatusForbidden {
			t.Errorf("member rewrites %s = %d, want 403", c.group, code)
		}
		if code := f.as(t, "member", f.memberKey, "DELETE", f.acme+"/groups/"+c.group, ""); code != http.StatusForbidden {
			t.Errorf("member deletes %s = %d, want 403", c.group, code)
		}
	}
	// With admins intact, the member is still refused an invitation.
	if code := f.as(t, "member", f.memberKey, "POST", f.acme+"/association_requests", `{"user":"outsider"}`); code != http.StatusForbidden {
		t.Errorf("member invites after refused group rewrite = %d, want 403", code)
	}
	// Members can still read the groups they are governed by.
	if code := f.as(t, "member", f.memberKey, "GET", f.acme+"/groups/users", ""); code != http.StatusOK {
		t.Errorf("member reads users group = %d, want 200", code)
	}
}

// An org admin (in the admins group, so holding update on the organization)
// may invite, rescind and remove members, but force-adding a user without an
// invitation stays superuser-only.
func TestEnforceACLOrgAdminManagesMembership(t *testing.T) {
	f := newOrgMembershipFixture(t)

	if code := f.as(t, "boss", f.bossKey, "POST", f.acme+"/users", `{"username":"outsider"}`); code != http.StatusForbidden {
		t.Errorf("admin force-adds a user = %d, want 403", code)
	}
	if code := f.as(t, "boss", f.bossKey, "POST", f.acme+"/association_requests", `{"user":"outsider"}`); code != http.StatusCreated {
		t.Errorf("admin invites a user = %d, want 201", code)
	}
	if code := f.as(t, "boss", f.bossKey, "DELETE", f.acme+"/association_requests/invitee-acme", ""); code != http.StatusOK {
		t.Errorf("admin rescinds an invitation = %d, want 200", code)
	}
	if code := f.as(t, "boss", f.bossKey, "DELETE", f.acme+"/users/other", ""); code != http.StatusOK {
		t.Errorf("admin removes a member = %d, want 200", code)
	}
}

// A user may always remove themself from an org, as erchef allows.
func TestEnforceACLMemberMayLeave(t *testing.T) {
	f := newOrgMembershipFixture(t)
	if code := f.as(t, "member", f.memberKey, "DELETE", f.acme+"/users/member", ""); code != http.StatusOK {
		t.Fatalf("member leaves = %d, want 200", code)
	}
	if code := statusOf(t, signed(t, f.srv, "GET", f.acme+"/users/member", "")); code != http.StatusNotFound {
		t.Fatalf("member after leaving = %d, want 404", code)
	}
}

// Someone outside the org is refused all of it, as before.
func TestEnforceACLOutsiderCannotManageMembership(t *testing.T) {
	f := newOrgMembershipFixture(t)
	for _, c := range []struct{ what, method, url, body string }{
		{"removes a member", "DELETE", f.acme + "/users/other", ""},
		{"invites a user", "POST", f.acme + "/association_requests", `{"user":"outsider"}`},
		{"rescinds an invitation", "DELETE", f.acme + "/association_requests/invitee-acme", ""},
	} {
		if code := f.as(t, "outsider", f.outsiderKey, c.method, c.url, c.body); code != http.StatusForbidden {
			t.Errorf("outsider %s = %d, want 403", c.what, code)
		}
	}
}
