package server

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

// grantGroups reads the groups on an object's grant ACE as the superuser.
func grantGroups(t *testing.T, srv *Server, aclURL string) []string {
	t.Helper()
	resp, err := http.DefaultClient.Do(signed(t, srv, "GET", aclURL+"/grant", ""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]struct {
		Groups []string `json:"groups"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc["grant"].Groups
}

// erchef refuses a non-superuser ACL write that takes the admins group off a
// grant ACE that had it (oc_chef_authz_acl_constraints), so an org admin
// cannot lock the admins group out of an object's ACL.
func TestACLGrantKeepsAdmins(t *testing.T) {
	f := newOrgMembershipFixture(t)
	if code := f.as(t, "boss", f.bossKey, "POST", f.acme+"/data", `{"name":"vault"}`); code != http.StatusCreated {
		t.Fatalf("admin creates the vault = %d, want 201", code)
	}

	for _, aclURL := range []string{
		f.acme + "/data/vault/_acl",
		f.acme + "/containers/nodes/_acl",
		f.acme + "/organizations/_acl",
	} {
		// Baseline: the admin holds grant here and admins is on the ACE, so a
		// 403 below is the constraint, not a missing permission.
		if !slices.Contains(grantGroups(t, f.srv, aclURL), "admins") {
			t.Fatalf("%s: grant ACE lacks admins before any change", aclURL)
		}
		keep := `{"grant":{"actors":["boss"],"groups":["admins"]}}`
		if code := f.as(t, "boss", f.bossKey, "PUT", aclURL+"/grant", keep); code != http.StatusOK {
			t.Fatalf("%s: admin rewrites grant keeping admins = %d, want 200", aclURL, code)
		}

		resp, err := http.DefaultClient.Do(signedAs(t, "boss", f.bossKey, "PUT", aclURL+"/grant",
			`{"grant":{"actors":["boss"],"groups":[]}}`))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: admin removes admins from grant = %d, want 403; body %s", aclURL, resp.StatusCode, body)
		}
		if want := `{"error":["Admin group cannot be removed from the Grant ACE"]}`; strings.TrimSpace(string(body)) != want {
			t.Errorf("%s: body = %s, want %s", aclURL, body, want)
		}
		if !slices.Contains(grantGroups(t, f.srv, aclURL), "admins") {
			t.Errorf("%s: refused write still removed admins from grant", aclURL)
		}

		// Only the grant permission is constrained.
		if code := f.as(t, "boss", f.bossKey, "PUT", aclURL+"/update", `{"update":{"actors":["boss"],"groups":[]}}`); code != http.StatusOK {
			t.Errorf("%s: admin removes admins from update = %d, want 200", aclURL, code)
		}
	}

	// The superuser bypasses the constraint.
	vault := f.acme + "/data/vault/_acl"
	if code := statusOf(t, signed(t, f.srv, "PUT", vault+"/grant", `{"grant":{"actors":["boss"],"groups":[]}}`)); code != http.StatusOK {
		t.Fatalf("superuser removes admins from grant = %d, want 200", code)
	}
	// With admins already gone, there is nothing left to protect.
	if code := f.as(t, "boss", f.bossKey, "PUT", vault+"/grant", `{"grant":{"actors":["boss"],"groups":["users"]}}`); code != http.StatusOK {
		t.Errorf("admin rewrites a grant ACE that never had admins = %d, want 200", code)
	}
}

// Without authentication there is no requestor to tell apart from the
// superuser, and chef-zero (the role --no-auth plays) has no such constraint.
func TestACLGrantAdminsRemovalWithoutAuth(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, DisableAuth: true})
	acme := srv.URL() + "/organizations/acme"
	req, _ := http.NewRequest("POST", acme+"/data", strings.NewReader(`{"name":"vault"}`))
	if code := statusOf(t, req); code != http.StatusCreated {
		t.Fatalf("create vault = %d, want 201", code)
	}
	req, _ = http.NewRequest("PUT", acme+"/data/vault/_acl/grant", strings.NewReader(`{"grant":{"actors":[],"groups":[]}}`))
	if code := statusOf(t, req); code != http.StatusOK {
		t.Errorf("unauthenticated grant write without admins = %d, want 200", code)
	}
}

// The constraint is validation, not authorization: a permissive server, where
// any member may reach the ACL, still refuses it.
func TestACLGrantKeepsAdminsWithoutEnforcement(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	acme := srv.URL() + "/organizations/acme"
	key := []byte(createUser(t, srv, `{"name":"member"}`))
	if code := statusOf(t, signed(t, srv, "POST", acme+"/users", `{"username":"member"}`)); code != http.StatusCreated {
		t.Fatalf("superuser associates member = %d, want 201", code)
	}
	if code := statusOf(t, signed(t, srv, "POST", acme+"/data", `{"name":"vault"}`)); code != http.StatusCreated {
		t.Fatalf("create vault = %d, want 201", code)
	}
	aclURL := acme + "/data/vault/_acl"
	if code := statusOf(t, signedAs(t, "member", key, "PUT", aclURL+"/grant", `{"grant":{"actors":["member"],"groups":["admins"]}}`)); code != http.StatusOK {
		t.Fatalf("member rewrites grant keeping admins = %d, want 200", code)
	}
	if code := statusOf(t, signedAs(t, "member", key, "PUT", aclURL+"/grant", `{"grant":{"actors":["member"],"groups":[]}}`)); code != http.StatusForbidden {
		t.Errorf("member removes admins from grant = %d, want 403", code)
	}
	if !slices.Contains(grantGroups(t, srv, aclURL), "admins") {
		t.Errorf("refused write still removed admins from grant")
	}
}
