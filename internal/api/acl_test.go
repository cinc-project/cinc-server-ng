package api

import (
	"encoding/json"
	"slices"
	"testing"
)

type aclPerm struct {
	Actors []string `json:"actors"`
	Groups []string `json:"groups"`
}

func TestACLDefaultShape(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/nodes", `{"name":"web01"}`)

	_, body := do(t, "GET", base+"/nodes/web01/_acl", "")
	var acl map[string]aclPerm
	if err := json.Unmarshal([]byte(body), &acl); err != nil {
		t.Fatalf("decode acl: %v (%s)", err, body)
	}
	for _, perm := range []string{"create", "read", "update", "delete", "grant"} {
		p, ok := acl[perm]
		if !ok {
			t.Fatalf("acl missing %q permission: %s", perm, body)
		}
		if p.Actors == nil || p.Groups == nil {
			t.Fatalf("acl %q must have actors and groups arrays: %s", perm, body)
		}
	}
}

func TestACLGetSinglePermission(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, body := do(t, "GET", base+"/roles/web/_acl/read", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get read perm = %d: %s", resp.StatusCode, body)
	}
	var got map[string]aclPerm
	json.Unmarshal([]byte(body), &got)
	if _, ok := got["read"]; !ok || len(got) != 1 {
		t.Fatalf("single-permission response = %s", body)
	}
}

func TestACLUpdatePermission(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	// Grant a specific actor on the "grant" permission.
	resp, body := do(t, "PUT", base+"/nodes/web01/_acl/grant",
		`{"grant":{"actors":["alice"],"groups":["admins"]}}`)
	if resp.StatusCode != 200 {
		t.Fatalf("put grant = %d: %s", resp.StatusCode, body)
	}

	// The change is reflected in the full ACL.
	_, body = do(t, "GET", base+"/nodes/web01/_acl", "")
	var acl map[string]aclPerm
	json.Unmarshal([]byte(body), &acl)
	if len(acl["grant"].Actors) != 1 || acl["grant"].Actors[0] != "alice" {
		t.Fatalf("grant not updated: %s", body)
	}
	// Other permissions remain at their defaults.
	if len(acl["read"].Groups) == 0 {
		t.Fatalf("read permission lost its defaults: %s", body)
	}
}

func TestACLInvalidPermission404(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, _ := do(t, "GET", base+"/nodes/web01/_acl/bogus", "")
	if resp.StatusCode != 404 {
		t.Fatalf("invalid perm = %d, want 404", resp.StatusCode)
	}
	resp, _ = do(t, "PUT", base+"/nodes/web01/_acl/bogus", `{"bogus":{"actors":[],"groups":[]}}`)
	if resp.StatusCode != 404 {
		t.Fatalf("put invalid perm = %d, want 404", resp.StatusCode)
	}
}

func TestACLDataBagAndOrg(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	// Data bag ACL path resolves alongside /data/{bag}/{item}.
	do(t, "POST", base+"/data", `{"name":"secrets"}`)
	resp, body := do(t, "GET", base+"/data/secrets/_acl", "")
	if resp.StatusCode != 200 {
		t.Fatalf("data bag acl = %d: %s", resp.StatusCode, body)
	}

	// Organization-level ACL.
	resp, body = do(t, "GET", base+"/organizations/_acl", "")
	if resp.StatusCode != 200 {
		t.Fatalf("org acl = %d: %s", resp.StatusCode, body)
	}
	var acl map[string]aclPerm
	json.Unmarshal([]byte(body), &acl)
	if _, ok := acl["grant"]; !ok {
		t.Fatalf("org acl missing grant: %s", body)
	}
}

// TestOrgACLAtErchefPath covers the organization's own ACL at erchef's path,
// /organizations/{org}/organizations/_acl[/{perm}]. erchef has no shorter
// /organizations/{org}/_acl form, so that path is not routed.
func TestOrgACLAtErchefPath(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", srv.URL+"/users", `{"name":"alice"}`)

	resp, body := do(t, "GET", base+"/organizations/_acl", "")
	if resp.StatusCode != 200 {
		t.Fatalf("GET org acl = %d: %s", resp.StatusCode, body)
	}
	var acl map[string]aclPerm
	json.Unmarshal([]byte(body), &acl)
	if _, ok := acl["grant"]; !ok {
		t.Fatalf("org acl missing grant: %s", body)
	}

	resp, body = do(t, "PUT", base+"/organizations/_acl/read", `{"read":{"actors":["alice"],"groups":[]}}`)
	if resp.StatusCode != 200 {
		t.Fatalf("PUT org acl read = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, "GET", base+"/organizations/_acl/read", "")
	if resp.StatusCode != 200 {
		t.Fatalf("GET org acl read = %d: %s", resp.StatusCode, body)
	}
	var got map[string]aclPerm
	json.Unmarshal([]byte(body), &got)
	if !slices.Equal(got["read"].Actors, []string{"alice"}) {
		t.Errorf("org acl read actors = %v, want [alice]; body %s", got["read"].Actors, body)
	}

	// The short form is not an erchef route: it 404s with a JSON error.
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/_acl", ""},
		{"GET", "/_acl/read", ""},
		{"PUT", "/_acl/read", `{"read":{"actors":[],"groups":[]}}`},
	} {
		resp, body := do(t, c.method, base+c.path, c.body)
		var e struct{ Error []string }
		if resp.StatusCode != 404 || json.Unmarshal([]byte(body), &e) != nil || len(e.Error) == 0 {
			t.Errorf("%s %s = %d %s, want a JSON 404", c.method, c.path, resp.StatusCode, body)
		}
	}
}

func TestUserACLEndpoints(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL
	do(t, "POST", base+"/users", `{"name":"alice"}`)

	// Full user ACL: all five permissions, JSON.
	resp, body := do(t, "GET", base+"/users/alice/_acl", "")
	if resp.StatusCode != 200 {
		t.Fatalf("user acl = %d: %s", resp.StatusCode, body)
	}
	var acl map[string]aclPerm
	if err := json.Unmarshal([]byte(body), &acl); err != nil {
		t.Fatalf("decode user acl: %v (%s)", err, body)
	}
	for _, p := range []string{"create", "read", "update", "delete", "grant"} {
		if _, ok := acl[p]; !ok {
			t.Fatalf("user acl missing %q: %s", p, body)
		}
	}

	// Single permission.
	if resp, _ := do(t, "GET", base+"/users/alice/_acl/read", ""); resp.StatusCode != 200 {
		t.Fatalf("user acl read = %d", resp.StatusCode)
	}

	// PUT updates and persists.
	if resp, _ := do(t, "PUT", base+"/users/alice/_acl/grant", `{"grant":{"actors":["bob"],"groups":[]}}`); resp.StatusCode != 200 {
		t.Fatalf("user acl put = %d", resp.StatusCode)
	}
	_, body = do(t, "GET", base+"/users/alice/_acl", "")
	json.Unmarshal([]byte(body), &acl)
	if len(acl["grant"].Actors) != 1 || acl["grant"].Actors[0] != "bob" {
		t.Fatalf("user acl grant not persisted: %s", body)
	}

	// Invalid permission → 404.
	if resp, _ := do(t, "GET", base+"/users/alice/_acl/bogus", ""); resp.StatusCode != 404 {
		t.Fatalf("user acl bogus = %d, want 404", resp.StatusCode)
	}
}

func TestPolicyGroupACLPutStatus201(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	// policy_group ACL PUT returns 201, matching Chef.
	if resp, body := do(t, "PUT", base+"/policy_groups/prod/_acl/read", `{"read":{"actors":[],"groups":["admins"]}}`); resp.StatusCode != 201 {
		t.Fatalf("policy_group acl put = %d, want 201; body %s", resp.StatusCode, body)
	}
	// Other object types stay 200.
	if resp, _ := do(t, "PUT", base+"/nodes/web01/_acl/read", `{"read":{"actors":[],"groups":["admins"]}}`); resp.StatusCode != 200 {
		t.Fatalf("node acl put = %d, want 200", resp.StatusCode)
	}
}
