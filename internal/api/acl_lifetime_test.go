package api

import (
	"net/http"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// acmeOrg returns the test store's "acme" organization.
func acmeOrg(t *testing.T, st *store.Store) *store.Org {
	t.Helper()
	org, ok, err := st.Org("acme")
	if err != nil || !ok {
		t.Fatalf("org acme: ok=%v err=%v", ok, err)
	}
	return org
}

type aclCase struct {
	what    string
	setup   [][3]string // method, path, body — requests that create the object
	aclType string
	aclName string
	aclPath string
	delete  [3]string
}

// An ACL is keyed by object type and name, so one left behind is silently
// inherited by the next object created under that name. It must not outlive the
// object it governs.
func TestDeletingAnObjectDeletesItsACL(t *testing.T) {
	cases := []aclCase{
		{
			what:    "node",
			setup:   [][3]string{{"POST", "/organizations/acme/nodes", `{"name":"web01"}`}},
			aclType: "nodes", aclName: "web01",
			aclPath: "/organizations/acme/nodes/web01/_acl/read",
			delete:  [3]string{"DELETE", "/organizations/acme/nodes/web01", ""},
		},
		{
			what:    "role",
			setup:   [][3]string{{"POST", "/organizations/acme/roles", `{"name":"web"}`}},
			aclType: "roles", aclName: "web",
			aclPath: "/organizations/acme/roles/web/_acl/read",
			delete:  [3]string{"DELETE", "/organizations/acme/roles/web", ""},
		},
		{
			what:    "client",
			setup:   [][3]string{{"POST", "/organizations/acme/clients", `{"name":"node1"}`}},
			aclType: "clients", aclName: "node1",
			aclPath: "/organizations/acme/clients/node1/_acl/read",
			delete:  [3]string{"DELETE", "/organizations/acme/clients/node1", ""},
		},
		{
			what:    "data bag",
			setup:   [][3]string{{"POST", "/organizations/acme/data", `{"name":"vault"}`}},
			aclType: "data", aclName: "vault",
			aclPath: "/organizations/acme/data/vault/_acl/read",
			delete:  [3]string{"DELETE", "/organizations/acme/data/vault", ""},
		},
		{
			what:    "cookbook",
			setup:   [][3]string{{"PUT", "/organizations/acme/cookbooks/apache/1.0.0", `{"name":"apache","version":"1.0.0"}`}},
			aclType: "cookbooks", aclName: "apache",
			aclPath: "/organizations/acme/cookbooks/apache/_acl/read",
			delete:  [3]string{"DELETE", "/organizations/acme/cookbooks/apache/1.0.0", ""},
		},
		{
			what:    "cookbook artifact",
			setup:   [][3]string{{"PUT", "/organizations/acme/cookbook_artifacts/apache/abc123", `{"name":"apache"}`}},
			aclType: "cookbook_artifacts", aclName: "apache",
			aclPath: "/organizations/acme/cookbook_artifacts/apache/_acl/read",
			delete:  [3]string{"DELETE", "/organizations/acme/cookbook_artifacts/apache/abc123", ""},
		},
		{
			what:    "policy",
			setup:   [][3]string{{"POST", "/organizations/acme/policies/base/revisions", `{"revision_id":"r1"}`}},
			aclType: "policies", aclName: "base",
			aclPath: "/organizations/acme/policies/base/_acl/read",
			delete:  [3]string{"DELETE", "/organizations/acme/policies/base", ""},
		},
		{
			what:    "policy group",
			setup:   [][3]string{{"PUT", "/organizations/acme/policy_groups/prod/policies/base", `{"revision_id":"r1"}`}},
			aclType: "policy_groups", aclName: "prod",
			aclPath: "/organizations/acme/policy_groups/prod/_acl/read",
			delete:  [3]string{"DELETE", "/organizations/acme/policy_groups/prod", ""},
		},
	}

	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			srv, st := newTestAPI(t)
			org := acmeOrg(t, st)
			for _, req := range c.setup {
				if resp, body := do(t, req[0], srv.URL+req[1], req[2]); resp.StatusCode >= 300 {
					t.Fatalf("setup %s %s = %d: %s", req[0], req[1], resp.StatusCode, body)
				}
			}
			// Give the object a distinguishable ACL, as `knife acl` would.
			if resp, body := do(t, "PUT", srv.URL+c.aclPath,
				`{"read":{"actors":["mallory"],"groups":[]}}`); resp.StatusCode >= 300 {
				t.Fatalf("put acl = %d: %s", resp.StatusCode, body)
			}
			if _, ok, err := org.Get("acls", aclKey(c.aclType, c.aclName)); err != nil || !ok {
				t.Fatalf("acl was not stored (ok=%v err=%v)", ok, err)
			}

			resp, body := do(t, c.delete[0], srv.URL+c.delete[1], c.delete[2])
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("delete = %d: %s", resp.StatusCode, body)
			}

			if _, ok, err := org.Get("acls", aclKey(c.aclType, c.aclName)); err != nil {
				t.Fatal(err)
			} else if ok {
				t.Errorf("the ACL for %s %s/%s outlived the object",
					c.what, c.aclType, c.aclName)
			}
		})
	}
}

// A global user's ACL lives in the global space and goes with the user.
func TestDeletingAUserDeletesItsACL(t *testing.T) {
	srv, st := newTestAPI(t)
	if resp, body := do(t, "POST", srv.URL+"/users", `{"name":"dave"}`); resp.StatusCode >= 300 {
		t.Fatalf("create user = %d: %s", resp.StatusCode, body)
	}
	if resp, body := do(t, "PUT", srv.URL+"/users/dave/_acl/read",
		`{"read":{"actors":["mallory"],"groups":[]}}`); resp.StatusCode >= 300 {
		t.Fatalf("put acl = %d: %s", resp.StatusCode, body)
	}
	if resp, _ := do(t, "DELETE", srv.URL+"/users/dave", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete user = %d", resp.StatusCode)
	}
	if _, ok, _ := st.Global().Get("acls", aclKey("users", "dave")); ok {
		t.Error("the ACL for user dave outlived the user")
	}
}

// A cookbook's ACL governs all of its versions, so it survives while any version
// remains and goes only with the last one.
func TestCookbookACLSurvivesWhileAVersionRemains(t *testing.T) {
	srv, st := newTestAPI(t)
	org := acmeOrg(t, st)
	for _, v := range []string{"1.0.0", "2.0.0"} {
		if resp, body := do(t, "PUT", srv.URL+"/organizations/acme/cookbooks/apache/"+v,
			`{"name":"apache","version":"`+v+`"}`); resp.StatusCode >= 300 {
			t.Fatalf("put %s = %d: %s", v, resp.StatusCode, body)
		}
	}
	if resp, body := do(t, "PUT", srv.URL+"/organizations/acme/cookbooks/apache/_acl/read",
		`{"read":{"actors":["alice"],"groups":[]}}`); resp.StatusCode >= 300 {
		t.Fatalf("put acl = %d: %s", resp.StatusCode, body)
	}

	if resp, _ := do(t, "DELETE", srv.URL+"/organizations/acme/cookbooks/apache/1.0.0", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete 1.0.0 = %d", resp.StatusCode)
	}
	if _, ok, _ := org.Get("acls", aclKey("cookbooks", "apache")); !ok {
		t.Error("the cookbook ACL was dropped while version 2.0.0 still exists")
	}
	if resp, _ := do(t, "DELETE", srv.URL+"/organizations/acme/cookbooks/apache/2.0.0", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete 2.0.0 = %d", resp.StatusCode)
	}
	if _, ok, _ := org.Get("acls", aclKey("cookbooks", "apache")); ok {
		t.Error("the cookbook ACL outlived its last version")
	}
}
