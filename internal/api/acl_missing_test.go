package api

import (
	"net/http"
	"strings"
	"testing"
)

// aclTargets creates one object of every type that has an _acl endpoint, named
// so its ACL lives at base+path. erchef looks the object up before its ACL, so
// these are also the objects whose ACL a request may read or write.
var aclTargets = []struct {
	typ, name string
	aclBase   string      // the object's _acl path
	setup     [][3]string // method, path, body: requests that create the object
}{
	{"nodes", "web01", "/organizations/acme/nodes/web01/_acl", [][3]string{{"POST", "/organizations/acme/nodes", `{"name":"web01"}`}}},
	{"roles", "web", "/organizations/acme/roles/web/_acl", [][3]string{{"POST", "/organizations/acme/roles", `{"name":"web"}`}}},
	{"environments", "prod", "/organizations/acme/environments/prod/_acl", [][3]string{{"POST", "/organizations/acme/environments", `{"name":"prod"}`}}},
	{"clients", "node1", "/organizations/acme/clients/node1/_acl", [][3]string{{"POST", "/organizations/acme/clients", `{"name":"node1"}`}}},
	{"groups", "ops", "/organizations/acme/groups/ops/_acl", [][3]string{{"POST", "/organizations/acme/groups", `{"groupname":"ops"}`}}},
	{"containers", "things", "/organizations/acme/containers/things/_acl", [][3]string{{"POST", "/organizations/acme/containers", `{"containername":"things"}`}}},
	{"data", "vault", "/organizations/acme/data/vault/_acl", [][3]string{{"POST", "/organizations/acme/data", `{"name":"vault"}`}}},
	{"cookbooks", "apache", "/organizations/acme/cookbooks/apache/_acl", [][3]string{{"PUT", "/organizations/acme/cookbooks/apache/1.0.0", `{"name":"apache","version":"1.0.0"}`}}},
	{"cookbook_artifacts", "apache", "/organizations/acme/cookbook_artifacts/apache/_acl", [][3]string{{"PUT", "/organizations/acme/cookbook_artifacts/apache/abc123", `{"name":"apache"}`}}},
	{"policies", "base", "/organizations/acme/policies/base/_acl", [][3]string{{"POST", "/organizations/acme/policies/base/revisions", `{"revision_id":"r1"}`}}},
	{"policy_groups", "prod", "/organizations/acme/policy_groups/prod/_acl", [][3]string{{"PUT", "/organizations/acme/policy_groups/prod/policies/base", `{"revision_id":"r1"}`}}},
	{"users", "alice", "/users/alice/_acl", [][3]string{{"POST", "/users", `{"name":"alice"}`}}},
}

// TestACLOfMissingObjectIs404 pins erchef's order: the object is looked up
// before its ACL, so reading or writing the ACL of an object that does not
// exist is a 404, and the write stores nothing. A stored ACL is keyed by type
// and name, so one written ahead of its object would govern whatever is later
// created under that name.
func TestACLOfMissingObjectIs404(t *testing.T) {
	for _, c := range aclTargets {
		t.Run(c.typ, func(t *testing.T) {
			srv, st := newTestAPI(t)
			for _, req := range []struct{ method, path, body string }{
				{"GET", c.aclBase, ""},
				{"GET", c.aclBase + "/read", ""},
				{"PUT", c.aclBase + "/read", `{"read":{"actors":["mallory"],"groups":[]}}`},
			} {
				resp, body := do(t, req.method, srv.URL+req.path, req.body)
				if resp.StatusCode != http.StatusNotFound {
					t.Errorf("%s %s = %d, want 404; body %s", req.method, req.path, resp.StatusCode, body)
					continue
				}
				errBody(t, resp, body)
				if !strings.Contains(body, c.name) {
					t.Errorf("%s %s: 404 should name the missing object: %s", req.method, req.path, body)
				}
			}
			space := st.Global()
			if c.typ != "users" {
				space = acmeOrg(t, st)
			}
			if _, ok, err := space.Get("acls", aclKey(c.typ, c.name)); err != nil {
				t.Fatal(err)
			} else if ok {
				t.Errorf("the refused PUT stored an ACL for the missing %s %s", c.typ, c.name)
			}
		})
	}
}

// TestACLOfExistingObjectIsServed is the other half: once the object exists,
// every type's ACL reads and writes as before.
func TestACLOfExistingObjectIsServed(t *testing.T) {
	for _, c := range aclTargets {
		t.Run(c.typ, func(t *testing.T) {
			srv, _ := newTestAPI(t)
			for _, req := range c.setup {
				if resp, body := do(t, req[0], srv.URL+req[1], req[2]); resp.StatusCode >= 300 {
					t.Fatalf("setup %s %s = %d: %s", req[0], req[1], resp.StatusCode, body)
				}
			}
			if resp, body := do(t, "GET", srv.URL+c.aclBase, ""); resp.StatusCode != http.StatusOK {
				t.Errorf("GET acl = %d: %s", resp.StatusCode, body)
			}
			if resp, body := do(t, "GET", srv.URL+c.aclBase+"/read", ""); resp.StatusCode != http.StatusOK {
				t.Errorf("GET acl read = %d: %s", resp.StatusCode, body)
			}
			if resp, body := do(t, "PUT", srv.URL+c.aclBase+"/read", `{"read":{"actors":[],"groups":["admins"]}}`); resp.StatusCode >= 300 {
				t.Errorf("PUT acl read = %d: %s", resp.StatusCode, body)
			}
		})
	}
}

// TestEnforceACLOfMissingObjectIs404 checks the order under enforcement: an
// actor with no grant on the object still learns it is missing (404), not that
// it lacks permission (403), as for every other object route.
func TestEnforceACLOfMissingObjectIs404(t *testing.T) {
	h, _ := enforcingHandler(t)
	stranger := Actor{Name: "stranger"}
	// Baseline: the stranger holds no grant on an object that does exist.
	if code, body := authzReq(t, h, stranger, "GET", "/organizations/acme/nodes/web01/_acl", ""); code != http.StatusForbidden {
		t.Fatalf("stranger GET existing node acl = %d, want 403; body %s", code, body)
	}
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/organizations/acme/nodes/ghost/_acl", ""},
		{"GET", "/organizations/acme/roles/ghost/_acl/read", ""},
		{"PUT", "/organizations/acme/nodes/ghost/_acl/read", `{"read":{"actors":["stranger"],"groups":[]}}`},
		{"GET", "/organizations/acme/data/ghost/_acl", ""},
		{"GET", "/organizations/acme/cookbooks/ghost/_acl", ""},
		{"GET", "/users/ghost/_acl", ""},
	} {
		if code, body := authzReq(t, h, stranger, c.method, c.path, c.body); code != http.StatusNotFound {
			t.Errorf("stranger %s %s = %d, want 404; body %s", c.method, c.path, code, body)
		}
	}
}
