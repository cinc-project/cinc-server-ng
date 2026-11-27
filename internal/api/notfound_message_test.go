package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// firstError returns error[0] of a JSON error body.
func firstError(t *testing.T, body string) string {
	t.Helper()
	var e struct {
		Error []string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil || len(e.Error) == 0 {
		t.Fatalf("want an {\"error\":[...]} body, got %s", body)
	}
	return e.Error[0]
}

// notFoundCases are erchef's 404 texts for a missing named object, taken from
// chef_wm_util:not_found_message/2 and the named group and container resources
// (oc_chef_wm_named_group, oc_chef_wm_named_container), which build their own.
// Each type words it differently, and none uses the plural collection name.
var notFoundCases = []struct{ method, path, body, want string }{
	{"GET", "/organizations/acme/nodes/ghost", "", "node 'ghost' not found"},
	{"PUT", "/organizations/acme/nodes/ghost", `{"name":"ghost"}`, "node 'ghost' not found"},
	{"DELETE", "/organizations/acme/nodes/ghost", "", "node 'ghost' not found"},
	{"GET", "/organizations/acme/roles/ghost", "", "Cannot load role ghost"},
	{"PUT", "/organizations/acme/roles/ghost", `{"name":"ghost"}`, "Cannot load role ghost"},
	{"DELETE", "/organizations/acme/roles/ghost", "", "Cannot load role ghost"},
	{"GET", "/organizations/acme/environments/ghost", "", "Cannot load environment ghost"},
	{"PUT", "/organizations/acme/environments/ghost", `{"name":"ghost"}`, "Cannot load environment ghost"},
	{"DELETE", "/organizations/acme/environments/ghost", "", "Cannot load environment ghost"},
	{"GET", "/organizations/acme/containers/ghost", "", "Cannot load container ghost"},
	{"DELETE", "/organizations/acme/containers/ghost", "", "Cannot load container ghost"},
	{"GET", "/organizations/acme/groups/ghost", "", "Cannot load group ghost"},
	{"PUT", "/organizations/acme/groups/ghost", `{"groupname":"ghost"}`, "Cannot load group ghost"},
	{"DELETE", "/organizations/acme/groups/ghost", "", "Cannot load group ghost"},
	{"GET", "/organizations/acme/clients/ghost", "", "Cannot load client ghost"},
	{"PUT", "/organizations/acme/clients/ghost", `{"name":"ghost"}`, "Cannot load client ghost"},
	{"DELETE", "/organizations/acme/clients/ghost", "", "Cannot load client ghost"},
	{"GET", "/organizations/acme/clients/ghost/keys", "", "Cannot load client ghost"},
	{"GET", "/users/ghost", "", "Could not find user ghost"},
	{"PUT", "/users/ghost", `{"name":"ghost"}`, "Could not find user ghost"},
	{"DELETE", "/users/ghost", "", "Could not find user ghost"},
	{"GET", "/users/ghost/keys", "", "Could not find user ghost"},
	// Data bags (chef_wm_named_data, chef_wm_named_data_item): the text
	// depends on the method, and on an item route a missing bag reads the
	// same as a missing item.
	{"GET", "/organizations/acme/data/ghost", "", "Cannot load data bag ghost"},
	{"DELETE", "/organizations/acme/data/ghost", "", "Cannot load data bag ghost"},
	{"POST", "/organizations/acme/data/ghost", `{"id":"item1"}`, "No data bag 'ghost' could be found. Please create this data bag before adding items to it."},
	{"GET", "/organizations/acme/data/ghost/item1", "", "Cannot load data bag item item1 for data bag ghost"},
	{"PUT", "/organizations/acme/data/ghost/item1", `{"id":"item1"}`, "Cannot load data bag item item1 for data bag ghost"},
	{"DELETE", "/organizations/acme/data/ghost/item1", "", "Cannot load data bag ghost item item1"},
	{"GET", "/organizations/acme/data/bag/ghost", "", "Cannot load data bag item ghost for data bag bag"},
	{"PUT", "/organizations/acme/data/bag/ghost", `{"id":"ghost"}`, "Cannot load data bag item ghost for data bag bag"},
	{"DELETE", "/organizations/acme/data/bag/ghost", "", "Cannot load data bag bag item ghost"},
	// The _acl of a missing object (oc_chef_wm_acl) uses not_found_message
	// too, where a group reads differently from its named endpoint.
	{"GET", "/organizations/acme/nodes/ghost/_acl", "", "node 'ghost' not found"},
	{"GET", "/organizations/acme/roles/ghost/_acl", "", "Cannot load role ghost"},
	{"GET", "/organizations/acme/environments/ghost/_acl", "", "Cannot load environment ghost"},
	{"GET", "/organizations/acme/clients/ghost/_acl", "", "Cannot load client ghost"},
	{"GET", "/organizations/acme/groups/ghost/_acl", "", "group 'ghost' not found"},
	{"GET", "/organizations/acme/containers/ghost/_acl", "", "Cannot load container ghost"},
	{"GET", "/organizations/acme/data/ghost/_acl", "", "Cannot load data bag ghost"},
	{"GET", "/organizations/acme/cookbooks/ghost/_acl", "", "Cannot find a cookbook named ghost"},
	{"GET", "/organizations/acme/policies/ghost/_acl", "", "policy 'ghost' not found"},
	{"GET", "/organizations/acme/policy_groups/ghost/_acl", "", "policy_group 'ghost' not found"},
	{"GET", "/users/ghost/_acl", "", "Could not find user ghost"},
}

func TestMissingObjectNotFoundMessages(t *testing.T) {
	srv, _ := newTestAPI(t)
	if resp, body := do(t, "POST", srv.URL+"/organizations/acme/data", `{"name":"bag"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create bag = %d: %s", resp.StatusCode, body)
	}
	for _, c := range notFoundCases {
		resp, body := do(t, c.method, srv.URL+c.path, c.body)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404; body %s", c.method, c.path, resp.StatusCode, body)
			continue
		}
		if got := firstError(t, body); got != c.want {
			t.Errorf("%s %s: error = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

// Under enforcement the middleware answers for a missing object before the
// handler runs, so it has to use the same text. It checks existence only for
// org objects and data bags: an actor with no grant on users, on a client's
// keys, or on an existing bag gets its 403 first, so those cases are left to
// the handler test above.
func TestEnforcedMissingObjectNotFoundMessages(t *testing.T) {
	h, _ := enforcingHandler(t)
	stranger := Actor{Name: "stranger"}
	for _, c := range notFoundCases {
		if strings.HasPrefix(c.path, "/users/") || strings.HasSuffix(c.path, "/keys") ||
			strings.HasPrefix(c.path, "/organizations/acme/data/bag/") {
			continue
		}
		code, body := authzReq(t, h, stranger, c.method, c.path, c.body)
		if code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404; body %s", c.method, c.path, code, body)
			continue
		}
		if got := firstError(t, body); got != c.want {
			t.Errorf("%s %s: error = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}
