package api

import (
	"net/http"
	"strings"
	"testing"
)

// TestPutOnMissingObjectIs404 pins erchef's update semantics: PUT on a named
// object updates it and never creates it (creation goes through POST on the
// collection). A PUT naming an object that does not exist answers 404 and
// stores nothing, so a later GET still finds nothing.
func TestPutOnMissingObjectIs404(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
	}{
		{"node", "/organizations/acme/nodes/ghost", `{"name":"ghost"}`},
		{"role", "/organizations/acme/roles/ghost", `{"name":"ghost"}`},
		{"environment", "/organizations/acme/environments/ghost", `{"name":"ghost"}`},
		{"client", "/organizations/acme/clients/ghost", `{"name":"ghost"}`},
		{"group", "/organizations/acme/groups/ghost", `{"groupname":"ghost"}`},
		{"user", "/users/ghost", `{"username":"ghost","display_name":"Ghost"}`},
		{"data bag item", "/organizations/acme/data/bag/ghost", `{"id":"ghost","v":"1"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := newTestAPI(t)
			// The bag exists, so only the item is missing.
			if resp, body := do(t, "POST", srv.URL+"/organizations/acme/data", `{"name":"bag"}`); resp.StatusCode != http.StatusCreated {
				t.Fatalf("create bag = %d: %s", resp.StatusCode, body)
			}
			// Baseline: the object is absent before the PUT.
			if resp, _ := do(t, "GET", srv.URL+c.path, ""); resp.StatusCode != http.StatusNotFound {
				t.Fatalf("GET before PUT = %d, want 404", resp.StatusCode)
			}

			resp, body := do(t, "PUT", srv.URL+c.path, c.body)
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("PUT on missing %s = %d, want 404; body %s", c.name, resp.StatusCode, body)
			}
			errBody(t, resp, body)
			if !strings.Contains(body, "ghost") {
				t.Errorf("404 body should name the missing object: %s", body)
			}
			if resp, body := do(t, "GET", srv.URL+c.path, ""); resp.StatusCode != http.StatusNotFound {
				t.Fatalf("GET after refused PUT = %d, want 404 (the PUT created it); body %s", resp.StatusCode, body)
			}
		})
	}
}
