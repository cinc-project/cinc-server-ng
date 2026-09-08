package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Deleting a policy removes every revision it had. A policy group still naming
// it then advertises a revision that cannot be fetched — the group listing shows
// a deployment that does not exist, and a node converging on it gets a 404 from
// an endpoint whose own group lookup succeeded.
func TestDeletingAPolicyClearsItsGroupDeployments(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	// Deploy "base" to two groups, and an unrelated policy to one of them.
	for _, g := range []string{"prod", "staging"} {
		if resp, body := do(t, "PUT", base+"/policy_groups/"+g+"/policies/base",
			`{"revision_id":"r1","run_list":["recipe[base]"]}`); resp.StatusCode >= 300 {
			t.Fatalf("deploy base to %s = %d: %s", g, resp.StatusCode, body)
		}
	}
	if resp, body := do(t, "PUT", base+"/policy_groups/prod/policies/web",
		`{"revision_id":"w1"}`); resp.StatusCode >= 300 {
		t.Fatalf("deploy web = %d: %s", resp.StatusCode, body)
	}

	if resp, body := do(t, "DELETE", base+"/policies/base", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete policy = %d: %s", resp.StatusCode, body)
	}

	for _, g := range []string{"prod", "staging"} {
		resp, body := do(t, "GET", base+"/policy_groups/"+g, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("read group %s = %d: %s", g, resp.StatusCode, body)
		}
		var doc struct {
			Policies map[string]any `json:"policies"`
		}
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatal(err)
		}
		if _, still := doc.Policies["base"]; still {
			t.Errorf("group %s still deploys the deleted policy: %s", g, body)
		}
	}
	// The unrelated deployment is untouched.
	resp, body := do(t, "GET", base+"/policy_groups/prod/policies/web", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("unrelated deployment = %d, want 200: %s", resp.StatusCode, body)
	}
}
