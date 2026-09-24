package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// Deleting one revision removes it from every group that pins it, as erchef's
// policy_revisions_policy_groups_association rows cascade on the revision's
// delete. Groups pinning another revision of the same policy keep it.
func TestDeletingARevisionClearsTheGroupsPinningIt(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	deploy := func(group, policy, rev string) {
		t.Helper()
		body := `{"name":"` + policy + `","revision_id":"` + rev + `","run_list":["recipe[base::default]"],"cookbook_locks":{}}`
		if resp, b := do(t, "PUT", base+"/policy_groups/"+group+"/policies/"+policy, body); resp.StatusCode >= 300 {
			t.Fatalf("deploy %s@%s to %s = %d: %s", policy, rev, group, resp.StatusCode, b)
		}
	}
	deploy("prod", "base", "r1")
	deploy("dev", "base", "r1")
	deploy("staging", "base", "r2")
	deploy("prod", "web", "w1")

	if resp, body := do(t, "DELETE", base+"/policies/base/revisions/r1", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete revision = %d: %s", resp.StatusCode, body)
	}

	type pin struct {
		RevisionID string `json:"revision_id"`
	}
	pinned := func(group string) map[string]pin {
		t.Helper()
		resp, body := do(t, "GET", base+"/policy_groups/"+group, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("read group %s = %d: %s", group, resp.StatusCode, body)
		}
		var doc struct {
			Policies map[string]pin `json:"policies"`
		}
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Policies
	}
	for _, g := range []string{"prod", "dev"} {
		if p, still := pinned(g)["base"]; still {
			t.Errorf("group %s still pins deleted revision %s", g, p.RevisionID)
		}
		if resp, _ := do(t, "GET", base+"/policy_groups/"+g+"/policies/base", ""); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s/policies/base = %d, want 404", g, resp.StatusCode)
		}
	}
	if got := pinned("staging")["base"].RevisionID; got != "r2" {
		t.Errorf("staging pins base@%q, want r2 (another revision is untouched)", got)
	}
	if got := pinned("prod")["web"].RevisionID; got != "w1" {
		t.Errorf("prod pins web@%q, want w1 (another policy is untouched)", got)
	}
	if resp, body := do(t, "GET", base+"/policies/base/revisions/r2", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("surviving revision = %d: %s", resp.StatusCode, body)
	}
}
