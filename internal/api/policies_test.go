package api

import (
	"encoding/json"
	"testing"
)

const sampleRevision = `{
  "revision_id": "1111111111111111111111111111111111111111111111111111111111111111",
  "name": "appserver",
  "run_list": ["recipe[nginx::default]"],
  "cookbook_locks": {
    "nginx": {
      "version": "1.0.0",
      "identifier": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  }
}`

func TestPolicyRevisionLifecycle(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	const rev = "1111111111111111111111111111111111111111111111111111111111111111"

	// No policies yet.
	resp, body := do(t, "GET", base+"/policies", "")
	if resp.StatusCode != 200 || body == "" {
		t.Fatalf("empty policies = %d %s", resp.StatusCode, body)
	}

	// Push a revision.
	resp, body = do(t, "POST", base+"/policies/appserver/revisions", sampleRevision)
	if resp.StatusCode != 201 {
		t.Fatalf("post revision = %d: %s", resp.StatusCode, body)
	}

	// It appears under GET /policies with its revision id.
	_, body = do(t, "GET", base+"/policies", "")
	var policies map[string]struct {
		URI       string         `json:"uri"`
		Revisions map[string]any `json:"revisions"`
	}
	json.Unmarshal([]byte(body), &policies)
	if _, ok := policies["appserver"].Revisions[rev]; !ok {
		t.Fatalf("policy not listed: %s", body)
	}

	// GET /policies/appserver lists revisions.
	resp, _ = do(t, "GET", base+"/policies/appserver", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get policy = %d", resp.StatusCode)
	}

	// GET the specific revision returns the full document.
	resp, body = do(t, "GET", base+"/policies/appserver/revisions/"+rev, "")
	if resp.StatusCode != 200 {
		t.Fatalf("get revision = %d", resp.StatusCode)
	}
	var got map[string]any
	json.Unmarshal([]byte(body), &got)
	if got["revision_id"] != rev {
		t.Fatalf("revision doc = %s", body)
	}

	// Duplicate revision -> 409.
	resp, _ = do(t, "POST", base+"/policies/appserver/revisions", sampleRevision)
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate revision = %d, want 409", resp.StatusCode)
	}

	// Delete the revision.
	resp, _ = do(t, "DELETE", base+"/policies/appserver/revisions/"+rev, "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete revision = %d", resp.StatusCode)
	}
	resp, _ = do(t, "GET", base+"/policies/appserver/revisions/"+rev, "")
	if resp.StatusCode != 404 {
		t.Fatalf("get deleted revision = %d", resp.StatusCode)
	}
}

func TestPolicyGroupDeployFlow(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	const rev = "1111111111111111111111111111111111111111111111111111111111111111"

	// Associate (deploy) a revision into the "production" group. This is the
	// PUT that chef-client's `chef push` performs.
	resp, body := do(t, "PUT", base+"/policy_groups/production/policies/appserver", sampleRevision)
	if resp.StatusCode != 200 {
		t.Fatalf("associate = %d: %s", resp.StatusCode, body)
	}

	// The group lists the policy at that revision.
	_, body = do(t, "GET", base+"/policy_groups", "")
	var groups map[string]struct {
		Policies map[string]struct {
			RevisionID string `json:"revision_id"`
		} `json:"policies"`
	}
	json.Unmarshal([]byte(body), &groups)
	if groups["production"].Policies["appserver"].RevisionID != rev {
		t.Fatalf("group policies = %s", body)
	}

	// Pull the deployed revision back (what a node does on converge).
	resp, body = do(t, "GET", base+"/policy_groups/production/policies/appserver", "")
	if resp.StatusCode != 200 {
		t.Fatalf("pull policy = %d: %s", resp.StatusCode, body)
	}
	var doc map[string]any
	json.Unmarshal([]byte(body), &doc)
	if doc["revision_id"] != rev {
		t.Fatalf("pulled revision = %s", body)
	}

	// Disassociate.
	resp, _ = do(t, "DELETE", base+"/policy_groups/production/policies/appserver", "")
	if resp.StatusCode != 200 {
		t.Fatalf("disassociate = %d", resp.StatusCode)
	}
	resp, _ = do(t, "GET", base+"/policy_groups/production/policies/appserver", "")
	if resp.StatusCode != 404 {
		t.Fatalf("pull after disassociate = %d", resp.StatusCode)
	}
}

func TestPolicyGroupDelete(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "PUT", base+"/policy_groups/staging/policies/appserver", sampleRevision)

	resp, _ := do(t, "DELETE", base+"/policy_groups/staging", "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete group = %d", resp.StatusCode)
	}
	resp, _ = do(t, "GET", base+"/policy_groups/staging", "")
	if resp.StatusCode != 404 {
		t.Fatalf("get deleted group = %d", resp.StatusCode)
	}
}

func TestPolicyMissing404(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, _ := do(t, "GET", base+"/policies/ghost", "")
	if resp.StatusCode != 404 {
		t.Fatalf("missing policy = %d", resp.StatusCode)
	}
}

// TestPolicyGroupReadShape pins erchef's body for GET and DELETE
// /policy_groups/G (oc_chef_wm_named_policy_group:build_policy_revisions_json):
// "policies" then "uri", and nothing else, whether the group was created by a
// deploy PUT or loaded from a chef-repo file that carries "name" and an empty
// "uri".
func TestPolicyGroupReadShape(t *testing.T) {
	srv, st := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	const rev = "1111111111111111111111111111111111111111111111111111111111111111"

	org, _, _ := st.Org("acme")
	if err := org.Put("policy_groups", "loaded",
		[]byte(`{"name":"loaded","uri":"","policies":{"web":{"revision_id":"1.0.0"},"db":{"revision_id":"2.0.0"}}}`)); err != nil {
		t.Fatal(err)
	}
	do(t, "PUT", base+"/policy_groups/pushed/policies/appserver", sampleRevision)

	cases := []struct{ group, want string }{
		{"loaded", `{"policies":{"db":{"revision_id":"2.0.0"},"web":{"revision_id":"1.0.0"}},"uri":"` + base + `/policy_groups/loaded"}`},
		{"pushed", `{"policies":{"appserver":{"revision_id":"` + rev + `"}},"uri":"` + base + `/policy_groups/pushed"}`},
	}
	for _, c := range cases {
		for _, method := range []string{"GET", "DELETE"} {
			resp, body := do(t, method, base+"/policy_groups/"+c.group, "")
			if resp.StatusCode != 200 || body != c.want {
				t.Errorf("%s %s = %d %s\nwant %s", method, c.group, resp.StatusCode, body, c.want)
			}
		}
	}
}
