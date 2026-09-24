package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// validPolicyLock is erchef's minimum_valid_policy_payload (oc-chef-pedant
// policies/complete_endpoint_spec.rb) for a policy named "some_policy_name".
func validPolicyLock() map[string]any {
	return map[string]any{
		"revision_id": "909c26701e291510eacdc6c06d626b9fa5350d25",
		"name":        "some_policy_name",
		"run_list":    []any{"recipe[policyfile_demo::default]"},
		"cookbook_locks": map[string]any{
			"policyfile_demo": map[string]any{
				"identifier": "f04cc40faf628253fe7d9566d66a1733fb1afbe9",
				"version":    "1.2.3",
			},
		},
	}
}

func policyLockJSON(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	doc := validPolicyLock()
	if mutate != nil {
		mutate(doc)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func lockOf(doc map[string]any) map[string]any {
	return doc["cookbook_locks"].(map[string]any)["policyfile_demo"].(map[string]any)
}

// TestPolicyRevisionValidation holds PUT /policy_groups/G/policies/P and
// POST /policies/P/revisions to erchef's oc_chef_policy_revision validation:
// a bad document is a 400 with erchef's message, and nothing is stored.
func TestPolicyRevisionValidation(t *testing.T) {
	long := strings.Repeat("a", 256)
	cases := []struct {
		name   string
		policy string // URL policy name; defaults to some_policy_name
		mutate func(map[string]any)
		want   string
	}{
		{"missing revision_id", "", func(d map[string]any) { delete(d, "revision_id") }, "Field 'revision_id' missing"},
		{"empty revision_id", "", func(d map[string]any) { d["revision_id"] = "" }, "Field 'revision_id' invalid"},
		{"long revision_id", "", func(d map[string]any) { d["revision_id"] = long }, "Field 'revision_id' invalid"},
		{"revision_id with a space", "", func(d map[string]any) { d["revision_id"] = "not a revision!" }, "Field 'revision_id' invalid"},
		{"revision_id with +", "", func(d map[string]any) { d["revision_id"] = "invalid+invalid" }, "Field 'revision_id' invalid"},
		{"revision_id not a string", "", func(d map[string]any) { d["revision_id"] = 12 }, "Field 'revision_id' invalid"},
		{"missing name", "", func(d map[string]any) { delete(d, "name") }, "Field 'name' missing"},
		{"mismatched name", "", func(d map[string]any) { d["name"] = "monkeypants" },
			"Field 'name' invalid : some_policy_name does not match monkeypants"},
		{"long name", long, func(d map[string]any) { d["name"] = long }, "Field 'name' invalid"},
		{"name with !", "invalid!invalid", func(d map[string]any) { d["name"] = "invalid!invalid" }, "Field 'name' invalid"},
		{"missing run_list", "", func(d map[string]any) { delete(d, "run_list") }, "Field 'run_list' missing"},
		{"run_list not an array", "", func(d map[string]any) { d["run_list"] = map[string]any{} }, "Field 'run_list' is not a valid run list"},
		{"run_list number", "", func(d map[string]any) { d["run_list"] = []any{123} }, "Field 'run_list' is not a valid run list"},
		{"run_list recipe[", "", func(d map[string]any) { d["run_list"] = []any{"recipe["} }, "Field 'run_list' is not a valid run list"},
		{"run_list role", "", func(d map[string]any) { d["run_list"] = []any{"role[foo]"} }, "Field 'run_list' is not a valid run list"},
		{"run_list unqualified recipe", "", func(d map[string]any) { d["run_list"] = []any{"recipe[foo]"} }, "Field 'run_list' is not a valid run list"},
		{"missing cookbook_locks", "", func(d map[string]any) { delete(d, "cookbook_locks") }, "Field 'cookbook_locks' missing"},
		{"cookbook_locks not an object", "", func(d map[string]any) { d["cookbook_locks"] = []any{} }, "Field 'cookbook_locks' invalid"},
		{"cookbook_locks entry not an object", "", func(d map[string]any) {
			d["cookbook_locks"].(map[string]any)["invalid_member"] = []any{}
		}, "Field 'cookbook_locks' invalid"},
		{"cookbook_locks bad cookbook name", "", func(d map[string]any) {
			d["cookbook_locks"].(map[string]any)["bad name"] = lockOf(d)
		}, "Field 'cookbook_locks' invalid"},
		{"lock missing identifier", "", func(d map[string]any) {
			d["cookbook_locks"].(map[string]any)["invalid_member"] = map[string]any{"dotted_decimal_identifier": "1.2.3"}
		}, "Field 'identifier' missing"},
		{"lock long identifier", "", func(d map[string]any) { lockOf(d)["identifier"] = long }, "Field 'identifier' invalid"},
		{"lock bad dotted_decimal_identifier", "", func(d map[string]any) {
			d["cookbook_locks"].(map[string]any)["invalid_member"] = map[string]any{
				"identifier": "123def", "version": "1.2.3", "dotted_decimal_identifier": "foo"}
		}, "Field 'dotted_decimal_identifier' is not a valid version"},
		{"lock missing version", "", func(d map[string]any) { delete(lockOf(d), "version") }, "Field 'version' missing"},
		{"lock bad version", "", func(d map[string]any) { lockOf(d)["version"] = "1.2.3.4" }, "Field 'version' is not a valid version"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := newTestAPI(t)
			base := srv.URL + "/organizations/acme"
			policy := c.policy
			if policy == "" {
				policy = "some_policy_name"
			}
			body := policyLockJSON(t, c.mutate)
			for _, req := range []struct{ method, path string }{
				{"PUT", "/policy_groups/some_policy_group/policies/" + policy},
				{"POST", "/policies/" + policy + "/revisions"},
			} {
				resp, got := do(t, req.method, base+req.path, body)
				if resp.StatusCode != http.StatusBadRequest {
					t.Errorf("%s %s = %d, want 400: %s", req.method, req.path, resp.StatusCode, got)
					continue
				}
				var e struct {
					Error []string `json:"error"`
				}
				if err := json.Unmarshal([]byte(got), &e); err != nil || len(e.Error) != 1 || e.Error[0] != c.want {
					t.Errorf("%s %s error = %s, want [%q]", req.method, req.path, got, c.want)
				}
			}
			// Nothing was stored: no policy, and no group.
			if resp, got := do(t, "GET", base+"/policies/"+policy, ""); resp.StatusCode != http.StatusNotFound {
				t.Errorf("policy after refused writes = %d, want 404: %s", resp.StatusCode, got)
			}
			if resp, got := do(t, "GET", base+"/policy_groups/some_policy_group", ""); resp.StatusCode != http.StatusNotFound {
				t.Errorf("group after refused write = %d, want 404: %s", resp.StatusCode, got)
			}
		})
	}
}

// TestPolicyRevisionValidationAccepts: the shapes erchef accepts still are.
func TestPolicyRevisionValidationAccepts(t *testing.T) {
	allChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqurstuvwxyz0123456789-_:."
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"minimum valid", nil},
		{"255-character revision_id", func(d map[string]any) { d["revision_id"] = strings.Repeat("a", 255) }},
		{"revision_id with every valid character", func(d map[string]any) { d["revision_id"] = allChars }},
		{"identifier with every valid character", func(d map[string]any) { lockOf(d)["identifier"] = allChars }},
		{"empty run_list and cookbook_locks", func(d map[string]any) {
			d["run_list"] = []any{}
			d["cookbook_locks"] = map[string]any{}
		}},
		{"dotted_decimal_identifier", func(d map[string]any) { lockOf(d)["dotted_decimal_identifier"] = "1.2.3" }},
		{"two-part version", func(d map[string]any) { lockOf(d)["version"] = "1.2" }},
		{"extra fields", func(d map[string]any) {
			d["solution_dependencies"] = map[string]any{}
			d["named_run_lists"] = map[string]any{}
			lockOf(d)["source_options"] = map[string]any{"path": "."}
		}},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := newTestAPI(t)
			base := srv.URL + "/organizations/acme"
			body := policyLockJSON(t, c.mutate)
			if resp, got := do(t, "PUT", base+"/policy_groups/g/policies/some_policy_name", body); resp.StatusCode >= 300 {
				t.Errorf("PUT = %d: %s", resp.StatusCode, got)
			}
			// A second policy name for the POST, since the PUT stored this revision.
			body = policyLockJSON(t, func(d map[string]any) {
				if c.mutate != nil {
					c.mutate(d)
				}
				d["name"] = "other_policy"
			})
			if resp, got := do(t, "POST", base+"/policies/other_policy/revisions", body); resp.StatusCode != http.StatusCreated {
				t.Errorf("case %d POST = %d: %s", i, resp.StatusCode, got)
			}
		})
	}
}
