package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

// wantError asserts a 400 whose body is erchef's single-message error.
func wantError(t *testing.T, what string, resp *http.Response, body, want string) {
	t.Helper()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("%s = %d, want 400: %s", what, resp.StatusCode, body)
		return
	}
	var e struct {
		Error []string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil || len(e.Error) != 1 || e.Error[0] != want {
		t.Errorf("%s error = %s, want [%q]", what, body, want)
	}
}

func sameJSON(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// TestRoleValidation holds role create and update to erchef's chef_role
// validation: role_name for the name, run_list_spec for run_list and each
// env_run_lists value, environment_name for env_run_lists keys.
func TestRoleValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"name with !", `{"name":"t-role-1234!bad"}`, "Field 'name' invalid"},
		{"name with a space", `{"name":"this+ is bad!!!"}`, "Field 'name' invalid"},
		{"name not a string", `{"name":12}`, "Field 'name' invalid"},
		{"run list item", `{"name":"r","run_list":["not a run list item!"]}`, "Field 'run_list' is not a valid run list"},
		{"run list number", `{"name":"r","run_list":[123]}`, "Field 'run_list' is not a valid run list"},
		{"run list recipe[", `{"name":"r","run_list":["recipe["]}`, "Field 'run_list' is not a valid run list"},
		{"run list bad version", `{"name":"r","run_list":["recipe[foo@1]"]}`, "Field 'run_list' is not a valid run list"},
		{"run list role with cookbook", `{"name":"r","run_list":["role[foo::bar]"]}`, "Field 'run_list' is not a valid run list"},
		{"run list not an array", `{"name":"r","run_list":"recipe[foo]"}`, "Field 'run_list' is not a valid run list"},
		{"env_run_lists not an object", `{"name":"r","env_run_lists":"This is clearly wrong"}`, "Field 'env_run_lists' contains invalid run lists"},
		{"env_run_lists bad item", `{"name":"r","env_run_lists":{"preprod":["recipe[blah]"],"prod":[123]}}`, "Field 'env_run_lists' contains invalid run lists"},
		{"env_run_lists not a list", `{"name":"r","env_run_lists":{"prod":"recipe[blah]"}}`, "Field 'env_run_lists' contains invalid run lists"},
		{"env_run_lists bad environment", `{"name":"r","env_run_lists":{"pr od":["recipe[blah]"]}}`, "Invalid key 'pr od' for env_run_lists"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := newTestAPI(t)
			base := srv.URL + "/organizations/acme"
			resp, body := do(t, "POST", base+"/roles", c.body)
			wantError(t, "POST /roles", resp, body, c.want)
			if resp, body := do(t, "GET", base+"/roles", ""); body != "{}" {
				t.Errorf("roles after a refused create = %d %s, want none", resp.StatusCode, body)
			}
		})
	}

	// On update the name comes from the URL, so check the run list cases
	// against an existing role and make sure it is left unchanged.
	for _, c := range cases[3:] {
		t.Run("update "+c.name, func(t *testing.T) {
			srv, _ := newTestAPI(t)
			base := srv.URL + "/organizations/acme"
			orig := `{"name":"r","description":"valid","run_list":[]}`
			if resp, body := do(t, "POST", base+"/roles", orig); resp.StatusCode != http.StatusCreated {
				t.Fatalf("create = %d: %s", resp.StatusCode, body)
			}
			resp, body := do(t, "PUT", base+"/roles/r", c.body)
			wantError(t, "PUT /roles/r", resp, body, c.want)
			if _, got := do(t, "GET", base+"/roles/r", ""); !sameJSON(got, orig) {
				t.Errorf("role after a refused update = %s, want %s", got, orig)
			}
		})
	}
}

// TestRoleUpdateName: a role PUT may omit the name, but one that names a
// different role is refused (erchef's url_json_name_mismatch).
func TestRoleUpdateName(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	if resp, body := do(t, "POST", base+"/roles", `{"name":"web"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	resp, body := do(t, "PUT", base+"/roles/web", `{"name":"this_is_not_the_same_name_as_before"}`)
	wantError(t, "PUT with another name", resp, body, "Role name mismatch.")
	if resp, body := do(t, "PUT", base+"/roles/web", `{"description":"named by the URL"}`); resp.StatusCode != http.StatusOK {
		t.Errorf("PUT without a name = %d: %s", resp.StatusCode, body)
	}
}

// TestRoleValidationAccepts: the run list shapes erchef accepts still are.
func TestRoleValidationAccepts(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	items := []string{"foo", "foo::bar", "bar::baz@1.0.0", "bar::baz@1.0", "recipe[web]", "recipe[web::default]",
		"recipe[web@1.2.3]", "role[prod]", "recipe", "recipe::foo", "role", "role::bar@1.0.0",
		"recipe[recipe]", "recipe[role]", "role[recipe]", "role[role]", "recipe[.a_b-c]"}
	role := map[string]any{
		"name":          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqurstuvwxyz0123456789-_:",
		"run_list":      items,
		"env_run_lists": map[string]any{"prod": items, "_default": []string{}},
	}
	b, _ := json.Marshal(role)
	if resp, body := do(t, "POST", base+"/roles", string(b)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	if resp, body := do(t, "POST", base+"/roles", `{"name":"bare"}`); resp.StatusCode != http.StatusCreated {
		t.Errorf("create with only a name = %d: %s", resp.StatusCode, body)
	}
}

// TestEnvironmentValidation holds environment create and update to erchef's
// chef_environment validation: environment_name for the name, and
// cookbook_versions keyed by cookbook name with valid version constraints.
func TestEnvironmentValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"missing name", `{"description":"x"}`, "Field 'name' missing"},
		{"empty name", `{"name":""}`, "Field 'name' invalid"},
		{"name with !", `{"name":"abc!123"}`, "Field 'name' invalid"},
		{"name with a space", `{"name":"abc 123"}`, "Field 'name' invalid"},
		{"name with a colon", `{"name":"a:b"}`, "Field 'name' invalid"},
		{"name not ASCII", `{"name":"大爆発"}`, "Field 'name' invalid"},
		{"name not a string", `{"name":1999}`, "Field 'name' invalid"},
		{"cookbook_versions not an object", `{"name":"e","cookbook_versions":"hello"}`, "Field 'cookbook_versions' is not a hash"},
		{"cookbook name with a space", `{"name":"e","cookbook_versions":{"the cookbook":">= 1.0.0"}}`, "Invalid key 'the cookbook' for cookbook_versions"},
		{"empty cookbook name", `{"name":"e","cookbook_versions":{"":">= 1.0.0"}}`, "Invalid key '' for cookbook_versions"},
		{"not a constraint", `{"name":"e","cookbook_versions":{"apache2":"not a constraint"}}`, "Invalid value 'not a constraint' for cookbook_versions"},
		{"four-part version", `{"name":"e","cookbook_versions":{"cookbook":">= 1.0.0.0"}}`, "Invalid value '>= 1.0.0.0' for cookbook_versions"},
		{"no space after operator", `{"name":"e","cookbook_versions":{"cookbook":">=1.0.0"}}`, "Invalid value '>=1.0.0' for cookbook_versions"},
		{"leading space", `{"name":"e","cookbook_versions":{"cookbook":" >= 1.0.0"}}`, "Invalid value ' >= 1.0.0' for cookbook_versions"},
		{"negative part", `{"name":"e","cookbook_versions":{"cookbook":">= 1.-2.3"}}`, "Invalid value '>= 1.-2.3' for cookbook_versions"},
		{"past a bigint", `{"name":"e","cookbook_versions":{"cookbook":">= 1.2.9223372036854775849"}}`, "Invalid value '>= 1.2.9223372036854775849' for cookbook_versions"},
		{"empty constraint", `{"name":"e","cookbook_versions":{"cookbook":""}}`, "Invalid value '' for cookbook_versions"},
		{"null constraint", `{"name":"e","cookbook_versions":{"cookbook":null}}`, "Invalid value 'null' for cookbook_versions"},
		{"number constraint", `{"name":"e","cookbook_versions":{"cookbook":1}}`, "Invalid value '1' for cookbook_versions"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := newTestAPI(t)
			base := srv.URL + "/organizations/acme"
			resp, body := do(t, "POST", base+"/environments", c.body)
			wantError(t, "POST /environments", resp, body, c.want)
			// newTestAPI does not seed _default, so the list starts empty.
			if _, body := do(t, "GET", base+"/environments", ""); body != "{}" {
				t.Errorf("environments after a refused create = %s, want none", body)
			}

			orig := `{"name":"e","description":"valid","cookbook_versions":{}}`
			if resp, body := do(t, "POST", base+"/environments", orig); resp.StatusCode != http.StatusCreated {
				t.Fatalf("create = %d: %s", resp.StatusCode, body)
			}
			resp, body = do(t, "PUT", base+"/environments/e", c.body)
			wantError(t, "PUT /environments/e", resp, body, c.want)
			if _, got := do(t, "GET", base+"/environments/e", ""); !sameJSON(got, orig) {
				t.Errorf("environment after a refused update = %s, want %s", got, orig)
			}
		})
	}
}

// TestEnvironmentValidationAccepts: the shapes erchef accepts still are.
func TestEnvironmentValidationAccepts(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	for _, body := range []string{
		`{"name":"ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-0123456789"}`,
		`{"name":"e1","cookbook_versions":{}}`,
		`{"name":"e2","cookbook_versions":{"cookbook":">= 1.0.0","a":">= 1.0","b":"<= 1.0.0","c":"> 1.0.0","d":"< 1.0.0","e":"= 1.0.0","f":"~> 1.0.0","g":"1.0.0"}}`,
		`{"name":"e3","cookbook_versions":{"cookbook":">= 1.2.20130730201745"}}`,
		`{"name":"e4","cookbook_versions":{"apache2":"~> 1.2.0","nginx":"= 2.0.0"}}`,
	} {
		if resp, got := do(t, "POST", base+"/environments", body); resp.StatusCode != http.StatusCreated {
			t.Errorf("create %s = %d: %s", body, resp.StatusCode, got)
		}
	}
}
