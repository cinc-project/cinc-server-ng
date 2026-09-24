package api

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestSatisfiesConstraint(t *testing.T) {
	cases := []struct {
		version, constraint string
		want                bool
	}{
		{"1.0.0", "", true},
		{"1.0.0", "= 1.0.0", true},
		{"1.0.1", "= 1.0.0", false},
		{"2.0.0", ">= 1.0.0", true},
		{"1.0.0", "> 1.0.0", false},
		{"1.0.0", "<= 1.0.0", true},
		{"0.9.0", "< 1.0.0", true},
		{"1.2.0", "!= 1.0.0", true},
		{"1.2.5", "~> 1.2", true},   // ~> 1.2 => >=1.2.0 <2.0.0
		{"1.3.0", "~> 1.2", true},   // still <2.0.0, allowed
		{"2.0.0", "~> 1.2", false},  // hits the 2.0.0 ceiling
		{"1.2.5", "~> 1.2.0", true}, // ~> 1.2.0 => >=1.2.0 <1.3.0
		{"1.3.0", "~> 1.2.0", false},
	}
	for _, c := range cases {
		if got := satisfiesConstraint(c.version, c.constraint); got != c.want {
			t.Errorf("satisfiesConstraint(%q, %q) = %v, want %v", c.version, c.constraint, got, c.want)
		}
	}
}

// seedCookbook uploads a one-recipe cookbook version with optional metadata
// dependencies (depName may be "").
func seedCookbook(t *testing.T, base, name, version string) {
	t.Helper()
	sum := uploadBlob(t, base, "recipe for "+name+" "+version)
	resp, body := do(t, "PUT", base+"/cookbooks/"+name+"/"+version, manifest(name, version, sum))
	if resp.StatusCode >= 300 {
		t.Fatalf("seed cookbook %s/%s = %d: %s", name, version, resp.StatusCode, body)
	}
}

func TestEnvironmentCookbookFiltering(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	seedCookbook(t, base, "apache2", "1.0.0")
	seedCookbook(t, base, "apache2", "2.0.0")
	seedCookbook(t, base, "nginx", "1.0.0")

	// An environment that pins apache2 to exactly 1.0.0.
	do(t, "POST", base+"/environments",
		`{"name":"prod","cookbook_versions":{"apache2":"= 1.0.0"}}`)

	// Filtered list: apache2 limited to 1.0.0, nginx unconstrained.
	_, body := do(t, "GET", base+"/environments/prod/cookbooks", "")
	var list map[string]struct {
		Versions []struct {
			Version string `json:"version"`
		} `json:"versions"`
	}
	json.Unmarshal([]byte(body), &list)
	if len(list["apache2"].Versions) != 1 || list["apache2"].Versions[0].Version != "1.0.0" {
		t.Fatalf("apache2 not filtered to 1.0.0: %s", body)
	}
	if len(list["nginx"].Versions) != 1 {
		t.Fatalf("nginx should be unconstrained: %s", body)
	}

	// _default has no constraints: apache2 shows both versions.
	_, body = do(t, "GET", base+"/environments/_default/cookbooks/apache2", "")
	json.Unmarshal([]byte(body), &list)
	if len(list["apache2"].Versions) != 2 {
		t.Fatalf("_default apache2 should have 2 versions: %s", body)
	}

	// Missing environment 404s.
	resp, _ := do(t, "GET", base+"/environments/ghost/cookbooks", "")
	if resp.StatusCode != 404 {
		t.Fatalf("missing env cookbooks = %d, want 404", resp.StatusCode)
	}
}

func TestEnvironmentRecipesAndNodes(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	seedCookbook(t, base, "apache2", "1.0.0")
	do(t, "POST", base+"/environments", `{"name":"prod"}`)
	do(t, "POST", base+"/nodes", `{"name":"web01","chef_environment":"prod"}`)
	do(t, "POST", base+"/nodes", `{"name":"web02","chef_environment":"staging"}`)

	_, body := do(t, "GET", base+"/environments/prod/recipes", "")
	var recipes []string
	json.Unmarshal([]byte(body), &recipes)
	if len(recipes) == 0 || recipes[0] != "apache2" {
		t.Fatalf("env recipes = %s", body)
	}

	_, body = do(t, "GET", base+"/environments/prod/nodes", "")
	var nodes map[string]string
	json.Unmarshal([]byte(body), &nodes)
	if _, ok := nodes["web01"]; !ok {
		t.Fatalf("prod nodes should include web01: %s", body)
	}
	if _, ok := nodes["web02"]; ok {
		t.Fatalf("prod nodes should not include staging node web02: %s", body)
	}
}

func TestEnvironmentCookbookVersionsDepsolve(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	seedCookbook(t, base, "apache2", "1.0.0")
	seedCookbook(t, base, "apache2", "2.0.0")
	do(t, "POST", base+"/environments", `{"name":"prod","cookbook_versions":{"apache2":"= 1.0.0"}}`)

	_, body := do(t, "POST", base+"/environments/prod/cookbook_versions",
		`{"run_list":["recipe[apache2]"]}`)
	var solved map[string]map[string]any
	json.Unmarshal([]byte(body), &solved)
	cb, ok := solved["apache2"]
	if !ok {
		t.Fatalf("depsolve missing apache2: %s", body)
	}
	if cb["version"] != "1.0.0" {
		t.Fatalf("depsolve picked wrong version (env pins 1.0.0): %s", body)
	}
}

func TestRoleEnvironments(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	do(t, "POST", base+"/environments", `{"name":"prod"}`)
	do(t, "POST", base+"/roles",
		`{"name":"web","run_list":["recipe[apache2]"],"env_run_lists":{"prod":["recipe[nginx]"]}}`)

	// The role advertises _default plus any env_run_lists keys.
	_, body := do(t, "GET", base+"/roles/web/environments", "")
	var envs []string
	json.Unmarshal([]byte(body), &envs)
	if !slices.Contains(envs, "_default") || !slices.Contains(envs, "prod") {
		t.Fatalf("role environments = %s", body)
	}

	// _default returns the base run_list.
	_, body = do(t, "GET", base+"/roles/web/environments/_default", "")
	var rl struct {
		RunList []string `json:"run_list"`
	}
	json.Unmarshal([]byte(body), &rl)
	if len(rl.RunList) != 1 || rl.RunList[0] != "recipe[apache2]" {
		t.Fatalf("_default run_list = %s", body)
	}

	// A named env returns its env_run_list.
	_, body = do(t, "GET", base+"/roles/web/environments/prod", "")
	json.Unmarshal([]byte(body), &rl)
	if len(rl.RunList) != 1 || rl.RunList[0] != "recipe[nginx]" {
		t.Fatalf("prod run_list = %s", body)
	}

	// The environment-scoped role endpoint mirrors the env run list.
	_, body = do(t, "GET", base+"/environments/prod/roles/web", "")
	json.Unmarshal([]byte(body), &rl)
	if len(rl.RunList) != 1 || rl.RunList[0] != "recipe[nginx]" {
		t.Fatalf("env/prod/roles/web run_list = %s", body)
	}
}
