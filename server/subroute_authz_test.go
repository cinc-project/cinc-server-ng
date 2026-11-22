package server

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// The routes nested under an environment or role, and /universe, are checked
// the way erchef checks them:
//
//   - POST /environments/{e}/cookbook_versions (chef_wm_depsolver): read on
//     the cookbooks container and on the environment, then read on every
//     cookbook in the solution (oc_chef_wm_base:check_cookbook_authz).
//   - GET /environments/{e}/cookbooks[/{c}] (chef_wm_environment_cookbooks)
//     and /environments/{e}/recipes (chef_wm_environment_recipes): read on
//     the environment.
//   - GET /environments/{e}/nodes (chef_wm_nodes): read on the nodes
//     container.
//   - GET /environments/{e}/roles/{r}, /roles/{r}/environments[/{e}]
//     (chef_wm_environment_roles, chef_wm_named_role): read on the role.
//   - GET /universe (chef_wm_universe): read on the cookbooks container.

// narrowRead leaves read on the object at path (relative to the org) to the
// admins alone.
func narrowRead(t *testing.T, srv *Server, base, path string) {
	t.Helper()
	mustStatus(t, signed(t, srv, "PUT", base+"/"+path+"/_acl/read",
		`{"read":{"actors":[],"groups":["admins"]}}`), http.StatusOK)
}

// cookbookDependingOn is a cookbook manifest whose metadata depends on deps.
func cookbookDependingOn(name, version string, deps ...string) string {
	d := ""
	for i, dep := range deps {
		if i > 0 {
			d += ","
		}
		d += fmt.Sprintf("%q:%q", dep, ">= 0.0.0")
	}
	return fmt.Sprintf(`{"name":"%s-%s","cookbook_name":"%s","version":"%s",`+
		`"metadata":{"version":"%s","dependencies":{%s}}}`, name, version, name, version, version, d)
}

// subrouteSetup is memberSetup plus an environment, a role and a cookbook.
func subrouteSetup(t *testing.T) (*Server, string, []byte) {
	t.Helper()
	srv, base, bob := memberSetup(t)
	mustStatus(t, signed(t, srv, "POST", base+"/environments", `{"name":"staging"}`), http.StatusCreated)
	mustStatus(t, signed(t, srv, "POST", base+"/roles", `{"name":"web","run_list":["recipe[apache]"]}`), http.StatusCreated)
	mustStatus(t, signed(t, srv, "PUT", base+"/cookbooks/apache/1.0.0", cookbook("apache", "1.0.0")), http.StatusCreated)
	return srv, base, bob
}

const solveApache = `{"run_list":["apache"]}`

func TestEnvironmentSubRoutesNeedReadOnEnvironment(t *testing.T) {
	srv, base, bob := subrouteSetup(t)
	env := base + "/environments/staging"
	reads := []string{env + "/cookbooks", env + "/cookbooks/apache", env + "/recipes"}
	for _, u := range reads {
		mustStatus(t, signedAs(t, "bob", bob, "GET", u, ""), http.StatusOK)
	}
	mustStatus(t, signedAs(t, "bob", bob, "POST", env+"/cookbook_versions", solveApache), http.StatusOK)

	narrowRead(t, srv, base, "environments/staging")
	mustStatus(t, signedAs(t, "bob", bob, "GET", env, ""), http.StatusForbidden) // baseline
	for _, u := range reads {
		mustStatus(t, signedAs(t, "bob", bob, "GET", u, ""), http.StatusForbidden)
		mustStatus(t, signed(t, srv, "GET", u, ""), http.StatusOK)
	}
	mustStatus(t, signedAs(t, "bob", bob, "POST", env+"/cookbook_versions", solveApache), http.StatusForbidden)
	mustStatus(t, signed(t, srv, "POST", env+"/cookbook_versions", solveApache), http.StatusOK)
	// A missing environment, or named cookbook, is a 404 before it is a 403.
	mustStatus(t, signedAs(t, "bob", bob, "GET", env+"/cookbooks/nope", ""), http.StatusNotFound)
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/environments/nope/recipes", ""), http.StatusNotFound)
}

func TestEnvironmentCookbooksIgnoreCookbooksContainer(t *testing.T) {
	// chef_wm_environment_cookbooks checks the environment alone.
	srv, base, bob := subrouteSetup(t)
	narrowRead(t, srv, base, "containers/cookbooks")
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/cookbooks", ""), http.StatusForbidden) // baseline
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/environments/staging/cookbooks", ""), http.StatusOK)
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/environments/staging/cookbooks/apache", ""), http.StatusOK)
}

func TestDepsolverAndUniverseNeedReadOnCookbooksContainer(t *testing.T) {
	srv, base, bob := subrouteSetup(t)
	solve := base + "/environments/_default/cookbook_versions"
	mustStatus(t, signedAs(t, "bob", bob, "POST", solve, solveApache), http.StatusOK)
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/universe", ""), http.StatusOK)

	narrowRead(t, srv, base, "containers/cookbooks")
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/cookbooks", ""), http.StatusForbidden) // baseline
	mustStatus(t, signedAs(t, "bob", bob, "POST", solve, solveApache), http.StatusForbidden)
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/universe", ""), http.StatusForbidden)
	mustStatus(t, signed(t, srv, "POST", solve, solveApache), http.StatusOK)
	mustStatus(t, signed(t, srv, "GET", base+"/universe", ""), http.StatusOK)
}

func TestDepsolverNeedsReadOnEverySolvedCookbook(t *testing.T) {
	srv, base, bob := subrouteSetup(t)
	mustStatus(t, signed(t, srv, "PUT", base+"/cookbooks/secret/1.0.0", cookbook("secret", "1.0.0")), http.StatusCreated)
	mustStatus(t, signed(t, srv, "PUT", base+"/cookbooks/app/1.0.0", cookbookDependingOn("app", "1.0.0", "secret")), http.StatusCreated)
	solve := base + "/environments/_default/cookbook_versions"
	mustStatus(t, signedAs(t, "bob", bob, "POST", solve, `{"run_list":["app"]}`), http.StatusOK)

	narrowRead(t, srv, base, "cookbooks/secret")
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/cookbooks/secret/1.0.0", ""), http.StatusForbidden) // baseline

	// secret is reached only as a dependency of app, and still refused, with
	// erchef's body naming it.
	code, body := signedBody(t, signedAs(t, "bob", bob, "POST", solve, `{"run_list":["app"]}`))
	if code != http.StatusForbidden {
		t.Fatalf("solve app = %d, want 403: %s", code, body)
	}
	const want = `{"error":[{"message":"Read permission is not granted for one or more cookbooks","unauthorized_cookbooks":["secret"]}]}`
	if got := strings.TrimSuffix(string(body), "\n"); got != want {
		t.Fatalf("solve app body = %s, want %s", got, want)
	}
	// A solution that doesn't include it is unaffected, and the admins can
	// still solve it.
	mustStatus(t, signedAs(t, "bob", bob, "POST", solve, solveApache), http.StatusOK)
	mustStatus(t, signed(t, srv, "POST", solve, `{"run_list":["app"]}`), http.StatusOK)
}

func TestEnvironmentNodesNeedReadOnNodesContainer(t *testing.T) {
	// dispatch.conf routes /environments/{e}/nodes to chef_wm_nodes, which
	// checks the nodes container, not the environment.
	srv, base, bob := subrouteSetup(t)
	u := base + "/environments/staging/nodes"
	mustStatus(t, signedAs(t, "bob", bob, "GET", u, ""), http.StatusOK)

	narrowRead(t, srv, base, "environments/staging")
	mustStatus(t, signedAs(t, "bob", bob, "GET", u, ""), http.StatusOK)

	narrowRead(t, srv, base, "containers/nodes")
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/nodes", ""), http.StatusForbidden) // baseline
	mustStatus(t, signedAs(t, "bob", bob, "GET", u, ""), http.StatusForbidden)
	mustStatus(t, signed(t, srv, "GET", u, ""), http.StatusOK)
}

func TestRoleEnvironmentRoutesNeedReadOnRole(t *testing.T) {
	srv, base, bob := subrouteSetup(t)
	reads := []string{
		base + "/environments/staging/roles/web",
		base + "/roles/web/environments/staging",
		base + "/roles/web/environments",
	}
	for _, u := range reads {
		mustStatus(t, signedAs(t, "bob", bob, "GET", u, ""), http.StatusOK)
	}

	narrowRead(t, srv, base, "roles/web")
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/roles/web", ""), http.StatusForbidden) // baseline
	for _, u := range reads {
		mustStatus(t, signedAs(t, "bob", bob, "GET", u, ""), http.StatusForbidden)
		mustStatus(t, signed(t, srv, "GET", u, ""), http.StatusOK)
	}
	// A missing role or environment is a 404 before it is a 403.
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/roles/nope/environments", ""), http.StatusNotFound)
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/roles/web/environments/nope", ""), http.StatusNotFound)
	mustStatus(t, signedAs(t, "bob", bob, "GET", base+"/environments/nope/roles/web", ""), http.StatusNotFound)
}

// A node's client, registered through the validator, must still be able to
// solve its run list and download the files of the solution: the chef-client
// converge path.
func TestNodeClientSolvesRunListAndDownloadsFiles(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	const recipe = "package 'nginx'\n"
	sum := md5.Sum([]byte(recipe))
	checksum := hex.EncodeToString(sum[:])
	if code, body := rawRequest(t, "PUT", sandboxUploadURL(t, srv, checksum), recipe); code != http.StatusOK {
		t.Fatalf("upload = %d: %s", code, body)
	}
	manifest := `{"name":"nginx-1.0.0","cookbook_name":"nginx","version":"1.0.0","metadata":{"version":"1.0.0"},` +
		`"all_files":[{"name":"recipes/default.rb","path":"recipes/default.rb","checksum":"` + checksum + `","specificity":"default"}]}`
	mustStatus(t, signedAt(t, srv, "2", "PUT", base+"/cookbooks/nginx/1.0.0", manifest), http.StatusCreated)

	key := createClientAndKey(t, srv, base, "node1")
	mustStatus(t, signedAs(t, "node1", key, "POST", base+"/nodes", `{"name":"node1"}`), http.StatusCreated)
	code, raw := signedBody(t, signedAs(t, "node1", key, "POST",
		base+"/environments/_default/cookbook_versions", `{"run_list":["recipe[nginx]"]}`))
	if code != http.StatusOK {
		t.Fatalf("solve = %d, want 200: %s", code, raw)
	}
	var solved map[string]struct {
		Recipes []struct {
			URL string `json:"url"`
		} `json:"recipes"`
	}
	if err := json.Unmarshal(raw, &solved); err != nil || len(solved["nginx"].Recipes) != 1 {
		t.Fatalf("decode solution: %v: %s", err, raw)
	}
	code, body := rawRequest(t, "GET", solved["nginx"].Recipes[0].URL, "")
	if code != http.StatusOK || string(body) != recipe {
		t.Fatalf("download = %d %q, want 200 %q", code, body, recipe)
	}
}
