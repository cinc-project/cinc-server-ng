package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/cinc-project/cinc-server-ng/internal/chefjson"
	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Environment- and role-scoped sub-endpoints: cookbook filtering by an
// environment's version constraints, a simplified dependency solver, recipe and
// node listings, and per-environment role run lists.

func (a *API) registerEnvironmentSubRoutes(mux *recordingMux) {
	const e = "/organizations/{org}/environments/{env}"
	mux.HandleFunc("GET "+e+"/cookbooks", a.envCookbooks)
	mux.HandleFunc("GET "+e+"/cookbooks/{name}", a.envCookbook)
	mux.HandleFunc("POST "+e+"/cookbook_versions", a.envCookbookVersions)
	mux.HandleFunc("GET "+e+"/recipes", a.envRecipes)
	mux.HandleFunc("GET "+e+"/nodes", a.envNodes)
	mux.HandleFunc("GET "+e+"/roles/{role}", a.envRole)

	const r = "/organizations/{org}/roles/{role}"
	mux.HandleFunc("GET "+r+"/environments", a.roleEnvironments)
	mux.HandleFunc("GET "+r+"/environments/{env}", a.roleEnvironment)
}

// envExists reports whether an environment exists. The "_default" environment
// is guaranteed by Chef to always exist, even if it was never explicitly stored.
func envExists(org *store.Org, env string) (bool, error) {
	if env == "_default" {
		return true, nil
	}
	_, ok, err := org.Get("environments", env)
	return ok, err
}

// envConstraints returns the environment's cookbook version constraints. The
// bool is false only when the environment does not exist; "_default" always
// exists and carries no constraints unless one was explicitly stored.
func envConstraints(org *store.Org, env string) (map[string]string, bool, error) {
	raw, ok, err := org.Get("environments", env)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, env == "_default", nil
	}
	var doc struct {
		CookbookVersions map[string]string `json:"cookbook_versions"`
	}
	if err := chefjson.Unmarshal(raw, &doc); err != nil {
		return nil, false, err
	}
	return doc.CookbookVersions, true, nil
}

// filteredCookbookVersions returns cookbook -> versions (newest first) limited
// to versions satisfying the environment's constraint for that cookbook.
func filteredCookbookVersions(org *store.Org, constraints map[string]string) (map[string][]string, error) {
	cv, err := cookbookVersions(org)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for name, versions := range cv {
		constraint := constraints[name]
		var kept []string
		for _, v := range versions {
			if satisfiesConstraint(v, constraint) {
				kept = append(kept, v)
			}
		}
		if len(kept) > 0 {
			out[name] = kept
		}
	}
	return out, nil
}

func (a *API) envCookbooks(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	// Every cookbook in an environment defaults to its newest version; one
	// cookbook defaults to all (chef_wm_environment_cookbooks:validate_request).
	// Validated before the environment is looked up, as erchef does.
	limit, ok := numVersions(w, r, 1)
	if !ok {
		return
	}
	constraints, ok, err := envConstraints(org, r.PathValue("env"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find environment "+r.PathValue("env"))
		return
	}
	fcv, err := filteredCookbookVersions(org, constraints)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, collectionListBody(r, org, "cookbooks", "version", fcv, limit))
}

func (a *API) envCookbook(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	limit, ok := numVersions(w, r, allVersions)
	if !ok {
		return
	}
	constraints, ok, err := envConstraints(org, r.PathValue("env"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find environment "+r.PathValue("env"))
		return
	}
	name := r.PathValue("name")
	all, err := filteredCookbookVersions(org, constraints)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	versions, ok := all[name]
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find a cookbook named "+name)
		return
	}
	writeJSON(w, http.StatusOK, collectionListBody(r, org, "cookbooks", "version", map[string][]string{name: versions}, limit))
}

func (a *API) envRecipes(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	constraints, ok, err := envConstraints(org, r.PathValue("env"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find environment "+r.PathValue("env"))
		return
	}
	fcv, err := filteredCookbookVersions(org, constraints)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	seen := map[string]bool{}
	var recipes []string
	for name, versions := range fcv {
		raw, ok, err := org.Get("cookbooks", cookbookKey(name, versions[0])) // newest first
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			continue
		}
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		for _, rec := range manifestRecipes(m, name) {
			if !seen[rec] {
				seen[rec] = true
				recipes = append(recipes, rec)
			}
		}
	}
	sort.Strings(recipes)
	writeJSON(w, http.StatusOK, recipes)
}

func (a *API) envNodes(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	env := r.PathValue("env")
	exists, err := envExists(org, env)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !exists {
		writeError(w, http.StatusNotFound, "Cannot find environment "+env)
		return
	}
	out := map[string]string{}
	var decodeErr error
	if err := org.Range("nodes", func(name string, raw []byte) bool {
		var node struct {
			ChefEnvironment string `json:"chef_environment"`
		}
		if err := chefjson.Unmarshal(raw, &node); err != nil {
			decodeErr = err
			return false
		}
		nodeEnv := node.ChefEnvironment
		if nodeEnv == "" {
			nodeEnv = "_default"
		}
		if nodeEnv == env {
			out[name] = objectURL(r, org.Name(), "nodes", name)
		}
		return true
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if decodeErr != nil {
		writeError(w, http.StatusInternalServerError, decodeErr.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// envCookbookVersions is a simplified dependency solver: for each cookbook named
// in the run list it picks the newest version satisfying the environment's
// constraint (or the version an "@" item pins), then recursively pulls in metadata dependencies (by name, also
// honoring environment constraints). Dependency-level version constraints
// beyond the environment's are not solved. Returns 412 if a cookbook cannot be
// satisfied.
func (a *API) envCookbookVersions(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	constraints, ok, err := envConstraints(org, r.PathValue("env"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find environment "+r.PathValue("env"))
		return
	}
	var body struct {
		RunList []string `json:"run_list"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	all, err := cookbookVersions(org)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	available, err := filteredCookbookVersions(org, constraints)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// erchef first refuses run list cookbooks with no version at all, then
	// (in dep_selector) items no version satisfies under the environment's
	// constraints and the item's own pin, each reported in full.
	items := depsolverRunListItems(body.RunList)
	var missing []string
	for _, it := range items {
		if len(all[it.cookbook]) == 0 {
			missing = append(missing, it.cookbook)
		}
	}
	if len(missing) > 0 {
		writeDepsolverError(w, depsolverNotFound(missing))
		return
	}
	pinned := map[string]string{}
	queue := make([]string, 0, len(items))
	var unmet []string
	for _, it := range items {
		versions := available[it.cookbook]
		if it.version != "" {
			versions = slices.DeleteFunc(slices.Clone(versions), func(v string) bool {
				return compareVersions(v, it.version) != 0
			})
		}
		if len(versions) == 0 {
			unmet = append(unmet, it.solutionConstraint())
			continue
		}
		if it.version != "" {
			if _, ok := pinned[it.cookbook]; !ok {
				pinned[it.cookbook] = versions[0]
			}
		}
		queue = append(queue, it.cookbook)
	}
	if len(unmet) > 0 {
		writeDepsolverError(w, depsolverConstraintsNotMet(unmet))
		return
	}

	solved := map[string]any{}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if name == "" || solved[name] != nil {
			continue
		}
		versions := available[name]
		if v, ok := pinned[name]; ok {
			versions = []string{v}
		}
		if len(versions) == 0 {
			writeError(w, http.StatusPreconditionFailed,
				"Run list contains invalid items: no versions match the constraints on cookbook "+name+".")
			return
		}
		raw, ok, err := org.Get("cookbooks", cookbookKey(name, versions[0]))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusPreconditionFailed, "Cannot find cookbook "+name)
			return
		}
		m, err := chefjson.DecodeObject(raw)
		if err != nil {
			continue
		}
		solved[name] = json.RawMessage(a.withFileURLs(raw, r, org.Name()))
		for dep := range manifestDependencies(m) {
			queue = append(queue, dep)
		}
	}
	denied, err := a.unreadableCookbooks(r, org, solved)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(denied) > 0 {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": []any{map[string]any{
			"message":                "Read permission is not granted for one or more cookbooks",
			"unauthorized_cookbooks": denied,
		}}})
		return
	}
	writeJSON(w, http.StatusOK, solved)
}

// unreadableCookbooks returns, sorted, the cookbooks of a solution the
// request's actor may not read. erchef checks every one before answering
// (oc_chef_wm_base:check_cookbook_authz), so a solution can't hand out the
// manifest, and the file URLs in it, of a cookbook the caller couldn't fetch
// directly, even one pulled in only as a dependency.
func (a *API) unreadableCookbooks(r *http.Request, org *store.Org, solved map[string]any) ([]string, error) {
	if !a.enforceACL {
		return nil, nil
	}
	actor, ok := actorFromContext(r.Context())
	if !ok || actor.IsGlobalAdmin {
		return nil, nil
	}
	var denied []string
	for name := range solved {
		allowed, err := a.actorAllowed(org, actor, "cookbooks", name, "read")
		if err != nil {
			return nil, err
		}
		if !allowed {
			denied = append(denied, name)
		}
	}
	sort.Strings(denied)
	return denied, nil
}

func (a *API) envRole(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	exists, err := envExists(org, r.PathValue("env"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !exists {
		writeError(w, http.StatusNotFound, "Cannot find environment "+r.PathValue("env"))
		return
	}
	role, ok := loadRole(w, org, r.PathValue("role"))
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run_list": roleRunList(role, r.PathValue("env"))})
}

func (a *API) roleEnvironments(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	role, ok := loadRole(w, org, r.PathValue("role"))
	if !ok {
		return
	}
	envs := []string{"_default"}
	if erl, ok := role["env_run_lists"].(map[string]any); ok {
		for name := range erl {
			if name != "_default" {
				envs = append(envs, name)
			}
		}
	}
	sort.Strings(envs)
	writeJSON(w, http.StatusOK, envs)
}

func (a *API) roleEnvironment(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	role, ok := loadRole(w, org, r.PathValue("role"))
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run_list": roleRunList(role, r.PathValue("env"))})
}

func loadRole(w http.ResponseWriter, org *store.Org, name string) (map[string]any, bool) {
	raw, ok, err := org.Get("roles", name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find role "+name)
		return nil, false
	}
	role, err := chefjson.DecodeObject(raw)
	if err != nil {
		return nil, false
	}
	return role, true
}

// roleRunList returns the role's run list for env: its env_run_lists entry if
// present, otherwise the base run_list (always used for _default).
func roleRunList(role map[string]any, env string) []any {
	if env != "_default" {
		if erl, ok := role["env_run_lists"].(map[string]any); ok {
			if rl, ok := erl[env].([]any); ok {
				return rl
			}
		}
	}
	if rl, ok := role["run_list"].([]any); ok {
		return rl
	}
	return []any{}
}

// depsolverItem is one run list item as erchef's depsolver reads it: a
// cookbook name and, for a "name@version" item, the exact version it pins.
type depsolverItem struct {
	cookbook, version string
}

// solutionConstraint is the item as dep_selector prints a SolutionConstraint
// ("(name op version)"), which is how erchef names it in a 412: an unversioned
// item is ">= 0.0.0", a pinned one "= X.Y.Z".
func (it depsolverItem) solutionConstraint() string {
	if it.version == "" {
		return "(" + it.cookbook + " >= 0.0.0)"
	}
	v := it.version
	if strings.Count(v, ".") == 1 {
		v += ".0"
	}
	return "(" + it.cookbook + " = " + v + ")"
}

// depsolverRunListItems parses run list items as
// chef_wm_depsolver:cookbooks_for_runlist does: split on "@" for a version,
// then on "::" for the cookbook, and nothing else. A "recipe[apache2]" or
// "role[web]" item is a cookbook literally named that (chef-client expands
// roles and sends bare recipe names). Duplicates are dropped, keeping the
// first, as remove_dups does.
func depsolverRunListItems(runList []string) []depsolverItem {
	var out []depsolverItem
	seen := map[depsolverItem]bool{}
	for _, item := range runList {
		recipe, version, _ := strings.Cut(item, "@")
		name, _, _ := strings.Cut(recipe, "::")
		it := depsolverItem{cookbook: name, version: version}
		if !seen[it] {
			seen[it] = true
			out = append(out, it)
		}
	}
	return out
}

// depsolverFailure is the object erchef puts in a depsolver 412's error list.
type depsolverFailure struct {
	Message                 string   `json:"message"`
	NonExistentCookbooks    []string `json:"non_existent_cookbooks"`
	CookbooksWithNoVersions []string `json:"cookbooks_with_no_versions"`
}

func writeDepsolverError(w http.ResponseWriter, f depsolverFailure) {
	writeJSON(w, http.StatusPreconditionFailed, map[string]any{"error": []any{f}})
}

// depsolverNotFound is chef_wm_depsolver:not_found_message(cookbook_version,
// Names): run list cookbooks with no version at all, in run list order.
func depsolverNotFound(names []string) depsolverFailure {
	msg := "Run list contains invalid items: no such cookbook " + names[0] + "."
	if len(names) > 1 {
		msg = "Run list contains invalid items: no such cookbooks " + strings.Join(names, ", ") + "."
	}
	return depsolverFailure{Message: msg, NonExistentCookbooks: names, CookbooksWithNoVersions: []string{}}
}

// depsolverConstraintsNotMet is chef_wm_depsolver:invalid_constraints_message
// for run list items no version satisfies once the environment's constraints
// and the item's pin apply.
func depsolverConstraintsNotMet(constraints []string) depsolverFailure {
	msg := "Run list contains invalid items: no versions match the constraints on cookbook " + constraints[0] + "."
	if len(constraints) > 1 {
		msg = "Run list contains invalid items: no versions match the constraints on cookbooks " +
			strings.Join(constraints, ", ") + "."
	}
	return depsolverFailure{Message: msg, NonExistentCookbooks: []string{}, CookbooksWithNoVersions: constraints}
}
