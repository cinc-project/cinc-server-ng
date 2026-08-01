package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/tas50/cinc-zero/internal/store"
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
	json.Unmarshal(raw, &doc)
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
	writeJSON(w, http.StatusOK, collectionListBody(r, org, "cookbooks", "version", fcv))
}

func (a *API) envCookbook(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, collectionListBody(r, org, "cookbooks", "version", map[string][]string{name: versions}))
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
	if err := org.Range("nodes", func(name string, raw []byte) bool {
		var node struct {
			ChefEnvironment string `json:"chef_environment"`
		}
		json.Unmarshal(raw, &node)
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
	writeJSON(w, http.StatusOK, out)
}

// envCookbookVersions is a simplified dependency solver: for each cookbook named
// in the run list it picks the newest version satisfying the environment's
// constraint, then recursively pulls in metadata dependencies (by name, also
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

	available, err := filteredCookbookVersions(org, constraints)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	solved := map[string]any{}
	queue := make([]string, 0, len(body.RunList))
	for _, item := range body.RunList {
		queue = append(queue, cookbookFromRunListItem(item))
	}

	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if name == "" || solved[name] != nil {
			continue
		}
		versions := available[name]
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
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		a.injectFileURLs(m, r, org.Name())
		solved[name] = m
		for dep := range manifestDependencies(m) {
			queue = append(queue, dep)
		}
	}
	writeJSON(w, http.StatusOK, solved)
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
	var role map[string]any
	if json.Unmarshal(raw, &role) != nil {
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

// cookbookFromRunListItem extracts the cookbook name from a run-list entry such
// as "recipe[apache2::default]", "role[web]" (ignored), or a bare "apache2".
func cookbookFromRunListItem(item string) string {
	item = strings.TrimSpace(item)
	if strings.HasPrefix(item, "role[") {
		return ""
	}
	if strings.HasPrefix(item, "recipe[") && strings.HasSuffix(item, "]") {
		item = item[len("recipe[") : len(item)-1]
	}
	name, _, _ := strings.Cut(item, "::")
	return name
}
