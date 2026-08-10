package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// Policyfile storage:
//   - Each policy's revisions live in "policy_revisions:<policy>" keyed by
//     revision_id, holding the full revision document.
//   - Policy groups live in the "policy_groups" collection keyed by group name,
//     each holding {"policies": {"<policy>": {"revision_id": "<rev>"}}}.
const policyGroupsColl = "policy_groups"

func policyRevColl(policy string) string { return "policy_revisions:" + policy }

const policyRevPrefix = "policy_revisions:"

func (a *API) registerPolicyRoutes(mux *recordingMux) {
	o := "/organizations/{org}"
	mux.HandleFunc("GET "+o+"/policies", a.listPolicies)
	mux.HandleFunc("GET "+o+"/policies/{name}", a.getPolicy)
	mux.HandleFunc("DELETE "+o+"/policies/{name}", a.deletePolicy)
	mux.HandleFunc("GET "+o+"/policies/{name}/revisions/{rev}", a.getPolicyRevision)
	mux.HandleFunc("POST "+o+"/policies/{name}/revisions", a.createPolicyRevision)
	mux.HandleFunc("DELETE "+o+"/policies/{name}/revisions/{rev}", a.deletePolicyRevision)

	mux.HandleFunc("GET "+o+"/policy_groups", a.listPolicyGroups)
	mux.HandleFunc("GET "+o+"/policy_groups/{group}", a.getPolicyGroup)
	mux.HandleFunc("DELETE "+o+"/policy_groups/{group}", a.deletePolicyGroup)
	mux.HandleFunc("GET "+o+"/policy_groups/{group}/policies/{policy}", a.getGroupPolicy)
	mux.HandleFunc("PUT "+o+"/policy_groups/{group}/policies/{policy}", a.putGroupPolicy)
	mux.HandleFunc("DELETE "+o+"/policy_groups/{group}/policies/{policy}", a.deleteGroupPolicy)
}

// policyNames returns the names of policies that currently have revisions.
func policyNames(org *store.Org) ([]string, error) {
	var names []string
	colls, err := org.Collections()
	if err != nil {
		return nil, err
	}
	for _, coll := range colls {
		if name, ok := strings.CutPrefix(coll, policyRevPrefix); ok {
			names = append(names, name)
		}
	}
	return names, nil
}

func policyURL(r *http.Request, org, name string) string {
	return requestBaseURL(r) + "/organizations/" + org + "/policies/" + name
}

func (a *API) listPolicies(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	out := map[string]any{}
	names, err := policyNames(org)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, name := range names {
		revs := map[string]any{}
		keys, err := org.Keys(policyRevColl(name))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, rev := range keys {
			revs[rev] = map[string]any{}
		}
		out[name] = map[string]any{
			"uri":       policyURL(r, org.Name(), name),
			"revisions": revs,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) getPolicy(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	name := r.PathValue("name")
	revIDs, err := org.Keys(policyRevColl(name))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(revIDs) == 0 {
		writeError(w, http.StatusNotFound, "Cannot find policy "+name)
		return
	}
	revs := map[string]any{}
	for _, rev := range revIDs {
		revs[rev] = map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"revisions": revs})
}

func (a *API) deletePolicy(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	name := r.PathValue("name")
	coll := policyRevColl(name)
	revIDs, err := org.Keys(coll)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(revIDs) == 0 {
		writeError(w, http.StatusNotFound, "Cannot find policy "+name)
		return
	}
	revs := map[string]any{}
	for _, rev := range revIDs {
		revs[rev] = map[string]any{}
		if _, _, err := org.Delete(coll, rev); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"revisions": revs})
}

func (a *API) getPolicyRevision(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	raw, ok, err := org.Get(policyRevColl(r.PathValue("name")), r.PathValue("rev"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find policy revision")
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

func (a *API) createPolicyRevision(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	raw, revID, err := decodeRevision(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if revID == "" {
		writeError(w, http.StatusBadRequest, "Field 'revision_id' missing")
		return
	}
	if err := org.Create(policyRevColl(r.PathValue("name")), revID, raw); errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "Policy revision already exists")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRaw(w, http.StatusCreated, raw)
}

func (a *API) deletePolicyRevision(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	raw, ok, err := org.Delete(policyRevColl(r.PathValue("name")), r.PathValue("rev"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find policy revision")
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

// --- policy groups ---

type policyGroup struct {
	Policies map[string]groupPolicy `json:"policies"`
}

type groupPolicy struct {
	RevisionID string `json:"revision_id"`
}

func loadGroup(org *store.Org, name string) (policyGroup, bool, error) {
	raw, ok, err := org.Get(policyGroupsColl, name)
	if err != nil {
		return policyGroup{}, false, err
	}
	if !ok {
		return policyGroup{}, false, nil
	}
	var g policyGroup
	if err := json.Unmarshal(raw, &g); err != nil {
		return policyGroup{}, false, nil
	}
	if g.Policies == nil {
		g.Policies = map[string]groupPolicy{}
	}
	return g, true, nil
}

func saveGroup(org *store.Org, name string, g policyGroup) error {
	return org.Put(policyGroupsColl, name, mustEncode(g))
}

func (a *API) listPolicyGroups(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	out := map[string]any{}
	keys, err := org.Keys(policyGroupsColl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, name := range keys {
		g, _, err := loadGroup(org, name)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out[name] = map[string]any{
			"uri":      requestBaseURL(r) + "/organizations/" + org.Name() + "/policy_groups/" + name,
			"policies": g.Policies,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) getPolicyGroup(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	raw, ok, err := org.Get(policyGroupsColl, r.PathValue("group"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find policy group "+r.PathValue("group"))
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

func (a *API) deletePolicyGroup(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	raw, ok, err := org.Delete(policyGroupsColl, r.PathValue("group"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find policy group "+r.PathValue("group"))
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

func (a *API) getGroupPolicy(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	g, ok, err := loadGroup(org, r.PathValue("group"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find policy group "+r.PathValue("group"))
		return
	}
	policy := r.PathValue("policy")
	assoc, ok := g.Policies[policy]
	if !ok {
		writeError(w, http.StatusNotFound, "Policy "+policy+" not in group")
		return
	}
	raw, ok, err := org.Get(policyRevColl(policy), assoc.RevisionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find policy revision")
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

// putGroupPolicy is the deploy operation: it stores the supplied policy
// revision and associates it with the group at that revision.
func (a *API) putGroupPolicy(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	raw, revID, err := decodeRevision(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if revID == "" {
		writeError(w, http.StatusBadRequest, "Field 'revision_id' missing")
		return
	}
	policy := r.PathValue("policy")
	if err := org.Put(policyRevColl(policy), revID, raw); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	groupName := r.PathValue("group")
	g, ok, err := loadGroup(org, groupName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		g = policyGroup{Policies: map[string]groupPolicy{}}
	}
	g.Policies[policy] = groupPolicy{RevisionID: revID}
	if err := saveGroup(org, groupName, g); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeRaw(w, http.StatusOK, raw)
}

func (a *API) deleteGroupPolicy(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	groupName := r.PathValue("group")
	g, ok, err := loadGroup(org, groupName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find policy group "+groupName)
		return
	}
	policy := r.PathValue("policy")
	assoc, ok := g.Policies[policy]
	if !ok {
		writeError(w, http.StatusNotFound, "Policy "+policy+" not in group")
		return
	}
	raw, _, err := org.Get(policyRevColl(policy), assoc.RevisionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	delete(g.Policies, policy)
	if err := saveGroup(org, groupName, g); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

// decodeRevision reads a policy revision body and returns canonical bytes plus
// its "revision_id".
func decodeRevision(r *http.Request) (raw []byte, revID string, err error) {
	var obj map[string]any
	if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
		return nil, "", err
	}
	revID, _ = obj["revision_id"].(string)
	return mustEncode(obj), revID, nil
}
