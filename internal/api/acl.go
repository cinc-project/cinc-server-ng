package api

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// Every object exposes a well-formed five-permission ACL that tooling such as
// `knife acl` can read and write. ACLs are stored per object in the "acls"
// collection keyed by "type/name"; an object with no stored ACL reports a
// sensible permissive default. By default these ACLs are structural only — no
// request is denied — but they become enforced when the server is started with
// ACL enforcement enabled (see authz_enforce.go).

var aclPerms = []string{"create", "read", "update", "delete", "grant"}

// aclObjectTypes are the object types Chef exposes ACL endpoints for.
var aclObjectTypes = []string{
	"clients", "containers", "cookbooks", "cookbook_artifacts", "data",
	"environments", "groups", "nodes", "policies", "policy_groups", "roles",
}

func (a *API) registerACLRoutes(mux *recordingMux) {
	for _, typ := range aclObjectTypes {
		base := "/organizations/{org}/" + typ + "/{name}/_acl"
		mux.HandleFunc("GET "+base, a.getACL(typ))
		mux.HandleFunc("GET "+base+"/{perm}", a.getACLPerm(typ))
		mux.HandleFunc("PUT "+base+"/{perm}", a.putACLPerm(typ))
	}
	// The organization's own ACL.
	mux.HandleFunc("GET /organizations/{org}/_acl", a.getOrgACL)
	mux.HandleFunc("GET /organizations/{org}/_acl/{perm}", a.getOrgACLPerm)
	mux.HandleFunc("PUT /organizations/{org}/_acl/{perm}", a.putOrgACLPerm)
	// Global user ACLs (not org-scoped); stored in the global object space.
	mux.HandleFunc("GET /users/{name}/_acl", a.getUserACL)
	mux.HandleFunc("GET /users/{name}/_acl/{perm}", a.getUserACLPerm)
	mux.HandleFunc("PUT /users/{name}/_acl/{perm}", a.putUserACLPerm)
}

// aclPutStatus is the status a successful ACL-permission PUT returns. Most
// object types use 200 OK, but policy_groups use 201 Created, matching Chef.
func aclPutStatus(typ string) int {
	if typ == "policy_groups" {
		return http.StatusCreated
	}
	return http.StatusOK
}

func aclKey(typ, name string) string { return typ + "/" + name }

// defaultACL returns the permissive default ACL granted to a fresh object.
func defaultACL() map[string]any {
	perm := func(groups ...string) map[string]any {
		return map[string]any{"actors": []string{}, "groups": groups}
	}
	return map[string]any{
		"create": perm("admins", "users"),
		"read":   perm("admins", "users", "clients"),
		"update": perm("admins", "users"),
		"delete": perm("admins", "users"),
		"grant":  perm("admins"),
	}
}

// writeCreatorACL seeds a newly created object's per-object ACL from the container
// default plus the creating actor, granting the creator full control of what it
// created (mirroring Chef, where the creator owns the object — e.g. a chef-client
// can update the node it just registered). It is written only under ACL
// enforcement, so the permissive default stores no extra ACLs.
func writeCreatorACL(org *store.Org, typ, name, creator string) error {
	acl := defaultACL()
	for _, p := range aclPerms {
		ace := acl[p].(map[string]any)
		ace["actors"] = append(ace["actors"].([]string), creator)
	}
	return org.Put("acls", aclKey(typ, name), mustEncode(acl))
}

// grantCreator records the creating actor as the owner of a newly created object.
// It is a no-op unless ACL enforcement is on and a verified actor is present, so
// the permissive default writes no per-object ACLs and behaves exactly as before.
func (a *API) grantCreator(r *http.Request, org *store.Org, typ, name string) error {
	if !a.enforceACL {
		return nil
	}
	actor, ok := actorFromContext(r.Context())
	if !ok {
		return nil
	}
	return writeCreatorACL(org, typ, name, actor.Name)
}

func loadACL(org *store.Org, typ, name string) (map[string]any, error) {
	raw, ok, err := org.Get("acls", aclKey(typ, name))
	if err != nil {
		return nil, err
	}
	if ok {
		var m map[string]any
		if json.Unmarshal(raw, &m) == nil {
			return m, nil
		}
	}
	return defaultACL(), nil
}

// The org-scoped object handlers resolve the {org} path value to its store and
// delegate to the scope-based core functions below; the org's own ACL and the
// global user ACLs reuse the same cores against the appropriate scope.

func (a *API) getACL(typ string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if org := a.org(w, r); org != nil {
			writeACLDoc(w, org, typ, r.PathValue("name"))
		}
	}
}

func (a *API) getACLPerm(typ string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if org := a.org(w, r); org != nil {
			writeACLPermDoc(w, org, typ, r.PathValue("name"), r.PathValue("perm"))
		}
	}
}

func (a *API) putACLPerm(typ string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if org := a.org(w, r); org != nil {
			updateACLPermDoc(w, r, org, typ, r.PathValue("name"), r.PathValue("perm"), aclPutStatus(typ))
		}
	}
}

func (a *API) getOrgACL(w http.ResponseWriter, r *http.Request) {
	if org := a.org(w, r); org != nil {
		writeACLDoc(w, org, "organizations", r.PathValue("org"))
	}
}

func (a *API) getOrgACLPerm(w http.ResponseWriter, r *http.Request) {
	if org := a.org(w, r); org != nil {
		writeACLPermDoc(w, org, "organizations", r.PathValue("org"), r.PathValue("perm"))
	}
}

func (a *API) putOrgACLPerm(w http.ResponseWriter, r *http.Request) {
	if org := a.org(w, r); org != nil {
		updateACLPermDoc(w, r, org, "organizations", r.PathValue("org"), r.PathValue("perm"), http.StatusOK)
	}
}

func (a *API) getUserACL(w http.ResponseWriter, r *http.Request) {
	writeACLDoc(w, a.store.Global(), "users", r.PathValue("name"))
}

func (a *API) getUserACLPerm(w http.ResponseWriter, r *http.Request) {
	writeACLPermDoc(w, a.store.Global(), "users", r.PathValue("name"), r.PathValue("perm"))
}

func (a *API) putUserACLPerm(w http.ResponseWriter, r *http.Request) {
	updateACLPermDoc(w, r, a.store.Global(), "users", r.PathValue("name"), r.PathValue("perm"), http.StatusOK)
}

// writeACLDoc writes the full five-permission ACL for an object.
func writeACLDoc(w http.ResponseWriter, org *store.Org, typ, name string) {
	acl, err := loadACL(org, typ, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, acl)
}

// writeACLPermDoc writes a single permission's ACE, 404ing on an unknown perm.
func writeACLPermDoc(w http.ResponseWriter, org *store.Org, typ, name, perm string) {
	if !slices.Contains(aclPerms, perm) {
		writeError(w, http.StatusNotFound, "Cannot find ACL permission "+perm)
		return
	}
	acl, err := loadACL(org, typ, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{perm: acl[perm]})
}

// updateACLPermDoc replaces a single permission's ACE and writes it back with
// the given success status (200 for most object types, 201 for policy_groups).
func updateACLPermDoc(w http.ResponseWriter, r *http.Request, org *store.Org, typ, name, perm string, status int) {
	if !slices.Contains(aclPerms, perm) {
		writeError(w, http.StatusNotFound, "Cannot find ACL permission "+perm)
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// The body is either {"<perm>": {actors, groups}} or the ace object itself.
	ace := body
	if inner, ok := body[perm].(map[string]any); ok {
		ace = inner
	}

	acl, err := loadACL(org, typ, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	acl[perm] = ace
	if err := org.Put("acls", aclKey(typ, name), mustEncode(acl)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, status, map[string]any{perm: ace})
}
