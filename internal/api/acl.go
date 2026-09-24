package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Every object exposes a well-formed five-permission ACL that tooling such as
// `knife acl` can read and write. ACLs are stored per object in the "acls"
// collection keyed by "type/name"; an object with no stored ACL reports a
// sensible permissive default, while the ACL of an object that does not exist is
// a 404, as in erchef. By default these ACLs are structural only — no
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
	// The organization's own ACL, at erchef's path. erchef has no shorter
	// /organizations/{org}/_acl form.
	mux.HandleFunc("GET /organizations/{org}/organizations/_acl", a.getOrgACL)
	mux.HandleFunc("GET /organizations/{org}/organizations/_acl/{perm}", a.getOrgACLPerm)
	mux.HandleFunc("PUT /organizations/{org}/organizations/_acl/{perm}", a.putOrgACLPerm)
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

// deleteACL removes an object's per-object ACL.
//
// An ACL is keyed by object type and name, and loadACL resolves it by that key
// alone — so one left behind after its object is gone is not inert: it is
// silently applied to the next object created under the same name. Deletion has
// to take the ACL with the object, or a grant made to a contractor on last
// year's "vault" data bag still governs this year's.
//
// Objects created through createObject/createActor happen to mask this, since
// grantCreator overwrites the ACL on create; data bags, cookbooks, policies,
// groups and containers have no such path and inherit the stale one verbatim.
func deleteACL(org *store.Org, typ, name string) error {
	_, _, err := org.Delete("acls", aclKey(typ, name))
	return err
}

// aclObjectExists reports whether the object an ACL of type typ and name
// belongs to exists. erchef looks the object up before its ACL, so the ACL of a
// missing object is a 404 rather than the default: and a stored one would not be
// inert, since loadACL keys it by type and name alone and it would govern
// whatever is later created under that name.
func aclObjectExists(org *store.Org, typ, name string) (bool, error) {
	switch typ {
	case "organizations":
		return true, nil // the caller has already resolved the org itself
	case "data":
		_, ok, err := org.Get(dataBagsColl, name)
		return ok, err
	case "cookbooks", "cookbook_artifacts":
		return hasVersion(org, typ, name)
	case "policies":
		revs, err := org.Keys(policyRevColl(name))
		return len(revs) > 0, err
	default: // stored one key per object in a collection named for the type
		_, ok, err := org.Get(typ, name)
		return ok, err
	}
}

// aclObjectFound writes a 404 (or a 500 on a store error) and returns false
// unless the object whose ACL is addressed exists.
func aclObjectFound(w http.ResponseWriter, org *store.Org, typ, name string) bool {
	ok, err := aclObjectExists(org, typ, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find "+typ+" "+name)
		return false
	}
	return true
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
	return fallbackACL(typ, name), nil
}

// fallbackACL is the ACL an object with no stored one reports. For most objects
// that is defaultACL(), which lets every org member (the "users" group) create,
// update and delete.
//
// Two kinds of object must not inherit that, because holding update on them is
// authority over the org itself rather than over one of its objects:
//
//   - The organization. Update on it is what invites, rescinds and removes
//     members, and no organization ever gets an ACL written for it, so the
//     fallback is its ACL. Chef's org policy (oc_chef_authz_org_creator) gives
//     the users group read on the organization and nothing else.
//   - The default groups. Membership of admins carries update on the
//     organization, and membership of users carries the default ACL's CRUD, so
//     a member who could rewrite either could grant themselves (or an outsider)
//     everything the membership gate withholds. Chef gives the users group no
//     permission on these groups.
//
// Both keep defaultACL's read, which is what lets a member see the org and the
// groups it belongs to. An ACL written for either through the _acl endpoints
// still replaces this fallback, as for any object.
func fallbackACL(typ, name string) map[string]any {
	acl := defaultACL()
	if typ == "organizations" || (typ == "groups" && slices.Contains(defaultGroups, name)) {
		for _, p := range []string{"create", "update", "delete"} {
			acl[p] = map[string]any{"actors": []string{}, "groups": []string{"admins"}}
		}
	}
	return acl
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
			a.updateACLPermDoc(w, r, org, org, typ, r.PathValue("name"), r.PathValue("perm"), aclPutStatus(typ))
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
		a.updateACLPermDoc(w, r, org, org, "organizations", r.PathValue("org"), r.PathValue("perm"), http.StatusOK)
	}
}

func (a *API) getUserACL(w http.ResponseWriter, r *http.Request) {
	writeACLDoc(w, a.store.Global(), "users", r.PathValue("name"))
}

func (a *API) getUserACLPerm(w http.ResponseWriter, r *http.Request) {
	writeACLPermDoc(w, a.store.Global(), "users", r.PathValue("name"), r.PathValue("perm"))
}

func (a *API) putUserACLPerm(w http.ResponseWriter, r *http.Request) {
	a.updateACLPermDoc(w, r, a.store.Global(), nil, "users", r.PathValue("name"), r.PathValue("perm"), http.StatusOK)
}

// writeACLDoc writes the full five-permission ACL for an object.
func writeACLDoc(w http.ResponseWriter, org *store.Org, typ, name string) {
	if !aclObjectFound(w, org, typ, name) {
		return
	}
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
	if !aclObjectFound(w, org, typ, name) {
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
// scope holds the ACL; members is the org the ACE's members resolve in, or nil
// for a global user's ACL (see unknownACEMembers).
func (a *API) updateACLPermDoc(w http.ResponseWriter, r *http.Request, scope, members *store.Org, typ, name, perm string, status int) {
	if !slices.Contains(aclPerms, perm) {
		writeError(w, http.StatusNotFound, "Cannot find ACL permission "+perm)
		return
	}
	if !aclObjectFound(w, scope, typ, name) {
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

	actors, groups, err := a.unknownACEMembers(members, ace)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(actors) > 0 || len(groups) > 0 {
		var msgs []string
		if len(actors) > 0 {
			msgs = append(msgs, "The actor(s) "+strings.Join(actors, ", ")+" do not exist.")
		}
		if len(groups) > 0 {
			msgs = append(msgs, "The group(s) "+strings.Join(groups, ", ")+" do not exist in this organization.")
		}
		writeError(w, http.StatusBadRequest, msgs...)
		return
	}

	acl, err := loadACL(scope, typ, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	acl[perm] = ace
	if err := scope.Put("acls", aclKey(typ, name), mustEncode(acl)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, status, map[string]any{perm: ace})
}

// unknownACEMembers returns the actor and group names an ACE lists that do not
// exist. erchef resolves every member to an authz id before writing an ACL and
// refuses the write when one is missing; an ACL here stores names, so keeping
// an unresolved one would be a latent grant to whatever is later created under
// it.
//
// Actors resolve as global users (the bootstrap superuser, which default ACLs
// name, belongs to no org) or as clients of org. Groups resolve as groups of
// org. For a global user's ACL org is nil: actors resolve as users only, and
// groups are not checked, since the global space has none to resolve against.
func (a *API) unknownACEMembers(org *store.Org, ace map[string]any) (actors, groups []string, err error) {
	for _, name := range jsonStrings(ace["actors"]) {
		_, ok, err := a.store.Global().Get("users", name)
		if err != nil {
			return nil, nil, err
		}
		if !ok && org != nil {
			if _, ok, err = org.Get("clients", name); err != nil {
				return nil, nil, err
			}
		}
		if !ok {
			actors = append(actors, name)
		}
	}
	if org == nil {
		return actors, nil, nil
	}
	for _, name := range jsonStrings(ace["groups"]) {
		_, ok, err := org.Get("groups", name)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			groups = append(groups, name)
		}
	}
	return actors, groups, nil
}
