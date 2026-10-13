package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/cinc-project/cinc-server-ng/internal/chefjson"
	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Groups and containers are stored and returned faithfully (so tooling that
// reads or writes them behaves). By default every authenticated actor is
// treated as authorized — the permissive default for a test server — but when
// ACL enforcement is enabled the membership recorded here actually gates
// requests (see authz_enforce.go).

var defaultGroups = []string{"admins", "billing-admins", "clients", "users", "public_key_read_access"}

// defaultGroupGroups are the groups erchef's org policy nests in a default
// group: public_key_read_access holds the users and clients groups.
var defaultGroupGroups = map[string][]string{
	"public_key_read_access": {"users", "clients"},
}

var defaultContainers = []string{
	"clients", "containers", "cookbooks", "cookbook_artifacts", "data",
	"environments", "groups", "nodes", "policies", "policy_groups",
	"roles", "sandboxes",
}

// seedAuthz adds the default groups and containers Chef creates in every org.
func seedAuthz(org *store.Org) error {
	for _, g := range defaultGroups {
		_, ok, err := org.Get("groups", g)
		if err != nil {
			return err
		}
		if !ok {
			if err := org.Put("groups", g, groupJSON(g, "", nil, nil, defaultGroupGroups[g])); err != nil {
				return err
			}
		}
	}
	for _, c := range defaultContainers {
		_, ok, err := org.Get("containers", c)
		if err != nil {
			return err
		}
		if !ok {
			if err := org.Put("containers", c, fmt.Appendf(nil,
				`{"containername":%q,"containerpath":%q}`, c, c)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *API) registerAuthzRoutes(mux *recordingMux) {
	// Groups carry their name in "groupname" (the field Chef clients POST) and
	// their members in top-level users/clients/groups arrays — a shape the
	// generic object CRUD doesn't model, so create/update are dedicated.
	const groups = "/organizations/{org}/groups"
	mux.HandleFunc("GET "+groups, a.listObjects("groups"))
	mux.HandleFunc("POST "+groups, a.createGroup)
	mux.HandleFunc("GET "+groups+"/{name}", a.getGroup)
	mux.HandleFunc("PUT "+groups+"/{name}", a.putGroup)
	mux.HandleFunc("DELETE "+groups+"/{name}", a.deleteGroup)
	mux.HandleFunc("HEAD "+groups+"/{name}", a.headObject("groups"))

	// Containers are keyed by "containername"; list and read are what tooling
	// needs, plus create/delete for completeness.
	const base = "/organizations/{org}/containers"
	mux.HandleFunc("GET "+base, a.listObjects("containers"))
	mux.HandleFunc("GET "+base+"/{name}", a.getObject("containers"))
	mux.HandleFunc("POST "+base, a.createContainer)
	mux.HandleFunc("DELETE "+base+"/{name}", a.deleteObject("containers"))
}

// getGroup returns a group with its incremental membership rows folded into
// the document, so callers see one consistent membership however it was added.
func (a *API) getGroup(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	name := r.PathValue("name")
	doc, ok, err := groupDocWithMembers(org, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find groups "+name)
		return
	}
	writeRaw(w, http.StatusOK, doc)
}

// createGroup creates a group from the Chef create body, which names the group
// in "groupname" (or "name"/"id") and may seed members.
func (a *API) createGroup(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	var obj map[string]any
	if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name := groupName(obj)
	if name == "" {
		writeError(w, http.StatusBadRequest, "Field 'name' missing")
		return
	}
	if !groupNameRE.MatchString(name) {
		writeError(w, http.StatusBadRequest, "Invalid group name.")
		return
	}
	users, clients, groups := groupMembers(obj)
	a.membership.Lock()
	defer a.membership.Unlock()
	if err := clearMembers(org, name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	err := org.Create("groups", name, groupJSON(name, "", users, clients, groups))
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "Object already exists")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"uri": objectURL(r, org.Name(), "groups", name),
	})
}

// putGroup updates a group's members from Chef's update body, which nests
// them under "actors":{users,clients,groups}.
//
// erchef (oc_chef_group:update_from_ejson) reads each kind with the group's
// current members as the default, so only the kinds the body names are
// replaced: one it leaves out keeps its members, and so does every kind when
// "actors" is absent, null, or the flat array a GET returns. The current
// members here are the effective membership, incremental rows included. The
// write folds them into the document and clears the rows, so a replaced kind
// loses both halves while a kept kind loses neither.
//
// erchef answers with the request body as it was sent, not the stored group.
func (a *API) putGroup(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	name := r.PathValue("name")
	if !exists(w, r, org, "groups", name, "Cannot find groups "+name) {
		return
	}
	raw, err := chefjson.Normalize(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	obj, err := chefjson.DecodeObject(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// Read-modify-write: a revocation landing between the read and the write
	// would be undone (see groupmembers.go). The group is checked again under
	// the lock, so a concurrent delete is not undone either.
	a.membership.Lock()
	defer a.membership.Unlock()
	if !exists(w, r, org, "groups", name, "Cannot find groups "+name) {
		return
	}
	users, clients, groups, err := groupMembership(org, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	update := groupUpdateMembers(obj)
	if v, ok := update[memberUsers]; ok {
		users = v
	}
	if v, ok := update[memberClients]; ok {
		clients = v
	}
	if v, ok := update[memberGroups]; ok {
		groups = v
	}
	// erchef resolves every kind it writes, kept ones included, and drops the
	// names it cannot find; a kept member whose actor is gone is not written
	// back.
	users, clients, groups, err = a.knownGroupMembers(org, users, clients, groups)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// The document now records the whole membership, so the rows it absorbed,
	// and those of a replaced kind, go.
	if err := clearMembers(org, name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := org.Put("groups", name, groupJSON(name, "", users, clients, groups)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

// groupUpdateMembers returns the member kinds a group update replaces, each
// mapped to the names the body gives it. Only a kind whose value is an array
// counts, read from the nested "actors" object as erchef reads it. When
// "actors" is not an object, the top-level users/clients/groups of the GET
// shape are read instead: erchef ignores those, but cinc-console saves a group
// by sending its GET document back with edited top-level lists.
func groupUpdateMembers(obj map[string]any) map[string][]string {
	src := obj
	if nested, ok := obj["actors"].(map[string]any); ok {
		src = nested
	}
	out := map[string][]string{}
	for _, kind := range []string{memberUsers, memberClients, memberGroups} {
		if _, ok := src[kind].([]any); ok {
			out[kind] = jsonStrings(src[kind])
		}
	}
	return out
}

// deleteGroup deletes a group and every reference to it.
//
// erchef names a group in an ACL, or in another group, by its authz id, and
// deleting the group deletes those references with it, so a group created
// later under the same name holds nothing. Here both name it by its name, so a
// reference left behind would be a grant to whoever is put in the next group
// of that name. The group's ACL, its incremental membership rows, its place in
// other groups (document and rows), and its entries in the org's ACLs all go.
func (a *API) deleteGroup(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	name := r.PathValue("name")
	a.membership.Lock()
	defer a.membership.Unlock()
	if _, ok, err := org.Get("groups", name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if !ok {
		writeError(w, http.StatusNotFound, "Cannot find groups "+name)
		return
	}
	// References go before the group itself, so a failure part-way leaves a
	// group that has lost some grants (and whose delete can be retried), never
	// a deleted group whose grants wait for the next group of its name.
	for _, step := range []func() error{
		func() error { return removeFromACLs(org, "groups", name) },
		func() error { return removeActorFromAllGroups(org, memberGroups, name) },
		func() error { return clearMembers(org, name) },
		func() error { return deleteACL(org, "groups", name) },
	} {
		if err := step(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	raw, ok, err := org.Delete("groups", name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find groups "+name)
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

// removeFromACLs drops name from the actors or groups (kind) of every ACE of
// every ACL stored in org: what deleting a group, a client or a user must do,
// since an ACL names them by bare name and would otherwise grant whatever is
// created next under it. ACLs are collected during the scan and rewritten after
// it, since a Range callback must not write back into the store.
func removeFromACLs(org *store.Org, kind, name string) error {
	changed := map[string][]byte{}
	if err := org.Range("acls", func(key string, raw []byte) bool {
		var acl map[string]any
		if json.Unmarshal(raw, &acl) != nil {
			return true
		}
		var dirty bool
		for _, perm := range aclPerms {
			ace, ok := acl[perm].(map[string]any)
			if !ok {
				continue
			}
			if kept, removed := without(anyStrings(ace[kind]), name); removed {
				ace[kind] = kept
				dirty = true
			}
		}
		if dirty {
			changed[key] = mustEncode(acl)
		}
		return true
	}); err != nil {
		return err
	}
	for key, raw := range changed {
		if err := org.Put("acls", key, raw); err != nil {
			return err
		}
	}
	return nil
}

// knownGroupMembers keeps only the members of a group update that exist: users
// are global (the bootstrap superuser belongs to no org yet sits in its
// groups), clients and groups belong to org. erchef's oc_chef_group:update
// resolves each name to an authz id and silently drops the ones it cannot
// find. A group here stores names, so keeping an unresolved one would make
// whatever is later created under that name a member from the start.
func (a *API) knownGroupMembers(org *store.Org, users, clients, groups []string) (u, c, g []string, err error) {
	keep := func(space *store.Org, coll string, names []string) ([]string, error) {
		out := make([]string, 0, len(names))
		for _, n := range names {
			_, ok, err := space.Get(coll, n)
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, n)
			}
		}
		return out, nil
	}
	if u, err = keep(a.store.Global(), "users", users); err != nil {
		return nil, nil, nil, err
	}
	if c, err = keep(org, "clients", clients); err != nil {
		return nil, nil, nil, err
	}
	if g, err = keep(org, "groups", groups); err != nil {
		return nil, nil, nil, err
	}
	return u, c, g, nil
}

// groupNameRE is erchef's rule for a new group's name (oc_chef_wm_groups
// VALID_NAME_REGEX): lowercase letters, digits, '-' and '_' only.
var groupNameRE = regexp.MustCompile(`^[a-z0-9_-]+$`)

// groupName reads a group's name from the Chef identity fields, in order.
func groupName(obj map[string]any) string {
	for _, field := range []string{"name", "groupname", "id"} {
		if v, ok := obj[field].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// addClientToOrgGroup adds client to the named org group's clients list (a
// no-op if already present), so a newly registered client is a member of the
// org's "clients" group and inherits its ACL grants under enforcement — the
// membership Chef gives clients so they can register and manage their own node.
func addClientToOrgGroup(org *store.Org, group, client string) error {
	return addMember(org, group, memberClients, client)
}

// groupMembers pulls members from a group body. An update nests them under
// "actors":{users,clients,groups}; a create may list them at the top level.
func groupMembers(obj map[string]any) (users, clients, groups []string) {
	src := obj
	if nested, ok := obj["actors"].(map[string]any); ok {
		src = nested
	}
	return jsonStrings(src["users"]), jsonStrings(src["clients"]), jsonStrings(src["groups"])
}

// groupJSON encodes a group as erchef's oc_chef_group:assemble_group_ejson
// does: "actors" is the clients followed by the users (nested groups are not
// actors), then the three member arrays, the org's name, and the group's name
// as both "name" and "groupname". The stored document omits "orgname" (pass
// ""), which the API adds. Empty member sets encode as [] rather than null.
func groupJSON(name, orgname string, users, clients, groups []string) []byte {
	strs := func(s []string) []any {
		out := make([]any, len(s))
		for i, v := range s {
			out[i] = v
		}
		return out
	}
	doc := &chefjson.Object{Members: []chefjson.Member{
		{Name: "actors", Value: append(strs(clients), strs(users)...)},
		{Name: "users", Value: strs(users)},
		{Name: "clients", Value: strs(clients)},
		{Name: "groups", Value: strs(groups)},
	}}
	if orgname != "" {
		doc.Members = append(doc.Members, chefjson.Member{Name: "orgname", Value: orgname})
	}
	doc.Members = append(doc.Members,
		chefjson.Member{Name: "name", Value: name},
		chefjson.Member{Name: "groupname", Value: name})
	return chefjson.Marshal(doc)
}

// jsonStrings coerces a decoded JSON array into a []string, dropping non-string
// elements. A missing or non-array value yields nil.
func jsonStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (a *API) createContainer(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	var obj map[string]any
	if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name, _ := obj["containername"].(string)
	if name == "" {
		name, _ = obj["id"].(string)
	}
	if name == "" {
		writeError(w, http.StatusBadRequest, "Field 'containername' missing")
		return
	}
	if err := org.Put("containers", name, mustEncode(obj)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"uri": objectURL(r, org.Name(), "containers", name),
	})
}
