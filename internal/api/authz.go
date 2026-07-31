package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/tas50/cinc-zero/internal/store"
)

// Groups and containers are stored and returned faithfully (so tooling that
// reads or writes them behaves). By default every authenticated actor is
// treated as authorized — the permissive default for a test server — but when
// ACL enforcement is enabled the membership recorded here actually gates
// requests (see authz_enforce.go).

var defaultGroups = []string{"admins", "billing-admins", "clients", "users"}

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
			if err := org.Put("groups", g, fmt.Appendf(nil,
				`{"name":%q,"groupname":%q,"actors":[],"users":[],"clients":[],"groups":[]}`, g, g)); err != nil {
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

func (a *API) registerAuthzRoutes(mux *http.ServeMux) {
	// Groups carry their name in "groupname" (the field Chef clients POST) and
	// their members in top-level users/clients/groups arrays — a shape the
	// generic object CRUD doesn't model, so create/update are dedicated.
	const groups = "/organizations/{org}/groups"
	mux.HandleFunc("GET "+groups, a.listObjects("groups"))
	mux.HandleFunc("POST "+groups, a.createGroup)
	mux.HandleFunc("GET "+groups+"/{name}", a.getGroup)
	mux.HandleFunc("PUT "+groups+"/{name}", a.putGroup)
	mux.HandleFunc("DELETE "+groups+"/{name}", a.deleteObject("groups"))
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
	users, clients, groups := groupMembers(obj)
	if err := clearMembers(org, name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	err := org.Create("groups", name, mustEncode(groupDoc(name, users, clients, groups)))
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

// putGroup replaces a group's members. Chef's update body nests them under
// "actors":{users,clients,groups}; the stored/returned doc carries them as
// top-level arrays (plus a flattened "actors"), where clients read them back.
func (a *API) putGroup(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	var obj map[string]any
	if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name := r.PathValue("name")
	users, clients, groups := groupMembers(obj)
	// An explicit write replaces the group's membership, so any rows added
	// incrementally since the last write no longer apply.
	if err := clearMembers(org, name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	doc := mustEncode(groupDoc(name, users, clients, groups))
	if err := org.Put("groups", name, doc); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRaw(w, http.StatusOK, doc)
}

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

// groupDoc builds Chef's canonical group representation: members in top-level
// users/clients/groups arrays, "actors" their union, and the name in both
// "name" and "groupname". Empty member sets encode as [] rather than null.
func groupDoc(name string, users, clients, groups []string) map[string]any {
	users, clients, groups = nonNilStrings(users), nonNilStrings(clients), nonNilStrings(groups)
	actors := make([]string, 0, len(users)+len(clients)+len(groups))
	actors = append(actors, users...)
	actors = append(actors, clients...)
	actors = append(actors, groups...)
	return map[string]any{
		"name":      name,
		"groupname": name,
		"actors":    actors,
		"users":     users,
		"clients":   clients,
		"groups":    groups,
	}
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

// nonNilStrings returns s, or an empty slice when s is nil, so it JSON-encodes
// as [] rather than null.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
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
