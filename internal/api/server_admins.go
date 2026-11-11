package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Chef Infra Server's global server-admins group lets its members manage user
// accounts without being the superuser. erchef's bootstrap
// (chef_server_data_bootstrap.rb, create_server_admins_global_group_in_bifrost)
// grants the group create, read, update and delete (not grant) on the users
// container, and every user created afterwards inherits that into its own ACL.
// So a member may list and create users, and read, update and delete any user
// and its keys (oc_chef_wm_keys asks for read or update on the user), but may
// not read or edit a user's ACL, and holds nothing on a superuser, whose ACL
// predates the group. Organizations are untouched.
//
// Here the user routes are gated by classifyUsers rather than by per-user
// ACLs, so the grant is applied there (authzCheck.serverAdmins) instead of
// being written into each user's ACL. Membership is the global-space
// collection serverAdminsColl, one key per user name.
//
// erchef has no REST route for membership: chef-server-ctl
// grant-server-admin-permissions, remove-server-admin-permissions and
// list-server-admins write bifrost directly. Their equivalent here is
// /_cinc/server_admins, a superuser-only, cinc-server-ng-specific route.
const serverAdminsColl = "server_admins"

const serverAdminsPath = "/_cinc/server_admins"

func (a *API) registerServerAdminRoutes(mux *recordingMux) {
	mux.HandleFunc("GET "+serverAdminsPath, a.listServerAdmins)
	mux.HandleFunc("PUT "+serverAdminsPath+"/{user}", a.addServerAdmin)
	mux.HandleFunc("DELETE "+serverAdminsPath+"/{user}", a.removeServerAdmin)
}

// isServerAdmin reports whether the named global user is in server-admins.
// Superusers are members too (chef-server-ctl's bootstrap adds pivotal), but
// they bypass authorization before this is ever asked.
func (a *API) isServerAdmin(name string) (bool, error) {
	_, ok, err := a.store.Global().Get(serverAdminsColl, name)
	return ok, err
}

// isSuperuser reports whether the named global user carries the superuser
// flag (see adminField).
func isSuperuser(global *store.Org, name string) (bool, error) {
	admin, err := storedField(global, "users", name, adminField)
	if err != nil {
		return false, err
	}
	b, _ := admin.(bool)
	return b, nil
}

// serverAdminAllowed reports whether actor passes check as a server-admins
// member: the check must extend to the group, the actor must be a member, and
// a check on one user must not target a superuser.
func (a *API) serverAdminAllowed(actor Actor, check *authzCheck) (bool, error) {
	if !check.serverAdmins || actor.IsClient {
		return false, nil
	}
	member, err := a.isServerAdmin(actor.Name)
	if err != nil || !member {
		return false, err
	}
	if check.serverAdminTarget == "" {
		return true, nil
	}
	super, err := isSuperuser(a.store.Global(), check.serverAdminTarget)
	return !super, err
}

// listServerAdmins is list-server-admins: the stored members and every
// superuser, sorted.
func (a *API) listServerAdmins(w http.ResponseWriter, r *http.Request) {
	global := a.store.Global()
	users, err := global.Keys(serverAdminsColl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	err = global.Range("users", func(name string, raw []byte) bool {
		var u map[string]any
		if json.Unmarshal(raw, &u) == nil {
			if admin, _ := u[adminField].(bool); admin && !slices.Contains(users, name) {
				users = append(users, name)
			}
		}
		return true
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	slices.Sort(users)
	if users == nil {
		users = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

// addServerAdmin is grant-server-admin-permissions: 201 when the user joins,
// 200 when it already was a member (a superuser always is).
func (a *API) addServerAdmin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("user")
	global := a.store.Global()
	// Held against a concurrent delete of the user, so a membership is never
	// written for a user that is already gone (see scopedDelete).
	a.membership.Lock()
	defer a.membership.Unlock()
	if _, ok, err := global.Get("users", name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if !ok {
		writeError(w, http.StatusNotFound, "User "+name+" was not found.")
		return
	}
	super, err := isSuperuser(global, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	status := http.StatusCreated
	if super {
		status = http.StatusOK
	} else if err := global.Create(serverAdminsColl, name, []byte(`{}`)); errors.Is(err, store.ErrConflict) {
		status = http.StatusOK
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, status, map[string]any{"username": name})
}

// removeServerAdmin is remove-server-admin-permissions, which refuses the
// superuser and a user that is not a member.
func (a *API) removeServerAdmin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("user")
	global := a.store.Global()
	super, err := isSuperuser(global, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if super {
		writeError(w, http.StatusBadRequest, "You cannot remove the superuser "+name+" from server-admins.")
		return
	}
	_, ok, err := global.Delete(serverAdminsColl, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "User "+name+" is not a member of server-admins so it cannot be removed.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": name})
}

// dropServerAdmin drops a deleted user's membership, which names it by bare
// name and would otherwise pass to the next user created under it.
func dropServerAdmin(global *store.Org, name string) error {
	_, _, err := global.Delete(serverAdminsColl, name)
	return err
}

// dropRequestedPrivilege keeps a user create from setting the superuser flag
// unless the caller is the superuser, as preservePrivilege does for an
// update. Creating users is no longer the superuser's alone: server-admins may,
// and a member must not be able to create a superuser.
func dropRequestedPrivilege(r *http.Request, obj map[string]any) {
	if actor, ok := actorFromContext(r.Context()); ok && !actor.IsGlobalAdmin {
		delete(obj, adminField)
	}
}
