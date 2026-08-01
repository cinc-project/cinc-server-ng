package api

import (
	"encoding/json"
	"net/http"

	"github.com/tas50/cinc-zero/internal/store"
)

// User↔organization association. A global user is associated with an org by
// recording their username in the org's "association_users" collection.

// AssociationUsersCollection holds the usernames associated with an org (org
// membership). Only the key matters; the value is a small record.
const AssociationUsersCollection = "association_users"

const assocColl = AssociationUsersCollection

func (a *API) registerAssociationRoutes(mux *recordingMux) {
	mux.HandleFunc("GET /organizations/{org}/users", a.listOrgUsers)
	mux.HandleFunc("POST /organizations/{org}/users", a.associateUser)
	mux.HandleFunc("GET /organizations/{org}/users/{user}", a.getOrgUser)
	mux.HandleFunc("DELETE /organizations/{org}/users/{user}", a.disassociateUser)
	mux.HandleFunc("GET /users/{user}/organizations", a.listUserOrgs)
}

// orgViewAllowed reports whether the request's actor may view this org's
// membership. With no actor (auth disabled / API-layer) everything is allowed;
// the bootstrap superuser always may; otherwise the actor must currently be a
// member of the org. A non-member — for example a user who was removed — is
// refused with 403, matching Chef Infra Server.
func (a *API) orgViewAllowed(w http.ResponseWriter, r *http.Request, org *store.Org) bool {
	actor, ok := actorFromContext(r.Context())
	if !ok || actor.IsGlobalAdmin {
		return true
	}
	_, ok, err := org.Get(assocColl, actor.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if ok {
		return true
	}
	writeError(w, http.StatusForbidden, "You are not a member of this organization.")
	return false
}

func (a *API) listOrgUsers(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	if !a.orgViewAllowed(w, r, org) {
		return
	}
	out := make([]map[string]any, 0)
	keys, err := org.Keys(assocColl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, username := range keys {
		out = append(out, map[string]any{"user": map[string]any{"username": username}})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) associateUser(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	username, _ := body["username"].(string)
	if username == "" {
		username, _ = body["user"].(string)
	}
	if username == "" {
		writeError(w, http.StatusBadRequest, "Field 'username' missing")
		return
	}
	// The user must exist globally before it can be associated.
	if _, ok, err := a.store.Global().Get("users", username); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if !ok {
		writeError(w, http.StatusNotFound, "Cannot find user "+username)
		return
	}
	// Associating a user who is already a member is a conflict.
	if _, ok, err := org.Get(assocColl, username); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if ok {
		writeStringError(w, http.StatusConflict, "The association already exists.")
		return
	}
	if err := org.Put(assocColl, username, mustEncode(map[string]any{"username": username})); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Associating a user makes them an org member, so they join the org's
	// "users" group — the same membership invite-acceptance grants (see
	// respondInvite). Without this, a directly-associated user would lack the
	// group-based permissions the default ACLs grant once enforcement is on.
	if err := addUserToOrgGroup(org, "users", username); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"uri": requestBaseURL(r) + "/organizations/" + org.Name() + "/users/" + username,
	})
}

func (a *API) getOrgUser(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	if !a.orgViewAllowed(w, r, org) {
		return
	}
	user := r.PathValue("user")
	if _, ok, err := org.Get(assocColl, user); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if !ok {
		writeError(w, http.StatusNotFound, "Cannot find user "+user+" in organization "+org.Name())
		return
	}
	// Return the global user record (without its out-of-band password).
	if raw, ok, err := a.store.Global().Get("users", user); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if ok {
		writeRaw(w, http.StatusOK, raw)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": user})
}

func (a *API) disassociateUser(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	user := r.PathValue("user")
	if _, ok, err := org.Delete(assocColl, user); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if !ok {
		writeError(w, http.StatusNotFound, "Cannot find user "+user+" in organization "+org.Name())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"username": user})
}

func (a *API) listUserOrgs(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	out := make([]map[string]any, 0)
	orgs, err := a.store.ListOrgs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, name := range orgs {
		org, ok, err := a.store.Org(name)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			continue
		}
		if _, ok, err := org.Get(assocColl, user); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		} else if ok {
			out = append(out, map[string]any{
				"organization": map[string]any{"name": name, "full_name": name},
			})
		}
	}
	writeJSON(w, http.StatusOK, out)
}
