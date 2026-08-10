package api

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// Association requests are the invite flow: an org admin invites a global user,
// and the user accepts or rejects. Pending invites live in each org's
// "association_requests" collection keyed by a deterministic id; accepting an
// invite associates the user (see association.go).

const assocReqColl = "association_requests"

func inviteID(user, org string) string { return user + "-" + org }

// writeStringError writes an error body as a JSON object with a string "error"
// field — the shape Chef Infra Server uses for the association / invitation
// endpoints, distinct from the {"error":[...]} array used elsewhere.
func writeStringError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (a *API) registerAssociationRequestRoutes(mux *recordingMux) {
	mux.HandleFunc("GET /organizations/{org}/association_requests", a.listOrgInvites)
	mux.HandleFunc("POST /organizations/{org}/association_requests", a.createInvite)
	mux.HandleFunc("DELETE /organizations/{org}/association_requests/{id}", a.rescindInvite)

	mux.HandleFunc("GET /users/{user}/association_requests", a.listUserInvites)
	mux.HandleFunc("GET /users/{user}/association_requests/count", a.countUserInvites)
	mux.HandleFunc("PUT /users/{user}/association_requests/{id}", a.respondInvite)
}

func (a *API) listOrgInvites(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	out := make([]map[string]any, 0)
	keys, err := org.Keys(assocReqColl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, id := range keys {
		raw, _, err := org.Get(assocReqColl, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		var inv map[string]any
		json.Unmarshal(raw, &inv)
		out = append(out, map[string]any{"id": id, "username": inv["username"]})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createInvite(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	user, _ := body["user"].(string)
	if user == "" {
		user, _ = body["username"].(string)
	}
	if user == "" {
		writeError(w, http.StatusBadRequest, "Field 'user' missing")
		return
	}
	if _, ok, err := a.store.Global().Get("users", user); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if !ok {
		writeError(w, http.StatusNotFound, "Cannot find user "+user)
		return
	}
	if _, ok, err := org.Get(assocColl, user); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if ok {
		writeStringError(w, http.StatusConflict, "The association already exists.")
		return
	}
	id := inviteID(user, org.Name())
	if _, ok, err := org.Get(assocReqColl, id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if ok {
		writeStringError(w, http.StatusConflict, "The invitation already exists.")
		return
	}
	// Record who issued the invite so acceptance can verify they still have the
	// authority to do so.
	inviter := ""
	if actor, ok := actorFromContext(r.Context()); ok {
		inviter = actor.Name
	}
	if err := org.Put(assocReqColl, id, mustEncode(map[string]any{
		"id": id, "username": user, "orgname": org.Name(), "inviter": inviter,
	})); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"uri":               requestBaseURL(r) + "/organizations/" + org.Name() + "/association_requests/" + id,
		"id":                id,
		"organization_user": map[string]any{"username": user},
	})
}

func (a *API) rescindInvite(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	raw, ok, err := org.Delete(assocReqColl, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeStringError(w, http.StatusNotFound, "Cannot find association request: "+r.PathValue("id"))
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

func (a *API) listUserInvites(w http.ResponseWriter, r *http.Request) {
	invites, err := a.userInvites(r.PathValue("user"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, invites)
}

func (a *API) countUserInvites(w http.ResponseWriter, r *http.Request) {
	invites, err := a.userInvites(r.PathValue("user"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"value": len(invites)})
}

// userInvites collects the pending invites for a user across all organizations.
func (a *API) userInvites(user string) ([]map[string]any, error) {
	out := make([]map[string]any, 0)
	orgs, err := a.store.ListOrgs()
	if err != nil {
		return nil, err
	}
	for _, name := range orgs {
		org, ok, err := a.store.Org(name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		raw, ok, err := org.Get(assocReqColl, inviteID(user, name))
		if err != nil {
			return nil, err
		}
		if ok {
			var inv map[string]any
			json.Unmarshal(raw, &inv)
			out = append(out, map[string]any{"id": inviteID(user, name), "orgname": name})
		}
	}
	return out, nil
}

// respondInvite accepts or rejects an invitation. Only the invited user may
// respond. Accepting associates the user with the org and adds them to its
// "users" group; either response consumes the invite. An invite issued by
// someone who has since lost the authority to invite can no longer be accepted.
func (a *API) respondInvite(w http.ResponseWriter, r *http.Request) {
	user, id := r.PathValue("user"), r.PathValue("id")

	// Only the invitee may respond to their own invitation; a third party (org
	// admin or anyone else) is forbidden. With no actor the endpoint stays open.
	if actor, ok := actorFromContext(r.Context()); ok && actor.Name != user {
		writeStringError(w, http.StatusForbidden, "You are not allowed to take this action.")
		return
	}

	org, ok, err := a.findInvite(user, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeStringError(w, http.StatusNotFound, "Cannot find association request: "+id)
		return
	}
	var body struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Response != "accept" && body.Response != "reject" {
		writeError(w, http.StatusBadRequest, "Param response must be either 'accept' or 'reject'")
		return
	}

	if body.Response == "accept" {
		var inv struct {
			Inviter string `json:"inviter"`
		}
		if raw, ok, err := org.Get(assocReqColl, id); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		} else if ok {
			json.Unmarshal(raw, &inv)
		}
		authorized, err := a.inviterAuthorized(org, inv.Inviter)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !authorized {
			writeStringError(w, http.StatusForbidden, "The user who issued this invitation can no longer do so.")
			return
		}
	}

	if _, _, err := org.Delete(assocReqColl, id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if body.Response == "accept" {
		if err := org.Put(assocColl, user, mustEncode(map[string]any{"username": user})); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := addUserToOrgGroup(org, "users", user); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"organization": map[string]any{"name": org.Name()},
	})
}

// inviterAuthorized reports whether the recorded inviter may still issue
// invitations for the org: a global superuser always may; otherwise they must
// still exist, still be associated with the org, and still belong to its
// "admins" group. An empty inviter (created without an authenticated actor) is
// treated as authorized.
func (a *API) inviterAuthorized(org *store.Org, inviter string) (bool, error) {
	if inviter == "" {
		return true, nil
	}
	uraw, ok, err := a.store.Global().Get("users", inviter)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	var u map[string]any
	json.Unmarshal(uraw, &u)
	if admin, _ := u["admin"].(bool); admin {
		return true, nil
	}
	if _, ok, err := org.Get(assocColl, inviter); err != nil {
		return false, err
	} else if !ok {
		return false, nil
	}
	users, _, _, err := groupMembership(org, "admins")
	if err != nil {
		return false, err
	}
	return slices.Contains(users, inviter), nil
}

// addUserToOrgGroup adds user to the named org group's user list (creating the
// group if absent), so authorization membership reflects the new member.
func addUserToOrgGroup(org *store.Org, group, user string) error {
	return addMember(org, group, memberUsers, user)
}

// AddUserToOrgGroup adds a global user to an org group, mirroring what
// associateUser does when a user joins via the API. The state loader uses it to
// reproduce that membership for users declared in members.json, which it writes
// straight into the store rather than through the association handler.
func AddUserToOrgGroup(org *store.Org, group, user string) error {
	return addUserToOrgGroup(org, group, user)
}

// findInvite locates the org holding the given invitation id for the user.
func (a *API) findInvite(user, id string) (*store.Org, bool, error) {
	orgs, err := a.store.ListOrgs()
	if err != nil {
		return nil, false, err
	}
	for _, name := range orgs {
		org, ok, err := a.store.Org(name)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			continue
		}
		raw, ok, err := org.Get(assocReqColl, id)
		if err != nil {
			return nil, false, err
		}
		if ok {
			var inv struct {
				Username string `json:"username"`
			}
			json.Unmarshal(raw, &inv)
			if inv.Username == user {
				return org, true, nil
			}
		}
	}
	return nil, false, nil
}
