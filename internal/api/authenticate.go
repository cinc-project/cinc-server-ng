package api

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// authenticate_user validates a user's password. Passwords are stored
// out-of-band (never in the user object or its API responses) in the
// "passwords" collection of the actor's scope, keyed by name. This is a test
// server, so the password is kept as-is in memory; it is only ever compared,
// never returned.

// PasswordsCollection is the store collection holding actor passwords,
// out-of-band from the actor record (real Chef stores these hashed and never
// returns them; cinc-zero keeps them in memory). authenticate_user reads it.
const PasswordsCollection = "passwords"

// StashPassword moves a "password" field out of an actor object into the
// out-of-band password store, so it is neither persisted in nor returned with
// the actor record. It reports whether a password was present.
func StashPassword(org *store.Org, name string, obj map[string]any) (bool, error) {
	if pw, ok := obj["password"].(string); ok {
		if err := org.Put(PasswordsCollection, name, []byte(pw)); err != nil {
			return false, err
		}
		delete(obj, "password")
		return true, nil
	}
	return false, nil
}

func (a *API) registerAuthenticateRoutes(mux *recordingMux) {
	mux.HandleFunc("POST /authenticate_user", a.authenticateUser)
}

func (a *API) authenticateUser(w http.ResponseWriter, r *http.Request) {
	// Only the superuser may verify another user's credentials. When the request
	// carries an authenticated actor (the server layer always sets one; the ACL
	// layer too), reject any non-admin caller. With no actor in context — auth
	// disabled, or the API-layer tests — the endpoint stays open, matching the
	// permissive default the rest of the package uses.
	if actor, ok := actorFromContext(r.Context()); ok && !actor.IsGlobalAdmin && !actor.ViaWebUI {
		writeError(w, http.StatusForbidden, "You are not allowed to take this action.")
		return
	}

	// chef-client/knife send the identity as "username"; accept "name" too.
	var body struct {
		Username string `json:"username"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name := body.Username
	if name == "" {
		name = body.Name
	}

	global := a.store.Global()
	userRaw, ok, err := global.Get("users", name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "Failed to authenticate. Username and password incorrect.")
		return
	}
	stored, ok, err := global.Get(PasswordsCollection, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok || subtle.ConstantTimeCompare(stored, []byte(body.Password)) != 1 {
		writeError(w, http.StatusUnauthorized, "Failed to authenticate. Username and password incorrect.")
		return
	}

	var user map[string]any
	json.Unmarshal(userRaw, &user)
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "linked",
		"user":   user,
	})
}
