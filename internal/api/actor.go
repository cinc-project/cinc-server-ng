package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// scopeFunc resolves the store space an actor collection lives in. Clients are
// org-scoped; users are global.
type scopeFunc func(w http.ResponseWriter, r *http.Request) *store.Org

// registerActorRoutes wires CRUD for an "actor" collection (clients or users).
// Actors are JSON objects carrying a public_key; on creation the server
// generates an RSA key pair if the caller did not supply one, returning the
// private key exactly once.
func (a *API) registerActorRoutes(mux *recordingMux, prefix, segment string, scope scopeFunc) {
	base := prefix + segment
	mux.HandleFunc("GET "+base, a.scopedList(segment, scope))
	mux.HandleFunc("POST "+base, a.createActor(segment, scope))
	mux.HandleFunc("GET "+base+"/{name}", a.scopedGet(segment, scope))
	mux.HandleFunc("PUT "+base+"/{name}", a.scopedPut(segment, scope))
	mux.HandleFunc("DELETE "+base+"/{name}", a.scopedDelete(segment, scope))
}

func (a *API) createActor(segment string, scope scopeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := scope(w, r)
		if org == nil {
			return
		}
		var obj map[string]any
		if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		name, _ := obj["name"].(string)
		if name == "" {
			// users may use "username" as the identity field
			name, _ = obj["username"].(string)
		}
		if name == "" {
			writeError(w, http.StatusBadRequest, "Field 'name' missing")
			return
		}

		// A client and a global user that share a name are the same principal to
		// everything downstream, so the second one must not be created.
		if msg, err := a.actorNameCollision(segment, name); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		} else if msg != "" {
			writeError(w, http.StatusConflict, msg)
			return
		}

		resp := map[string]any{
			"uri": objectURL(r, orgSegment(r), segment, name),
		}

		// A caller-supplied public key may arrive at the top level or nested
		// under "chef_key" (the key-management shape knife/cinc send). Accept
		// either; only generate a pair when no public key is provided.
		pub := bodyPublicKey(obj)
		if pub != "" {
			obj["public_key"] = pub
		} else {
			key, err := auth.GenerateKey()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "key generation failed")
				return
			}
			pubPEM, err := auth.EncodePublicKeyPEM(&key.PublicKey)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "key encoding failed")
				return
			}
			obj["public_key"] = string(pubPEM)
			// Modern Chef returns the generated key nested under "chef_key"
			// (the key-management shape), which is what knife and cinc read.
			resp["chef_key"] = map[string]any{
				"name":            "default",
				"public_key":      string(pubPEM),
				"expiration_date": "infinity",
				"private_key":     string(auth.EncodePrivateKeyPEM(key)),
			}
		}
		// The private key is never persisted; the public key lives top-level on
		// the stored actor, and a password is stashed out-of-band (for
		// authenticate_user). Strip the transient/nested fields.
		delete(obj, "chef_key")
		delete(obj, "private_key")
		if _, err := StashPassword(org, name, obj); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		raw := mustEncode(obj)
		if err := org.Create(segment, name, raw); errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "Object already exists")
			return
		} else if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := a.grantCreator(r, org, segment, name); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Under enforcement, a regular client joins the org's "clients" group (as
		// Chef does), so it can register and manage its own node. Validators stay
		// outside the group — they may only create clients.
		if a.enforceACL && segment == "clients" {
			if isValidator, _ := obj["validator"].(bool); !isValidator {
				if err := addClientToOrgGroup(org, "clients", name); err != nil {
					writeError(w, http.StatusInternalServerError, err.Error())
					return
				}
			}
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

// actorNameCollision reports why an actor may not be created under this name,
// or "" when the name is free.
//
// Nothing downstream distinguishes a client from a user by anything but its
// name. ACL entries name actors as bare strings, so `{"actors":["pivotal"]}`
// grants whichever principal answers to "pivotal"; and resolveAuth resolves an
// org client before a global user on any org-scoped path, so the client wins.
// A client created under a user's name therefore inherits every grant that user
// holds in the org *and* displaces them from it, since their requests are then
// checked against the client's key and fail. Registering a client only needs
// create on the clients container, which is what an org validator key — the key
// distributed to every node — is seeded with.
//
// Real Chef avoids this by keying authorization on immutable authz ids rather
// than names. Short of that change, the collision is refused at creation, which
// is the only point where it can still be prevented cheaply.
func (a *API) actorNameCollision(segment, name string) (string, error) {
	switch segment {
	case "clients":
		_, ok, err := a.store.Global().Get("users", name)
		if err != nil {
			return "", err
		}
		if ok {
			return "A user named " + name + " already exists; a client cannot share its name", nil
		}
	case "users":
		// Clients are org-scoped, so the same client name in two orgs is fine —
		// they never resolve on the same path. A user is global and would
		// collide with all of them.
		orgs, err := a.store.ListOrgs()
		if err != nil {
			return "", err
		}
		for _, orgName := range orgs {
			org, ok, err := a.store.Org(orgName)
			if err != nil {
				return "", err
			}
			if !ok {
				continue
			}
			if _, ok, err := org.Get("clients", name); err != nil {
				return "", err
			} else if ok {
				return "A client named " + name + " already exists in organization " + orgName +
					"; a user cannot share its name", nil
			}
		}
	}
	return "", nil
}

// orgSegment returns the org path value, or "" for global (user) routes.
func orgSegment(r *http.Request) string {
	return r.PathValue("org")
}

// bodyPublicKey reads an actor's public key from a request body, accepting it
// at the top level or nested under "chef_key" (the key-management shape knife
// and cinc send). It returns "" when neither carries one.
func bodyPublicKey(obj map[string]any) string {
	if pub, _ := obj["public_key"].(string); pub != "" {
		return pub
	}
	if ck, ok := obj["chef_key"].(map[string]any); ok {
		if pub, _ := ck["public_key"].(string); pub != "" {
			return pub
		}
	}
	return ""
}

// storedPublicKey returns the public key already stored for an actor, or "" if
// the actor does not exist or carries no key.
func storedPublicKey(org *store.Org, segment, name string) (string, error) {
	raw, ok, err := org.Get(segment, name)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	var prev map[string]any
	if json.Unmarshal(raw, &prev) != nil {
		return "", nil
	}
	pub, _ := prev["public_key"].(string)
	return pub, nil
}

// adminField is the global-user flag the authentication layer reads back to
// decide whether an actor is the superuser (see server/auth.go). It lives in the
// same document as a user's profile fields, which a user may edit for itself.
const adminField = "admin"

// preservePrivilege keeps a user update from setting its own superuser flag.
//
// classifyRequest lets a user act on its own global record, because maintaining
// your own profile is self-service. But the record it edits is also where the
// authentication layer looks up "admin" to decide whether the actor bypasses
// every ACL, so an unfiltered update turns that self-service into a one-request
// path from any authenticated user to full control of the server.
//
// The flag is therefore server-controlled on update: the stored value is carried
// forward unless the caller is already the superuser, who may still grant and
// revoke it. With no authenticated actor the endpoint stays open, matching the
// permissive default the rest of the package uses. Only global users carry the
// flag — an org client's "admin" is not read by anything — so clients are left
// alone.
func preservePrivilege(r *http.Request, org *store.Org, segment, name string, obj map[string]any) error {
	if segment != "users" {
		return nil
	}
	actor, ok := actorFromContext(r.Context())
	if !ok || actor.IsGlobalAdmin {
		return nil
	}
	stored, err := storedField(org, segment, name, adminField)
	if err != nil {
		return err
	}
	if stored == nil {
		delete(obj, adminField)
		return nil
	}
	obj[adminField] = stored
	return nil
}

// storedField returns one field of an actor's stored record, or nil when the
// actor or the field is absent.
func storedField(org *store.Org, segment, name, field string) (any, error) {
	raw, ok, err := org.Get(segment, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	var prev map[string]any
	if json.Unmarshal(raw, &prev) != nil {
		return nil, nil
	}
	return prev[field], nil
}

func (a *API) scopedList(segment string, scope scopeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := scope(w, r)
		if org == nil {
			return
		}

		// Chef Infra Server supports exact-match filtering of the actor list by
		// query parameter (notably GET /users?email= and
		// ?external_authentication_uid=). When a recognized filter is present,
		// only actors whose stored field matches exactly are returned; an
		// unrecognized value yields an empty map rather than an error.
		filters := map[string]string{}
		for _, field := range []string{"email", "external_authentication_uid"} {
			if v := r.URL.Query().Get(field); v != "" {
				filters[field] = v
			}
		}

		out := map[string]string{}
		keys, err := org.Keys(segment)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, name := range keys {
			match, err := actorMatchesFilters(org, segment, name, filters)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if !match {
				continue
			}
			out[name] = objectURL(r, orgSegment(r), segment, name)
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// actorMatchesFilters reports whether the stored actor document satisfies every
// supplied exact-match filter. With no filters it always matches; a missing or
// unparseable record matches nothing.
func actorMatchesFilters(org *store.Org, segment, name string, filters map[string]string) (bool, error) {
	if len(filters) == 0 {
		return true, nil
	}
	raw, ok, err := org.Get(segment, name)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return false, nil
	}
	for field, want := range filters {
		if got, _ := doc[field].(string); got != want {
			return false, nil
		}
	}
	return true, nil
}

func (a *API) scopedGet(segment string, scope scopeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := scope(w, r)
		if org == nil {
			return
		}
		raw, ok, err := viewObject(r, org, segment, r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, "Cannot find "+segment+" "+r.PathValue("name"))
			return
		}
		writeRaw(w, http.StatusOK, enveloped(segment, orgSegment(r), raw))
	}
}

func (a *API) scopedPut(segment string, scope scopeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := scope(w, r)
		if org == nil {
			return
		}
		name := r.PathValue("name")
		var obj map[string]any
		if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		delete(obj, "private_key")
		// A PUT that omits the public key must not silently drop the actor's
		// existing key — that would break its authentication. Carry the stored
		// key forward (key changes go through the keys API, not a bare update),
		// normalizing a nested chef_key to the top-level field either way.
		pub := bodyPublicKey(obj)
		if pub == "" {
			stored, err := storedPublicKey(org, segment, name)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			pub = stored
		}
		delete(obj, "chef_key")
		if pub != "" {
			obj["public_key"] = pub
		}
		if err := preservePrivilege(r, org, segment, name, obj); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if _, err := StashPassword(org, name, obj); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		raw := mustEncode(obj)
		if err := org.Put(segment, name, raw); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRaw(w, http.StatusOK, raw)
	}
}

func (a *API) scopedDelete(segment string, scope scopeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := scope(w, r)
		if org == nil {
			return
		}
		name := r.PathValue("name")
		raw, ok, err := org.Delete(segment, name)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, "Cannot find "+segment+" "+name)
			return
		}
		// Registration put the client in the org's "clients" group. Membership
		// must not outlive the actor: the group grants permission by name, so a
		// later client registered under the same name would inherit it.
		if segment == "clients" {
			if err := removeActorFromAllGroups(org, memberClients, name); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		writeRaw(w, http.StatusOK, enveloped(segment, orgSegment(r), raw))
	}
}

// mustEncode marshals v to canonical JSON without HTML escaping.
func mustEncode(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}
