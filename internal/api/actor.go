package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tas50/cinc-server-ng/internal/auth"
	"github.com/tas50/cinc-server-ng/internal/store"
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
		raw, ok, err := org.Delete(segment, r.PathValue("name"))
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

// mustEncode marshals v to canonical JSON without HTML escaping.
func mustEncode(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}
