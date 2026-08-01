package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tas50/cinc-zero/internal/auth"
	"github.com/tas50/cinc-zero/internal/store"
)

// Key management implements Chef's v1 key API for actors (clients and users).
// Every actor has a "default" key derived from its stored public_key; callers
// may add, fetch, replace, and delete additional named keys. Named keys live in
// a per-actor collection ("<segment>_keys:<actor>") within the actor's scope
// (org for clients, global for users). As with actor creation, a key POSTed
// without a public_key has one generated, and the private key is returned once.

const defaultKeyName = "default"

func (a *API) registerKeyRoutes(mux *recordingMux, prefix, segment string, scope scopeFunc) {
	base := prefix + segment + "/{name}/keys"
	mux.HandleFunc("GET "+base, a.listKeys(segment, scope))
	mux.HandleFunc("POST "+base, a.addKey(segment, scope))
	mux.HandleFunc("GET "+base+"/{key}", a.getKey(segment, scope))
	mux.HandleFunc("PUT "+base+"/{key}", a.putKey(segment, scope))
	mux.HandleFunc("DELETE "+base+"/{key}", a.deleteKey(segment, scope))
}

func keysColl(segment, actor string) string { return segment + "_keys:" + actor }

func keysBaseURL(r *http.Request, segment, actor string) string {
	return objectURL(r, orgSegment(r), segment, actor) + "/keys"
}

// loadActor fetches the actor object, writing a 404 if it does not exist.
func loadActor(w http.ResponseWriter, org *store.Org, segment, name string) (map[string]any, bool) {
	raw, ok, err := org.Get(segment, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return nil, false
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find "+segment+" "+name)
		return nil, false
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil {
		return nil, false
	}
	return obj, true
}

func (a *API) listKeys(segment string, scope scopeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := scope(w, r)
		if org == nil {
			return
		}
		name := r.PathValue("name")
		actor, ok := loadActor(w, org, segment, name)
		if !ok {
			return
		}

		coll := keysColl(segment, name)
		base := keysBaseURL(r, segment, name)
		var out []map[string]any
		_, storedDefault, err := org.Get(coll, defaultKeyName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// The synthetic default key reflects the actor's public_key.
		if !storedDefault {
			if pk, _ := actor["public_key"].(string); pk != "" {
				out = append(out, keyListItem(base, defaultKeyName))
			}
		}
		kns, err := org.Keys(coll)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, kn := range kns {
			out = append(out, keyListItem(base, kn))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func keyListItem(base, name string) map[string]any {
	return map[string]any{"name": name, "uri": base + "/" + name, "expired": false}
}

func (a *API) getKey(segment string, scope scopeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := scope(w, r)
		if org == nil {
			return
		}
		name, keyName := r.PathValue("name"), r.PathValue("key")
		actor, ok := loadActor(w, org, segment, name)
		if !ok {
			return
		}
		coll := keysColl(segment, name)
		raw, ok, err := org.Get(coll, keyName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if ok {
			writeRaw(w, http.StatusOK, raw)
			return
		}
		if keyName == defaultKeyName {
			if pk, _ := actor["public_key"].(string); pk != "" {
				writeJSON(w, http.StatusOK, keyObject(defaultKeyName, pk))
				return
			}
		}
		writeError(w, http.StatusNotFound, "Cannot find key "+keyName)
	}
}

func keyObject(name, publicKey string) map[string]any {
	return map[string]any{
		"name":            name,
		"public_key":      publicKey,
		"expiration_date": "infinity",
		"expired":         false,
	}
}

func (a *API) addKey(segment string, scope scopeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := scope(w, r)
		if org == nil {
			return
		}
		name := r.PathValue("name")
		if _, ok := loadActor(w, org, segment, name); !ok {
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		keyName, _ := body["name"].(string)
		if keyName == "" {
			writeError(w, http.StatusBadRequest, "Field 'name' missing")
			return
		}

		resp := map[string]any{"uri": keysBaseURL(r, segment, name) + "/" + keyName}
		pub, hasPub := body["public_key"].(string)
		if !hasPub || pub == "" {
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
			pub = string(pubPEM)
			resp["private_key"] = string(auth.EncodePrivateKeyPEM(key))
		}

		expiration, _ := body["expiration_date"].(string)
		if expiration == "" {
			expiration = "infinity"
		}
		stored := map[string]any{"name": keyName, "public_key": pub, "expiration_date": expiration}
		if err := org.Create(keysColl(segment, name), keyName, mustEncode(stored)); errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "Key already exists")
			return
		} else if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

func (a *API) putKey(segment string, scope scopeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := scope(w, r)
		if org == nil {
			return
		}
		name, keyName := r.PathValue("name"), r.PathValue("key")
		actor, ok := loadActor(w, org, segment, name)
		if !ok {
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		coll := keysColl(segment, name)
		_, stored, err := org.Get(coll, keyName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Updating the synthetic default key rewrites the actor's public_key.
		if keyName == defaultKeyName && !stored {
			if pub, ok := body["public_key"].(string); ok && pub != "" {
				actor["public_key"] = pub
				if err := org.Put(segment, name, mustEncode(actor)); err != nil {
					writeError(w, http.StatusInternalServerError, err.Error())
					return
				}
			}
			writeJSON(w, http.StatusOK, keyObject(defaultKeyName, str(actor["public_key"])))
			return
		}
		if !stored {
			writeError(w, http.StatusNotFound, "Cannot find key "+keyName)
			return
		}
		body["name"] = keyName
		raw := mustEncode(body)
		if err := org.Put(coll, keyName, raw); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRaw(w, http.StatusOK, raw)
	}
}

func (a *API) deleteKey(segment string, scope scopeFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := scope(w, r)
		if org == nil {
			return
		}
		name, keyName := r.PathValue("name"), r.PathValue("key")
		actor, ok := loadActor(w, org, segment, name)
		if !ok {
			return
		}
		coll := keysColl(segment, name)
		raw, ok, err := org.Delete(coll, keyName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if ok {
			writeRaw(w, http.StatusOK, raw)
			return
		}
		// Deleting the synthetic default key clears the actor's public_key.
		if keyName == defaultKeyName {
			if pk, _ := actor["public_key"].(string); pk != "" {
				delete(actor, "public_key")
				if err := org.Put(segment, name, mustEncode(actor)); err != nil {
					writeError(w, http.StatusInternalServerError, err.Error())
					return
				}
				writeJSON(w, http.StatusOK, keyObject(defaultKeyName, pk))
				return
			}
		}
		writeError(w, http.StatusNotFound, "Cannot find key "+keyName)
	}
}

func str(v any) string { s, _ := v.(string); return s }
