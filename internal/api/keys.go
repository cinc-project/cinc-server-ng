package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Key management implements Chef's v1 key API for actors (clients and users).
// Named keys live in a per-actor collection ("<segment>_keys:<actor>") within
// the actor's scope (org for clients, global for users). As with actor
// creation, a key POSTed without a public_key has one generated, and the
// private key is returned once.
//
// The "default" key is the stored "default" row when there is one, and is
// otherwise synthesized from the actor record's public_key (which is where
// actor creation puts it). Writes through the keys API keep the actor's
// public_key in step with the default key, so the two never disagree about
// which key material is the default.
//
// Every key the keys API lists authenticates its actor until it expires, as in
// Chef Infra Server: SigningKeys is the single definition of that set, shared by
// the key list and the authentication layer.

const defaultKeyName = "default"

// infinity is the expiration_date of a key that never expires.
const infinity = "infinity"

// keyExpired reports whether a key with this expiration_date has expired at
// now. "infinity" (or no date at all, which is how a key POSTed without one is
// treated) never expires; a date that does not parse counts as expired, so a
// malformed key can never authenticate.
func keyExpired(expiration string, now time.Time) bool {
	if expiration == "" || expiration == infinity {
		return false
	}
	at, err := time.Parse(time.RFC3339, expiration)
	if err != nil {
		return true
	}
	return !at.After(now)
}

// storedKey is the shape of a row in an actor's keys collection.
type storedKey struct {
	PublicKey      string `json:"public_key"`
	ExpirationDate string `json:"expiration_date"`
}

// SigningKeys returns the public keys (PEM) that authenticate the named actor
// at now: every key the keys API lists for it, minus the expired ones.
// actorPublicKey is the public_key on the actor's record, which is the default
// key unless a stored "default" row takes its place.
func SigningKeys(org *store.Org, segment, name, actorPublicKey string, now time.Time) ([]string, error) {
	var keys []string
	storedDefault := false
	err := org.Range(keysColl(segment, name), func(keyName string, raw []byte) bool {
		if keyName == defaultKeyName {
			storedDefault = true
		}
		var k storedKey
		if json.Unmarshal(raw, &k) != nil || k.PublicKey == "" || keyExpired(k.ExpirationDate, now) {
			return true
		}
		keys = append(keys, k.PublicKey)
		return true
	})
	if err != nil {
		return nil, err
	}
	if !storedDefault && actorPublicKey != "" {
		keys = append(keys, actorPublicKey)
	}
	return keys, nil
}

// setActorPublicKey records pub as the actor's public_key (the default key's
// material), or removes the field when pub is empty.
func setActorPublicKey(org *store.Org, segment, name string, actor map[string]any, pub string) error {
	if pub == "" {
		delete(actor, "public_key")
	} else {
		actor["public_key"] = pub
	}
	return org.Put(segment, name, mustEncode(actor))
}

// setStoredDefaultPublicKey points a stored "default" key row at pub, so an
// actor update that carries a new public_key rotates the default key even after
// the keys API has stored it as a row. It does nothing when there is no row.
func setStoredDefaultPublicKey(org *store.Org, segment, name, pub string) error {
	coll := keysColl(segment, name)
	raw, ok, err := org.Get(coll, defaultKeyName)
	if err != nil || !ok {
		return err
	}
	var row map[string]any
	if err := json.Unmarshal(raw, &row); err != nil {
		return err
	}
	row["public_key"] = pub
	return org.Put(coll, defaultKeyName, mustEncode(row))
}

// deleteActorKeys removes every key an actor holds. A deleted actor's keys must
// not outlive it: they authenticate by actor name, so a later actor registered
// under the same name would otherwise inherit them.
func deleteActorKeys(org *store.Org, segment, name string) error {
	coll := keysColl(segment, name)
	names, err := org.Keys(coll)
	if err != nil {
		return err
	}
	for _, kn := range names {
		if _, _, err := org.Delete(coll, kn); err != nil {
			return err
		}
	}
	return nil
}

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
				out = append(out, keyListItem(base, defaultKeyName, false))
			}
		}
		kns, err := org.Keys(coll)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		now := a.now()
		for _, kn := range kns {
			raw, ok, err := org.Get(coll, kn)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if !ok {
				continue
			}
			var k storedKey
			_ = json.Unmarshal(raw, &k)
			out = append(out, keyListItem(base, kn, keyExpired(k.ExpirationDate, now)))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func keyListItem(base, name string, expired bool) map[string]any {
	return map[string]any{"name": name, "uri": base + "/" + name, "expired": expired}
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
		actor, ok := loadActor(w, org, segment, name)
		if !ok {
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
		if msg := validateKeyFields(body); msg != "" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
		// The default key made with the actor is a key like any other, so a
		// second "default" conflicts with it even though it has no stored row.
		if keyName == defaultKeyName && str(actor["public_key"]) != "" {
			writeError(w, http.StatusConflict, "Key already exists")
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
		if keyName == defaultKeyName {
			if err := setActorPublicKey(org, segment, name, actor, pub); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
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
		// As erchef's chef_key_base:maybe_generate_key_pair: create_key asks the
		// server for a new pair in place of the key's public_key, so asking for
		// both is contradictory. The flag is a request, never part of the key.
		createKey, _ := body["create_key"].(bool)
		delete(body, "create_key")
		if createKey && str(body["public_key"]) != "" {
			writeError(w, http.StatusBadRequest, "Since you requested a new key be created, you cannot also specify a public_key.")
			return
		}
		if msg := validateKeyFields(body); msg != "" {
			writeError(w, http.StatusBadRequest, msg)
			return
		}
		coll := keysColl(segment, name)
		_, stored, err := org.Get(coll, keyName)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !stored && keyName != defaultKeyName {
			writeError(w, http.StatusNotFound, "Cannot find key "+keyName)
			return
		}
		privateKey := ""
		if createKey {
			pub, priv, err := generateKeyPair()
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			body["public_key"], privateKey = pub, priv
		}

		// Updating the synthetic default key stores it as a row, so it keeps the
		// expiration_date it is given, and rewrites the actor's public_key.
		if keyName == defaultKeyName && !stored {
			pub := str(actor["public_key"])
			if pub == "" {
				writeError(w, http.StatusNotFound, "Cannot find key "+keyName)
				return
			}
			if p := str(body["public_key"]); p != "" {
				pub = p
			}
			expiration := str(body["expiration_date"])
			if expiration == "" {
				expiration = infinity
			}
			raw := mustEncode(map[string]any{"name": defaultKeyName, "public_key": pub, "expiration_date": expiration})
			if err := org.Put(coll, defaultKeyName, raw); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if err := setActorPublicKey(org, segment, name, actor, pub); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if privateKey != "" {
				// The private half goes back in the response only; it is never stored.
				resp := map[string]any{"name": defaultKeyName, "public_key": pub, "expiration_date": expiration, "private_key": privateKey}
				writeJSON(w, http.StatusOK, resp)
				return
			}
			writeRaw(w, http.StatusOK, raw)
			return
		}
		body["name"] = keyName
		raw := mustEncode(body)
		if err := org.Put(coll, keyName, raw); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if pub := str(body["public_key"]); keyName == defaultKeyName && pub != "" {
			if err := setActorPublicKey(org, segment, name, actor, pub); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		if privateKey != "" {
			// The private half goes back in the response only; it is never stored.
			body["private_key"] = privateKey
			writeJSON(w, http.StatusOK, body)
			return
		}
		writeRaw(w, http.StatusOK, raw)
	}
}

// generateKeyPair makes a new RSA key pair, returning the public half and the
// private half as PEM.
func generateKeyPair() (pub, priv string, err error) {
	key, err := auth.GenerateKey()
	if err != nil {
		return "", "", errors.New("key generation failed")
	}
	pubPEM, err := auth.EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		return "", "", errors.New("key encoding failed")
	}
	return string(pubPEM), string(auth.EncodePrivateKeyPEM(key)), nil
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
			// The actor's public_key mirrors the default key, so it goes too.
			if keyName == defaultKeyName && str(actor["public_key"]) != "" {
				if err := setActorPublicKey(org, segment, name, actor, ""); err != nil {
					writeError(w, http.StatusInternalServerError, err.Error())
					return
				}
			}
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
