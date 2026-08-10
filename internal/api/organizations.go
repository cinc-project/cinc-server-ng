package api

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/tas50/cinc-server-ng/internal/auth"
	"github.com/tas50/cinc-server-ng/internal/store"
)

// orgsColl is the global collection holding organization metadata
// ({name, full_name, guid}).
const orgsColl = "organizations"

func (a *API) registerOrganizationRoutes(mux *recordingMux) {
	mux.HandleFunc("GET /organizations", a.listOrganizations)
	mux.HandleFunc("POST /organizations", a.createOrganization)
	mux.HandleFunc("GET /organizations/{org}", a.getOrganization)
	mux.HandleFunc("PUT /organizations/{org}", a.putOrganization)
	mux.HandleFunc("DELETE /organizations/{org}", a.deleteOrganization)
}

// CreateOrganization provisions a new organization with a freshly generated
// validator key. See CreateOrganizationWithKey; this is the convenience form
// used by the POST handler, where one key is generated on demand.
func CreateOrganization(st *store.Store, name, fullName string) ([]byte, error) {
	key, err := auth.GenerateKey()
	if err != nil {
		return nil, err
	}
	return CreateOrganizationWithKey(st, name, fullName, key)
}

// CreateOrganizationWithKey provisions a new organization using the provided
// validator key: it creates the org in the store, seeds the _default
// environment, registers org metadata, and creates the "<name>-validator"
// client. It returns the validator's PEM-encoded private key, which Chef returns
// exactly once at creation time. Taking the key as a parameter lets the server
// bootstrap generate all of its keys in parallel (the slow part) and then seed
// the store serially. This helper is shared by the POST handler and bootstrap.
func CreateOrganizationWithKey(st *store.Store, name, fullName string, key *rsa.PrivateKey) ([]byte, error) {
	guid, err := randomGUID()
	if err != nil {
		return nil, err
	}
	pubPEM, err := auth.EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	meta := map[string]any{"name": name, "full_name": fullName, "guid": guid}
	validator := name + "-validator"
	clientDoc := fmt.Sprintf(`{"name":%q,"clientname":%q,"validator":true,"public_key":%q}`,
		validator, validator, string(pubPEM))
	// Grant the validator create on the clients container, mirroring a real org
	// where the validator key can register new clients/nodes. This is structural
	// until ACL enforcement is enabled, at which point it lets a freshly
	// bootstrapped org behave like a real one.
	clientsACL := defaultACL()
	clientsACL["create"] = map[string]any{"actors": []string{validator}, "groups": []string{"admins", "users"}}

	// Grant the "clients" group create on the nodes container, mirroring real
	// Chef: a registered client (which joins that group) can create its own node.
	// Item operations on a node remain governed by its per-object ACL.
	nodesACL := defaultACL()
	nodesACL["create"] = map[string]any{"actors": []string{}, "groups": []string{"admins", "users", "clients"}}

	// Provision the org atomically: a failure partway through (more likely on a
	// durable backend) must not leave a half-created organization behind.
	if err := st.Tx(func(tx *store.Store) error {
		org, err := tx.CreateOrg(name)
		if err != nil {
			return err
		}
		if err := SeedOrg(org); err != nil {
			return err
		}
		if err := tx.Global().Put(orgsColl, name, mustEncode(meta)); err != nil {
			return err
		}
		if err := org.Put("clients", validator, []byte(clientDoc)); err != nil {
			return err
		}
		if err := org.Put("acls", aclKey("containers", "clients"), mustEncode(clientsACL)); err != nil {
			return err
		}
		return org.Put("acls", aclKey("containers", "nodes"), mustEncode(nodesACL))
	}); err != nil {
		return nil, err
	}

	return auth.EncodePrivateKeyPEM(key), nil
}

func randomGUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (a *API) listOrganizations(w http.ResponseWriter, r *http.Request) {
	out := map[string]string{}
	names, err := a.store.Global().Keys(orgsColl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, name := range names {
		out[name] = requestBaseURL(r) + "/organizations/" + name
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createOrganization(w http.ResponseWriter, r *http.Request) {
	var obj map[string]any
	if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	name, _ := obj["name"].(string)
	if name == "" {
		writeError(w, http.StatusBadRequest, "Field 'name' missing")
		return
	}
	fullName, _ := obj["full_name"].(string)

	priv, err := CreateOrganization(a.store, name, fullName)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "Organization already exists")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"clientname":  name + "-validator",
		"private_key": string(priv),
		"uri":         requestBaseURL(r) + "/organizations/" + name,
	})
}

func (a *API) getOrganization(w http.ResponseWriter, r *http.Request) {
	raw, ok, err := a.store.Global().Get(orgsColl, r.PathValue("org"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find org "+r.PathValue("org"))
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

func (a *API) putOrganization(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("org")
	raw, ok, err := a.store.Global().Get(orgsColl, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find org "+name)
		return
	}
	var meta map[string]any
	json.Unmarshal(raw, &meta)

	var update map[string]any
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if fn, ok := update["full_name"].(string); ok {
		meta["full_name"] = fn
	}
	encoded := mustEncode(meta)
	if err := a.store.Global().Put(orgsColl, name, encoded); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRaw(w, http.StatusOK, encoded)
}

func (a *API) deleteOrganization(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("org")
	raw, ok, err := a.store.Global().Delete(orgsColl, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find org "+name)
		return
	}
	if _, err := a.store.DeleteOrg(name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRaw(w, http.StatusOK, raw)
}
