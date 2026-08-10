package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// cookbook_artifacts hold the immutable, content-addressed cookbooks that
// Policyfiles pin to. They mirror cookbooks but are keyed by an opaque
// identifier rather than a version, share the same blob store and manifest
// shape, and have no _latest/_recipes aliases.

func (a *API) registerCookbookArtifactRoutes(mux *recordingMux) {
	const base = "/organizations/{org}/cookbook_artifacts"
	mux.HandleFunc("GET "+base, a.listArtifacts)
	mux.HandleFunc("GET "+base+"/{name}", a.getArtifact)
	mux.HandleFunc("GET "+base+"/{name}/{identifier}", a.getArtifactVersion)
	mux.HandleFunc("PUT "+base+"/{name}/{identifier}", a.putArtifactVersion)
	mux.HandleFunc("DELETE "+base+"/{name}/{identifier}", a.deleteArtifactVersion)
}

// artifactIdentifiers returns name -> identifiers (sorted), since artifact
// identifiers are opaque hashes with no meaningful version ordering.
func artifactIdentifiers(org *store.Org) (map[string][]string, error) {
	out := map[string][]string{}
	keys, err := org.Keys("cookbook_artifacts")
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		name, ident, ok := strings.Cut(key, "/")
		if !ok {
			continue
		}
		out[name] = append(out[name], ident)
	}
	for _, idents := range out {
		sort.Strings(idents)
	}
	return out, nil
}

func (a *API) listArtifacts(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	idents, err := artifactIdentifiers(org)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, collectionListBody(r, org, "cookbook_artifacts", "identifier", idents))
}

func (a *API) getArtifact(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	name := r.PathValue("name")
	all, err := artifactIdentifiers(org)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	idents, ok := all[name]
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find a cookbook artifact named "+name)
		return
	}
	writeJSON(w, http.StatusOK, collectionListBody(r, org, "cookbook_artifacts", "identifier", map[string][]string{name: idents}))
}

func (a *API) getArtifactVersion(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	name, ident := r.PathValue("name"), r.PathValue("identifier")
	raw, ok, err := org.Get("cookbook_artifacts", cookbookKey(name, ident))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find a cookbook artifact named "+name+" with identifier "+ident)
		return
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		writeRaw(w, http.StatusOK, raw)
		return
	}
	a.injectFileURLs(m, r, org.Name())
	writeJSON(w, http.StatusOK, m)
}

func (a *API) putArtifactVersion(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	name, ident := r.PathValue("name"), r.PathValue("identifier")

	// Artifacts are content-addressed and immutable: an existing identifier is
	// never overwritten.
	if _, existed, err := org.Get("cookbook_artifacts", cookbookKey(name, ident)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if existed {
		writeError(w, http.StatusConflict,
			"Cookbook artifact "+name+" with identifier "+ident+" already exists")
		return
	}

	var m map[string]any
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	for _, sum := range manifestChecksums(m) {
		has, err := org.HasBlob(sum)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !has {
			writeError(w, http.StatusBadRequest, "Manifest has a checksum that hasn't been uploaded: "+sum)
			return
		}
	}
	if err := org.Put("cookbook_artifacts", cookbookKey(name, ident), mustEncode(m)); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.injectFileURLs(m, r, org.Name())
	writeJSON(w, http.StatusCreated, m)
}

func (a *API) deleteArtifactVersion(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	name, ident := r.PathValue("name"), r.PathValue("identifier")
	raw, ok, err := org.Delete("cookbook_artifacts", cookbookKey(name, ident))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find a cookbook artifact named "+name+" with identifier "+ident)
		return
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		if err := gcOrphanedBlobs(org, manifestChecksums(m)); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.injectFileURLs(m, r, org.Name())
		writeJSON(w, http.StatusOK, m)
		return
	}
	writeRaw(w, http.StatusOK, raw)
}
