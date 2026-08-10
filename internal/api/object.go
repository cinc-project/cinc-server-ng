package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// listBufPool reuses response buffers across list requests so a large list does
// not allocate (and discard) its whole JSON body every time.
var listBufPool = sync.Pool{New: func() any { b := make([]byte, 0, 4096); return &b }}

// registerObjectRoutes wires the standard Chef CRUD routes for a "named JSON
// object" collection such as nodes, roles, or environments. These share an
// identical shape: a list endpoint returning name->URL, plus create/get/
// update/delete/head on individual named objects.
func (a *API) registerObjectRoutes(mux *recordingMux, segment string) {
	base := "/organizations/{org}/" + segment
	mux.HandleFunc("GET "+base, a.listObjects(segment))
	mux.HandleFunc("POST "+base, a.createObject(segment))
	mux.HandleFunc("GET "+base+"/{name}", a.getObject(segment))
	mux.HandleFunc("PUT "+base+"/{name}", a.putObject(segment))
	mux.HandleFunc("DELETE "+base+"/{name}", a.deleteObject(segment))
	mux.HandleFunc("HEAD "+base+"/{name}", a.headObject(segment))
}

// objectURL builds the absolute URL for a named object. Global collections
// (users, which are not org-scoped) pass an empty org and are addressed at the
// top level — "/users/{name}" — rather than under "/organizations//...".
func objectURL(r *http.Request, org, segment, name string) string {
	if org == "" {
		return requestBaseURL(r) + "/" + segment + "/" + name
	}
	return requestBaseURL(r) + "/organizations/" + org + "/" + segment + "/" + name
}

// listObjects returns the collection's name->URL map. The keys are already
// sorted by the store, so the response is streamed directly into a reusable
// buffer — writing the shared URL prefix once per entry — instead of building an
// intermediate map and re-sorting and reflecting over it in encoding/json.
func (a *API) listObjects(segment string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := a.org(w, r)
		if org == nil {
			return
		}
		keys, err := org.Keys(segment) // sorted
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Every value is the same prefix followed by the (escaped) name; escape the
		// constant prefix once rather than per entry.
		prefix := appendJSONStringContent(nil, objectURL(r, org.Name(), segment, ""))

		bufp := listBufPool.Get().(*[]byte)
		b := append((*bufp)[:0], '{')
		for i, k := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, '"')
			b = appendJSONStringContent(b, k)
			b = append(b, '"', ':', '"')
			b = append(b, prefix...)
			b = appendJSONStringContent(b, k)
			b = append(b, '"')
		}
		b = append(b, '}')
		writeRaw(w, http.StatusOK, b)
		*bufp = b
		listBufPool.Put(bufp)
	}
}

// decodeNamedBody reads the request body as a JSON object and returns the
// canonical bytes plus the value of its "name" field.
func decodeNamedBody(r *http.Request) (raw []byte, name string, err error) {
	var obj map[string]any
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&obj); err != nil {
		return nil, "", err
	}
	n, _ := obj["name"].(string)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		return nil, "", err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), n, nil
}

func (a *API) createObject(segment string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := a.org(w, r)
		if org == nil {
			return
		}
		raw, name, err := decodeNamedBody(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if name == "" {
			writeError(w, http.StatusBadRequest, "Field 'name' missing")
			return
		}
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
		writeJSON(w, http.StatusCreated, map[string]string{
			"uri": objectURL(r, org.Name(), segment, name),
		})
	}
}

func (a *API) getObject(segment string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := a.org(w, r)
		if org == nil {
			return
		}
		name := r.PathValue("name")
		raw, ok, err := viewObject(r, org, segment, name)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, "Cannot find "+segment+" "+name)
			return
		}
		writeRaw(w, http.StatusOK, raw)
	}
}

func (a *API) putObject(segment string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := a.org(w, r)
		if org == nil {
			return
		}
		name := r.PathValue("name")
		raw, _, err := decodeNamedBody(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if err := org.Put(segment, name, raw); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRaw(w, http.StatusOK, raw)
	}
}

func (a *API) deleteObject(segment string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := a.org(w, r)
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
		writeRaw(w, http.StatusOK, raw)
	}
}

func (a *API) headObject(segment string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org := a.org(w, r)
		if org == nil {
			return
		}
		_, ok, err := viewObject(r, org, segment, r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
