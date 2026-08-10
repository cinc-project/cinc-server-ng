package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// Data bags are a two-level namespace: the "data_bags" collection registers the
// bags, and each bag's items live in their own "databag_items:<bag>"
// collection. Items are keyed by their "id" field rather than "name".
const dataBagsColl = "data_bags"

func dataBagItemsColl(bag string) string { return "databag_items:" + bag }

func (a *API) registerDataBagRoutes(mux *recordingMux) {
	const base = "/organizations/{org}/data"
	mux.HandleFunc("GET "+base, a.listDataBags)
	mux.HandleFunc("POST "+base, a.createDataBag)
	mux.HandleFunc("GET "+base+"/{bag}", a.listDataBagItems)
	mux.HandleFunc("POST "+base+"/{bag}", a.createDataBagItem)
	mux.HandleFunc("DELETE "+base+"/{bag}", a.deleteDataBag)
	mux.HandleFunc("GET "+base+"/{bag}/{item}", a.getDataBagItem)
	mux.HandleFunc("PUT "+base+"/{bag}/{item}", a.putDataBagItem)
	mux.HandleFunc("DELETE "+base+"/{bag}/{item}", a.deleteDataBagItem)
}

func dataBagURL(r *http.Request, org, bag string) string {
	return requestBaseURL(r) + "/organizations/" + org + "/data/" + bag
}

func (a *API) listDataBags(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	bags, err := org.Keys(dataBagsColl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]string{}
	for _, bag := range bags {
		out[bag] = dataBagURL(r, org.Name(), bag)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createDataBag(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
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
		writeError(w, http.StatusBadRequest, "Field 'name' missing")
		return
	}
	if err := org.Create(dataBagsColl, name, mustEncode(map[string]any{"name": name})); errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "Data bag already exists")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"uri": dataBagURL(r, org.Name(), name)})
}

func (a *API) deleteDataBag(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	bag := r.PathValue("bag")
	raw, ok, err := org.Delete(dataBagsColl, bag)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find data bag "+bag)
		return
	}
	// Remove the bag's items too.
	items := dataBagItemsColl(bag)
	ids, err := org.Keys(items)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, id := range ids {
		if _, _, err := org.Delete(items, id); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		writeRaw(w, http.StatusOK, raw)
		return
	}
	doc["chef_type"] = chefTypeDataBag
	doc["json_class"] = jsonClassDataBag
	writeJSON(w, http.StatusOK, doc)
}

// bagExists reports whether the named bag exists, writing a 404 if not.
func (a *API) bagExists(w http.ResponseWriter, org *store.Org, bag string) bool {
	_, ok, err := org.Get(dataBagsColl, bag)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find data bag "+bag)
		return false
	}
	return true
}

func (a *API) listDataBagItems(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	bag := r.PathValue("bag")
	if !a.bagExists(w, org, bag) {
		return
	}
	ids, err := org.Keys(dataBagItemsColl(bag))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]string{}
	for _, id := range ids {
		out[id] = dataBagURL(r, org.Name(), bag) + "/" + id
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createDataBagItem(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	bag := r.PathValue("bag")
	if !a.bagExists(w, org, bag) {
		return
	}
	raw, id, err := decodeItem(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if id == "" {
		writeError(w, http.StatusBadRequest, "Field 'id' missing")
		return
	}
	if err := org.Create(dataBagItemsColl(bag), id, raw); errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "Data bag item already exists")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var item map[string]any
	if json.Unmarshal(raw, &item) != nil {
		writeRaw(w, http.StatusCreated, raw)
		return
	}
	writeJSON(w, http.StatusCreated, withCreateEnvelope(bag, item))
}

func (a *API) getDataBagItem(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	bag := r.PathValue("bag")
	if !a.bagExists(w, org, bag) {
		return
	}
	raw, ok, err := org.Get(dataBagItemsColl(bag), r.PathValue("item"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find data bag item "+r.PathValue("item"))
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

func (a *API) putDataBagItem(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	bag := r.PathValue("bag")
	if !a.bagExists(w, org, bag) {
		return
	}
	raw, _, err := decodeItem(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := org.Put(dataBagItemsColl(bag), r.PathValue("item"), raw); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRaw(w, http.StatusOK, raw)
}

func (a *API) deleteDataBagItem(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	bag := r.PathValue("bag")
	if !a.bagExists(w, org, bag) {
		return
	}
	item := r.PathValue("item")
	raw, ok, err := org.Delete(dataBagItemsColl(bag), item)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find data bag item "+item)
		return
	}
	writeRaw(w, http.StatusOK, wrapStoredDataBagItem(bag, item, raw))
}

// decodeItem reads a data bag item body and returns canonical bytes plus its
// "id" field.
func decodeItem(r *http.Request) (raw []byte, id string, err error) {
	var obj map[string]any
	if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
		return nil, "", err
	}
	id, _ = obj["id"].(string)
	return mustEncode(obj), id, nil
}
