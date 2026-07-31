package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Assorted server endpoints: /_stats, per-org required_recipe and principals,
// plus the X-Ops-Server-API-Version negotiation applied to every response.

// Supported server API version range advertised to clients.
const (
	apiVersionMin = 0
	apiVersionMax = 2
)

func (a *API) registerServerEndpoints(mux *http.ServeMux) {
	mux.HandleFunc("GET /_stats", a.statsHandler)
	mux.HandleFunc("GET /license", a.license)
	mux.HandleFunc("GET /server_api_version", a.serverAPIVersion)
	mux.HandleFunc("GET /organizations/{org}/required_recipe", a.requiredRecipe)
	mux.HandleFunc("GET /organizations/{org}/principals/{name}", a.principal)
}

// serverAPIVersion reports the supported server API version range and the
// version negotiated for this request. The request has already passed version
// validation in withAPIVersion, so the header here is either absent (default to
// the minimum) or a supported integer.
func (a *API) serverAPIVersion(w http.ResponseWriter, r *http.Request) {
	requested, _ := parseAPIVersion(r.Header.Get("X-Ops-Server-API-Version"))
	writeJSON(w, http.StatusOK, map[string]int{
		"min_api_version":  apiVersionMin,
		"max_api_version":  apiVersionMax,
		"request_version":  requested,
		"response_version": requested,
	})
}

// license reports the server license state. A stock Chef Infra Server exposes
// this endpoint so clients can surface node-limit warnings; cinc-zero is an
// unlimited in-memory test server, so it always reports a valid, non-exceeded
// license with no nodes counted against it.
func (a *API) license(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"limit_exceeded": false,
		"node_license":   25,
		"node_count":     0,
		"upgrade_url":    "https://www.chef.io/contact-us/",
	})
}

// requiredRecipe mirrors a stock server where the feature is disabled.
func (a *API) requiredRecipe(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "Required recipe is not configured on this server.")
}

// principal resolves a name to its actor record. Org clients take precedence
// over global users, matching Chef's principal lookup.
func (a *API) principal(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	name := r.PathValue("name")

	if raw, ok, err := org.Get("clients", name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if ok {
		writeJSON(w, http.StatusOK, principalDoc(name, "client", raw))
		return
	}
	if raw, ok, err := a.store.Global().Get("users", name); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if ok {
		writeJSON(w, http.StatusOK, principalDoc(name, "user", raw))
		return
	}
	writeError(w, http.StatusNotFound, "Cannot find principal "+name)
}

func principalDoc(name, typ string, actorRaw []byte) map[string]any {
	var actor map[string]any
	json.Unmarshal(actorRaw, &actor)
	pubKey, _ := actor["public_key"].(string)
	return map[string]any{
		"name":       name,
		"type":       typ,
		"public_key": pubKey,
		"authz_id":   name,
		"org_member": true,
	}
}

// withAPIVersion negotiates the server API version on every request. It runs
// ahead of routing so version validation precedes method and content checks, as
// Chef's documented precedence requires. It advertises the supported range in
// the X-Ops-Server-API-Version response header and rejects an unacceptable
// requested version: a non-numeric header is a 400 Bad Request, while a
// well-formed version outside the supported range is a 406 Not Acceptable,
// matching Chef Infra Server's version negotiation.
func withAPIVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("X-Ops-Server-API-Version")
		requested, ok := parseAPIVersion(header)
		if !ok {
			// A malformed (non-integer) version is a bad request — distinct from a
			// well-formed but unsupported version, which is 406 below. This matches
			// Chef Infra Server, which 400s a non-numeric header and 406s an
			// out-of-range one.
			setVersionHeader(w, apiVersionMin, apiVersionMin)
			writeError(w, http.StatusBadRequest,
				"Invalid X-Ops-Server-API-Version header value "+strconv.Quote(strings.TrimSpace(header))+"; expected an integer.")
			return
		}
		response := min(max(requested, apiVersionMin), apiVersionMax)
		setVersionHeader(w, requested, response)

		if requested < apiVersionMin || requested > apiVersionMax {
			writeError(w, http.StatusNotAcceptable,
				fmt.Sprintf("Unsupported server API version %d; this server supports versions %d through %d.",
					requested, apiVersionMin, apiVersionMax))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// parseAPIVersion reads the requested API version from the header value. An
// absent (empty) header defaults to the minimum supported version. A present
// but non-integer value reports ok=false so the caller can reject it with 406.
func parseAPIVersion(header string) (version int, ok bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return apiVersionMin, true
	}
	n, err := strconv.Atoi(header)
	if err != nil {
		return 0, false
	}
	return n, true
}

// setVersionHeader writes the X-Ops-Server-API-Version negotiation document.
// Chef encodes the values as JSON strings, which clients parse back to ints.
func setVersionHeader(w http.ResponseWriter, requested, response int) {
	negotiation, _ := json.Marshal(map[string]string{
		"min_version":      strconv.Itoa(apiVersionMin),
		"max_version":      strconv.Itoa(apiVersionMax),
		"request_version":  strconv.Itoa(requested),
		"response_version": strconv.Itoa(response),
	})
	w.Header().Set("X-Ops-Server-API-Version", string(negotiation))
}
