package api

import (
	"encoding/json"
	"math/big"
	"net/http"
	"strconv"

	"github.com/cinc-project/cinc-server-ng/internal/chefjson"
	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Assorted server endpoints: /_stats, per-org required_recipe and principals,
// plus the X-Ops-Server-API-Version negotiation applied to every response.

// Supported server API version range advertised to clients.
const (
	apiVersionMin = 0
	apiVersionMax = 2
)

func (a *API) registerServerEndpoints(mux *recordingMux) {
	mux.HandleFunc("GET /_stats", a.statsHandler)
	mux.HandleFunc("GET /license", a.license)
	mux.HandleFunc("GET /server_api_version", a.serverAPIVersion)
	mux.HandleFunc("GET /organizations/{org}/required_recipe", a.requiredRecipe)
	mux.HandleFunc("GET /organizations/{org}/principals/{name}", a.principal)
}

// serverAPIVersion reports the supported server API version range and nothing
// else (oc_chef_wm_server_api_version:version_body). Like erchef's, it needs a
// signed request from any requestor.
func (a *API) serverAPIVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, struct {
		Min int `json:"min_api_version"`
		Max int `json:"max_api_version"`
	}{apiVersionMin, apiVersionMax})
}

// license reports the server license state. A stock Chef Infra Server exposes
// this endpoint so clients can surface node-limit warnings; cinc-server-ng is an
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

// principalJSON is one principal in erchef's member order
// (chef_wm_named_principal:assemble_principal_ejson).
type principalJSON struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Type      string `json:"type"`
	AuthzID   string `json:"authz_id"`
	OrgMember bool   `json:"org_member"`
}

// principal resolves a name to the actors that answer to it, as
// chef_wm_named_principal does.
//
// Under API v0 (which is also what an unversioned request gets, in erchef and
// here) the answer is a single object: the org client if there is one, else
// the global user. Under v1 and later it is {"principals":[...]}, read from
// erchef's keys_by_name view: one entry per unexpired key of every matching
// actor, users ahead of clients (ORDER BY type DESC; erchef defines no order
// among one actor's keys, and neither does this). A name with no entries
// is a 404 either way. org_member is always true for a client and, for a user,
// whether the user is associated with the org.
func (a *API) principal(w http.ResponseWriter, r *http.Request) {
	org := a.org(w, r)
	if org == nil {
		return
	}
	name := r.PathValue("name")

	v0 := requestAPIVersion(r) == 0
	var (
		found []principalJSON
		err   error
	)
	if v0 {
		found, err = a.principalV0(org, name)
	} else {
		found, err = a.principalsByKey(org, name)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(found) == 0 {
		writeJSON(w, http.StatusNotFound, struct {
			NotFound string `json:"not_found"`
			Error    string `json:"error"`
		}{"principal", "Cannot find principal " + name})
		return
	}
	if v0 {
		writeJSON(w, http.StatusOK, found[0])
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"principals": found})
}

// principalV0 is erchef's v0 lookup (chef_db:fetch_requestor): the org client
// of that name, falling back to the global user, with the record's own key.
func (a *API) principalV0(org *store.Org, name string) ([]principalJSON, error) {
	for _, src := range []struct {
		scope *store.Org
		coll  string
		typ   string
	}{{org, "clients", "client"}, {a.store.Global(), "users", "user"}} {
		raw, ok, err := src.scope.Get(src.coll, name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		pub, _ := chefjson.String(raw, "public_key")
		member, err := principalOrgMember(org, src.typ, name)
		if err != nil {
			return nil, err
		}
		return []principalJSON{{name, pub, src.typ, name, member}}, nil
	}
	return nil, nil
}

// principalsByKey is erchef's v1+ lookup (chef_db:fetch_requestors over
// keys_by_name): every unexpired key of the matching user, then of the
// matching org client, one entry per key.
func (a *API) principalsByKey(org *store.Org, name string) ([]principalJSON, error) {
	var out []principalJSON
	now := a.now()
	for _, src := range []struct {
		scope *store.Org
		coll  string
		typ   string
	}{{a.store.Global(), "users", "user"}, {org, "clients", "client"}} {
		raw, ok, err := src.scope.Get(src.coll, name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		pub, _ := chefjson.String(raw, "public_key")
		keys, err := SigningKeys(src.scope, src.coll, name, pub, now)
		if err != nil {
			return nil, err
		}
		if len(keys) == 0 {
			continue
		}
		member, err := principalOrgMember(org, src.typ, name)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			out = append(out, principalJSON{name, k, src.typ, name, member})
		}
	}
	return out, nil
}

// principalOrgMember is oc_chef_wm_base:is_user_in_org/4: a client is always
// a member of its org, and a user is one when associated with it.
func principalOrgMember(org *store.Org, typ, name string) (bool, error) {
	if typ == "client" {
		return true, nil
	}
	_, ok, err := org.Get(assocColl, name)
	return ok, err
}

// WithAPIVersion negotiates the server API version on every request, as
// oc_chef_wm_base:service_available does. erchef judges the header there,
// ahead of malformed_request and is_authorized, so an unacceptable version is
// a 406 even on an unsigned request: the server runs this outside its
// signature check (Handler applies it as well, for library use; a second pass
// is idempotent). It also runs ahead of routing, so version validation
// precedes method and content checks.
//
// No header is version 0. A header that is not an integer, or one outside the
// supported range, is erchef's 406 (invalid_server_api_version_response). A
// header sent with no value is not an integer: list_to_integer("") fails.
func WithAPIVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("X-Ops-Server-API-Version")
		if len(values) == 0 {
			setVersionHeader(w, "0", "0")
			next.ServeHTTP(w, r)
			return
		}
		raw := values[0]
		// big.Int in base 10 accepts what list_to_integer does: an optional
		// sign and decimal digits, of any size.
		n, isInt := new(big.Int).SetString(raw, 10)
		if isInt && n.IsInt64() && n.Int64() >= apiVersionMin && n.Int64() <= apiVersionMax {
			v := n.String()
			setVersionHeader(w, v, v)
			next.ServeHTTP(w, r)
			return
		}
		// add_api_info_header(_, _, not_acceptable): the requested version as
		// an integer, -1 when it is not one, and a response version of -1.
		requested := "-1"
		if isInt {
			requested = n.String()
		}
		setVersionHeader(w, requested, "-1")
		writeJSON(w, http.StatusNotAcceptable, struct {
			Error   string `json:"error"`
			Message string `json:"message"`
			Min     int    `json:"min_version"`
			Max     int    `json:"max_version"`
		}{"invalid-x-ops-server-api-version", "Specified version " + raw + " not supported", apiVersionMin, apiVersionMax})
	})
}

// requestAPIVersion is the server API version a request asked for;
// WithAPIVersion has already rejected a malformed or unsupported one.
func requestAPIVersion(r *http.Request) int {
	v, err := strconv.Atoi(r.Header.Get("X-Ops-Server-API-Version"))
	if err != nil {
		return apiVersionMin
	}
	return v
}

// setVersionHeader writes the X-Ops-Server-API-Version negotiation document in
// oc_chef_wm_base:build_api_info_header_body's form: this member order, every
// value a JSON string.
func setVersionHeader(w http.ResponseWriter, requested, response string) {
	negotiation, _ := json.Marshal(struct {
		Min      string `json:"min_version"`
		Max      string `json:"max_version"`
		Request  string `json:"request_version"`
		Response string `json:"response_version"`
	}{strconv.Itoa(apiVersionMin), strconv.Itoa(apiVersionMax), requested, response})
	w.Header().Set("X-Ops-Server-API-Version", string(negotiation))
}
