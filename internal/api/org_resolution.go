package api

import (
	"context"
	"net/http"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// Authorization and the handler must act on the same org. A request naming an
// org that does not exist has nothing to be authorized against, so it passes
// through for the handler to answer 404; were the handler to look the org up
// again, an org created in between would be served to a request no membership
// gate or ACL had judged against it. So the first lookup of the path's org
// is recorded in the request, and every later one (the gate, authorize, the
// handler) answers from that record.

const orgResolutionContextKey ctxKey = 2

// orgResolution is what the first lookup found under the org name: the org,
// or nil when it did not exist.
type orgResolution struct {
	name string
	org  *store.Org
}

// lookupOrg returns the named org and whether it exists, as first found for
// this request: from r's record when there is one for name, and otherwise
// from the store, returning r with the answer recorded.
func (a *API) lookupOrg(r *http.Request, name string) (*http.Request, *store.Org, bool, error) {
	if res, ok := recordedOrg(r, name); ok {
		return r, res.org, res.org != nil, nil
	}
	org, ok, err := a.store.Org(name)
	if err != nil {
		return r, nil, false, err
	}
	if !ok {
		org = nil
	}
	r = r.WithContext(context.WithValue(r.Context(), orgResolutionContextKey, orgResolution{name: name, org: org}))
	return r, org, ok, nil
}

// recordedOrg returns r's recorded lookup of the named org, if any.
func recordedOrg(r *http.Request, name string) (orgResolution, bool) {
	res, ok := r.Context().Value(orgResolutionContextKey).(orgResolution)
	if !ok || res.name != name {
		return orgResolution{}, false
	}
	return res, true
}

// orgMissingWhenAuthorized reports whether the request was authorized when
// the named org did not exist. A handler that reads the org from somewhere
// other than lookupOrg (the global org metadata) answers 404 when it does.
func orgMissingWhenAuthorized(r *http.Request, name string) bool {
	res, ok := recordedOrg(r, name)
	return ok && res.org == nil
}
