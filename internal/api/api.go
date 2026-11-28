// Package api implements the Chef Infra Server HTTP API surface over the
// in-memory store. Handlers operate on a *store.Org and emit Chef-shaped JSON.
// Authentication is a separate layer wrapped around this handler, so these
// handlers can be exercised directly in tests.
package api

import (
	"crypto/rsa"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// API holds the dependencies shared by all handlers.
type API struct {
	store *store.Store
	// enforceACL turns on authorization enforcement: when set, requests are
	// checked against object ACLs and group membership before reaching a
	// handler. When clear (the default) every authenticated actor is permitted.
	enforceACL bool
	// fileStoreKey signs the pre-signed cookbook file-store URLs the server
	// hands to clients. When empty (the default) those URLs carry no grant and
	// the file store is open, matching the permissive zero value the rest of the
	// package uses; server.New sets a key whenever authentication is on.
	fileStoreKey []byte
	// search memoizes the flattened searchable view of each document so repeated
	// queries skip re-unmarshalling and re-flattening unchanged objects.
	search *searchCache
	// groups memoizes the reverse index of group membership, rebuilt only when
	// the store reports that groups changed.
	groups *groupIndexCache
	// searchIdx holds the inverted index for each searched collection, built on
	// first use and kept current from the store's write stream.
	searchIdx *searchIndexes
	// stats holds the server's instruments, served by /_stats.
	stats *instruments
	// mux is the router, retained so authorization can ask whether a request
	// reaches a real route before refusing it.
	mux *recordingMux
	// routes are the patterns registered, so a test can require every mutating
	// one to be authorized.
	routes []string
	// externalURL, when set, is the scheme://host prefix of every URL the
	// server hands back, in place of one rebuilt from the request.
	externalURL string
	// draining is set once the server is shutting down; /_status then fails
	// so a load balancer stops routing here.
	draining atomic.Bool
	// now is the clock that decides whether an actor's key has expired.
	// Defaults to time.Now.
	now func() time.Time
	// generateKey makes the key pairs the keys API hands out. Defaults to
	// auth.GenerateKey.
	generateKey func() (*rsa.PrivateKey, error)
	// afterAuthorize, when set, runs once a request has passed authorization
	// and before its handler: a test seam for what changes in between.
	afterAuthorize func(*http.Request)
	// membership orders group-membership changes against revocations; see
	// groupmembers.go.
	membership sync.RWMutex
}

// Option configures an API at construction time.
type Option func(*API)

// WithACLEnforcement enables (or disables) authorization enforcement.
func WithACLEnforcement(enabled bool) Option {
	return func(a *API) { a.enforceACL = enabled }
}

// WithFileStoreKey sets the key used to pre-sign cookbook file-store URLs. The
// authentication layer must verify grants with the same key. Leave it unset to
// keep the file store open (the permissive default for direct API-layer use).
func WithFileStoreKey(key []byte) Option {
	return func(a *API) { a.fileStoreKey = key }
}

// WithExternalURL fixes the scheme://host prefix of the absolute URLs the
// server returns (erchef's base_resource_url), for deployments where the
// request's Host and X-Forwarded-Proto do not carry the public address. The
// caller validates it; an empty value keeps deriving the prefix per request.
func WithExternalURL(base string) Option {
	return func(a *API) { a.externalURL = base }
}

// WithClock sets the clock used to decide whether an actor's key has expired.
// The authentication layer must judge expiry by the same clock.
func WithClock(now func() time.Time) Option {
	return func(a *API) {
		if now != nil {
			a.now = now
		}
	}
}

// New returns an API backed by st, applying any options.
func New(st *store.Store, opts ...Option) *API {
	a := &API{
		store:     st,
		search:    newSearchCache(),
		groups:    newGroupIndexCache(),
		searchIdx: newSearchIndexes(),
		now:       time.Now,

		generateKey: auth.GenerateKey,
	}
	for _, opt := range opts {
		opt(a)
	}
	// Instruments are registered after the options are applied so they can read
	// through to whatever the API was configured with.
	a.stats = newInstruments(a)
	// Keep the derived indexes current as data changes beneath us.
	st.Watch(a.searchIdx.observe)
	st.Watch(a.groups.observe)
	return a
}

// Handler builds the HTTP handler exposing the full API surface.
func (a *API) Handler() http.Handler {
	mux := newRecordingMux()
	a.mux = mux
	a.registerSystemRoutes(mux)
	a.registerObjectRoutes(mux, "nodes")
	a.registerObjectRoutes(mux, "roles")
	a.registerEnvironmentRoutes(mux)
	a.registerEnvironmentSubRoutes(mux)

	orgScope := func(w http.ResponseWriter, r *http.Request) *store.Org { return a.org(w, r) }
	globalScope := func(_ http.ResponseWriter, r *http.Request) *store.Org { return a.store.Global().As(actorID(r)) }
	a.registerActorRoutes(mux, "/organizations/{org}/", "clients", orgScope)
	a.registerActorRoutes(mux, "/", "users", globalScope)
	a.registerKeyRoutes(mux, "/organizations/{org}/", "clients", orgScope)
	a.registerKeyRoutes(mux, "/", "users", globalScope)
	a.registerDataBagRoutes(mux)
	a.registerCookbookRoutes(mux)
	a.registerCookbookArtifactRoutes(mux)
	a.registerSearchRoutes(mux)
	a.registerACLRoutes(mux)
	a.registerAuthenticateRoutes(mux)
	a.registerAssociationRoutes(mux)
	a.registerAssociationRequestRoutes(mux)
	a.registerPolicyRoutes(mux)
	a.registerOrganizationRoutes(mux)
	a.registerAuthzRoutes(mux)
	a.registerServerAdminRoutes(mux)
	a.registerServerEndpoints(mux)

	a.routes = mux.patterns

	h := withJSONErrors(mux)
	if a.enforceACL {
		h = a.authzMiddleware(h)
	}
	h = WithoutTrailingSlash(WithAPIVersion(h))
	if a.externalURL != "" {
		h = withExternalURL(a.externalURL, h)
	}
	return h
}

// WithoutTrailingSlash routes "/users/" as "/users", as Chef Infra Server does
// (webmachine matches path tokens, so a trailing slash is not one), and real
// clients rely on it: knife user create posts to "/users/". Authorization
// classifies requests by path, and an unrecognized read is allowed through, so
// a slash that survived to that point could make "/nodes/web01/" skip its ACL
// check and then route anyway. The server applies it ahead of authentication
// too, so that every layer decides on the one path the router routes.
//
// The slashes are trimmed from the escaped path, as received, and the decoded
// path is derived from what is left: an escaped slash (%2F) is part of a name,
// not a separator, and stays. Trimming the decoded path instead would drop
// the slash a trailing %2F decodes to while RawPath kept it; url.URL then
// discards RawPath as stale and re-encodes Path, turning "file_store%2Fx%2F"
// into the two segments "file_store/x" after the auth layer had judged it one.
func WithoutTrailingSlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped := r.URL.EscapedPath()
		if len(escaped) <= 1 || !strings.HasSuffix(escaped, "/") {
			next.ServeHTTP(w, r)
			return
		}
		trimmed := strings.TrimRight(escaped, "/")
		if trimmed == "" {
			trimmed = "/"
		}
		decoded, err := url.PathUnescape(trimmed)
		if err != nil {
			// EscapedPath only returns a valid encoding; this is unreachable.
			writeError(w, http.StatusBadRequest, "invalid request path")
			return
		}
		r = r.Clone(r.Context())
		r.URL.Path = decoded
		r.URL.RawPath = trimmed
		next.ServeHTTP(w, r)
	})
}

// org resolves the {org} path value to its store, writing a 404 and returning
// nil if it does not exist. Under enforcement that is the answer authorization
// had (org_resolution.go), not a fresh lookup.
func (a *API) org(w http.ResponseWriter, r *http.Request) *store.Org {
	name := r.PathValue("org")
	_, org, ok, err := a.lookupOrg(r, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return nil
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find org "+name)
		return nil
	}
	return org.As(actorID(r))
}

// actorID names the request's authenticated actor as store.Meta records it:
// "users/<name>" or "clients/<name>", or "" when there is none (auth off).
func actorID(r *http.Request) string {
	actor, ok := actorFromContext(r.Context())
	if !ok || actor.Name == "" {
		return ""
	}
	if actor.IsClient {
		return "clients/" + actor.Name
	}
	return "users/" + actor.Name
}
