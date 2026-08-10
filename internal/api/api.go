// Package api implements the Chef Infra Server HTTP API surface over the
// in-memory store. Handlers operate on a *store.Org and emit Chef-shaped JSON.
// Authentication is a separate layer wrapped around this handler, so these
// handlers can be exercised directly in tests.
package api

import (
	"net/http"

	"github.com/tas50/cinc-server-ng/internal/store"
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

// New returns an API backed by st, applying any options.
func New(st *store.Store, opts ...Option) *API {
	a := &API{
		store:     st,
		search:    newSearchCache(),
		groups:    newGroupIndexCache(),
		searchIdx: newSearchIndexes(),
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
	globalScope := func(http.ResponseWriter, *http.Request) *store.Org { return a.store.Global() }
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
	a.registerServerEndpoints(mux)

	a.routes = mux.patterns

	var h http.Handler = withJSONErrors(mux)
	if a.enforceACL {
		h = a.authzMiddleware(h)
	}
	return withAPIVersion(h)
}

// org resolves the {org} path value to its store, writing a 404 and returning
// nil if it does not exist.
func (a *API) org(w http.ResponseWriter, r *http.Request) *store.Org {
	name := r.PathValue("org")
	org, ok, err := a.store.Org(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return nil
	}
	if !ok {
		writeError(w, http.StatusNotFound, "Cannot find org "+name)
		return nil
	}
	return org
}
