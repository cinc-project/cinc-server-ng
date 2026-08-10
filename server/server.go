// Package server assembles the in-memory store, the Chef API handlers, and the
// authentication layer into a runnable, embeddable Chef Infra Server. It is the
// public entry point for Go test suites:
//
//	srv, _ := server.New(server.Options{Orgs: []string{"test"}})
//	srv.Start()
//	defer srv.Stop(context.Background())
//	// talk to srv.URL() with a client signed by srv.AdminKey()
package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/tas50/cinc-server-ng/internal/api"
	"github.com/tas50/cinc-server-ng/internal/auth"
	"github.com/tas50/cinc-server-ng/internal/metrics"
	"github.com/tas50/cinc-server-ng/internal/repo"
	"github.com/tas50/cinc-server-ng/internal/state"
	"github.com/tas50/cinc-server-ng/internal/store"
	"github.com/tas50/cinc-server-ng/internal/store/sqlite"
)

// Options configures a Server. The zero value is usable: it creates a single
// organization named "acme", an admin user named "pivotal", and enforces real
// Mixlib authentication with a 15-minute clock-skew window.
type Options struct {
	// Addr is the listen address. Defaults to "127.0.0.1:0" (random port).
	Addr string
	// Orgs are the organizations to create at startup. Defaults to ["acme"].
	Orgs []string
	// AdminName is the bootstrap admin user. Defaults to "pivotal".
	AdminName string
	// DisableAuth skips signature verification entirely (useful for tests that
	// do not want to sign requests).
	DisableAuth bool
	// EnforceACL turns on authorization enforcement: object ACLs and group
	// membership actually gate requests, and unauthorized operations return
	// 403. Defaults to false (every authenticated actor is permitted), which
	// keeps existing test pipelines unaffected. Requires authentication, so it
	// cannot be combined with DisableAuth.
	EnforceACL bool
	// SkewSeconds is the allowed clock skew for request timestamps. Defaults to
	// 900 (15 minutes).
	SkewSeconds int
	// Now is the clock used for skew checks. Defaults to time.Now.
	Now func() time.Time
	// Repo is an optional path to a chef-repo whose objects (nodes, roles,
	// environments, clients, policies, policy_groups, data bags) are loaded
	// into the first organization at startup, mirroring `knife upload`.
	Repo string
	// StatePath is an optional path to a full server-state directory (global
	// users, every organization, and each org's chef-objects plus authz
	// groups), loaded at startup. Unlike Repo it can populate multiple orgs and
	// the global users/groups the chef-repo format cannot express. It cannot be
	// combined with Repo, which a state directory already subsumes.
	StatePath string
	// WebUIKey is an optional PEM-encoded key (public or private) that a
	// management console (e.g. cinc-console) uses to sign requests on behalf of
	// users via the "X-Ops-Request-Source: web" header — the Chef Infra Server
	// webui-impersonation mechanism. When empty, the bootstrap admin key doubles
	// as the webui key, so the key written by --key-out works out of the box.
	WebUIKey []byte
	// MaxBodyBytes caps the size of a request body the server will read into
	// memory, so a single oversized request cannot exhaust memory. It applies to
	// every path, including the unauthenticated cookbook file store (whose
	// handler reads the uploaded file fully into memory). Defaults to 1 GiB; set
	// a negative value to disable the limit.
	MaxBodyBytes int64
	// Storage selects the persistence backend: "memory" (default, ephemeral) or
	// "sqlite" (durable). Ignored when Backend is set.
	Storage string
	// DB is the SQLite database file path; required when Storage is "sqlite".
	DB string
	// SQLiteGroupCommit enables the SQLite coalescing writer (group commit): under
	// concurrent fleet write load it batches pending writes into shared
	// transactions for higher throughput, at a small single-client latency cost.
	// Ignored unless Storage is "sqlite".
	SQLiteGroupCommit bool
	// Backend, when non-nil, is used directly and overrides Storage/DB. It lets
	// embedding tests inject a specific store.Backend (e.g. a shared in-memory
	// SQLite DB).
	Backend store.Backend
}

func (o *Options) withDefaults() {
	if o.Addr == "" {
		o.Addr = "127.0.0.1:0"
	}
	if o.Storage == "" {
		o.Storage = "memory"
	}
	if len(o.Orgs) == 0 {
		o.Orgs = []string{"acme"}
	}
	if o.AdminName == "" {
		o.AdminName = "pivotal"
	}
	if o.SkewSeconds == 0 {
		o.SkewSeconds = 900
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxBodyBytes == 0 {
		o.MaxBodyBytes = 1 << 30 // 1 GiB
	}
}

// buildStore constructs the data store for the given options: an injected Backend
// if provided, otherwise the selected Storage backend — in-memory by default (the
// ephemeral "zero" experience) or SQLite (durable) when Storage is "sqlite".
func buildStore(opts Options) (*store.Store, error) {
	if opts.Backend != nil {
		return store.NewWithBackend(opts.Backend), nil
	}
	switch opts.Storage {
	case "memory":
		return store.New(), nil
	case "sqlite":
		if opts.DB == "" {
			return nil, errors.New(`storage "sqlite" requires a database path (Options.DB / --db)`)
		}
		var sqlOpts []sqlite.Option
		if opts.SQLiteGroupCommit {
			sqlOpts = append(sqlOpts, sqlite.WithGroupCommit())
		}
		b, err := sqlite.Open(opts.DB, sqlOpts...)
		if err != nil {
			return nil, fmt.Errorf("open sqlite %q: %w", opts.DB, err)
		}
		return store.NewWithBackend(b), nil
	default:
		return nil, fmt.Errorf("unknown storage %q (want %q or %q)", opts.Storage, "memory", "sqlite")
	}
}

// serverKeysColl is a private global collection holding the PEM-encoded bootstrap
// private keys (admin and per-org validators). It is not exposed by any API route,
// so a durable backend can keep stable credentials across restarts. Real Chef
// Infra Server never stores private keys; cinc-server-ng is a test server that already
// keeps secrets (e.g. passwords) in its store, and persisting these keys is what
// makes a restarted SQLite-backed server keep working with existing clients.
const serverKeysColl = "server_keys"

// serverKeyAdmin is the server_keys key under which the admin private key lives.
const serverKeyAdmin = "admin"

// serverKeyValidator names the server_keys entry for an org's validator key.
func serverKeyValidator(org string) string { return "validator:" + org }

// loadServerKey reads a persisted bootstrap private key from the global
// server_keys collection. It returns (key, fresh, err): fresh is true when no key
// was stored yet, signalling the caller to generate and persist one.
func loadServerKey(st *store.Store, name string) (key *rsa.PrivateKey, fresh bool, err error) {
	raw, ok, err := st.Global().Get(serverKeysColl, name)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, true, nil
	}
	key, err = auth.ParsePrivateKey(raw)
	if err != nil {
		return nil, false, fmt.Errorf("parse stored %q key: %w", name, err)
	}
	return key, false, nil
}

// storeServerKey persists a bootstrap private key in the global server_keys
// collection.
func storeServerKey(st *store.Store, name string, key *rsa.PrivateKey) error {
	return st.Global().Put(serverKeysColl, name, auth.EncodePrivateKeyPEM(key))
}

// Server is a running (or ready-to-run) cinc-server-ng instance.
type Server struct {
	opts          Options
	store         *store.Store
	handler       http.Handler
	httpSrv       *http.Server
	listener      net.Listener
	adminKey      []byte            // PEM-encoded admin private key
	validatorKeys map[string][]byte // org name -> PEM-encoded validator private key
	keyCache      *auth.PublicKeyCache
	webuiPub      *rsa.PublicKey // verifies X-Ops-Request-Source: web requests
	fileStoreKey  []byte         // signs/verifies pre-signed cookbook file-store URLs
	api           *api.API
	url           string
}

// New builds a Server: it creates the store, bootstraps the admin user and the
// configured organizations, and wires the API behind the auth layer. It does
// not begin listening; call Start for that.
func New(opts Options) (*Server, error) {
	opts.withDefaults()
	if opts.DisableAuth && opts.EnforceACL {
		return nil, errors.New("EnforceACL requires authentication; do not set DisableAuth")
	}
	if opts.Repo != "" && opts.StatePath != "" {
		return nil, errors.New("Repo and StatePath are mutually exclusive; a state directory already subsumes a chef-repo")
	}
	st, err := buildStore(opts)
	if err != nil {
		return nil, err
	}

	// Bootstrap (or, against a durable backend that already holds state, reload)
	// the admin user and each organization. The private keys for the admin and the
	// per-org validators are persisted in the global server_keys collection, so a
	// restart on a populated store keeps stable credentials rather than
	// regenerating them and invalidating existing clients. On the in-memory backend
	// the store always starts empty, so this is identical to a clean bootstrap.
	adminPriv, adminFresh, err := loadServerKey(st, serverKeyAdmin)
	if err != nil {
		return nil, err
	}
	type orgPlan struct {
		name   string
		priv   *rsa.PrivateKey
		create bool
	}
	plans := make([]orgPlan, len(opts.Orgs))
	nGen := 0
	if adminFresh {
		nGen++
	}
	for i, name := range opts.Orgs {
		priv, fresh, err := loadServerKey(st, serverKeyValidator(name))
		if err != nil {
			return nil, err
		}
		plans[i] = orgPlan{name: name, priv: priv, create: fresh}
		if fresh {
			nGen++
		}
	}

	// RSA-2048 generation is the dominant startup cost; generate only the keys we
	// actually need — all of them on a fresh store, none on a clean restart — in
	// parallel.
	gen, err := generateKeys(nGen)
	if err != nil {
		return nil, err
	}
	gi := 0
	if adminFresh {
		adminPriv = gen[gi]
		gi++
	}
	for i := range plans {
		if plans[i].create {
			plans[i].priv = gen[gi]
			gi++
		}
	}

	// On a fresh store, write the admin user record and persist its private key.
	if adminFresh {
		pubPEM, err := auth.EncodePublicKeyPEM(&adminPriv.PublicKey)
		if err != nil {
			return nil, err
		}
		adminDoc := fmt.Sprintf(`{"username":%q,"admin":true,"public_key":%q}`, opts.AdminName, string(pubPEM))
		if err := st.Global().Put("users", opts.AdminName, []byte(adminDoc)); err != nil {
			return nil, err
		}
		if err := storeServerKey(st, serverKeyAdmin, adminPriv); err != nil {
			return nil, err
		}
	}

	// The webui key verifies management-console requests (X-Ops-Request-Source:
	// web). It defaults to the admin key, so the --key-out key acts as the webui
	// key without extra setup; a distinct key may be supplied via WebUIKey.
	webuiPub := &adminPriv.PublicKey
	if len(opts.WebUIKey) > 0 {
		webuiPub, err = parseWebUIKey(opts.WebUIKey)
		if err != nil {
			return nil, fmt.Errorf("parse webui key: %w", err)
		}
	}

	validatorKeys := make(map[string][]byte, len(opts.Orgs))
	for _, p := range plans {
		if !p.create {
			// Org was bootstrapped on a prior run; reuse its stored validator key.
			validatorKeys[p.name] = auth.EncodePrivateKeyPEM(p.priv)
			continue
		}
		validator, err := api.CreateOrganizationWithKey(st, p.name, p.name, p.priv)
		if err != nil {
			return nil, fmt.Errorf("create org %q: %w", p.name, err)
		}
		validatorKeys[p.name] = validator
		if err := storeServerKey(st, serverKeyValidator(p.name), p.priv); err != nil {
			return nil, err
		}
	}

	// Load a chef-repo into the first organization, if configured.
	if opts.Repo != "" {
		org, ok, err := st.Org(opts.Orgs[0])
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("repo target org %q not found", opts.Orgs[0])
		}
		if _, err := repo.Load(org, opts.Repo); err != nil {
			return nil, fmt.Errorf("load repo %q: %w", opts.Repo, err)
		}
	}

	// Hydrate the full server (global users, every org, groups) from disk, if
	// configured. Orgs already bootstrapped above are loaded into; any extra
	// orgs present in the state directory are created on the fly.
	if opts.StatePath != "" {
		if _, err := state.Load(st, opts.StatePath); err != nil {
			return nil, fmt.Errorf("load state %q: %w", opts.StatePath, err)
		}
	}

	// The cookbook file store cannot use Mixlib signing (clients transfer file
	// bodies at URLs the server hands them, unsigned), so with authentication on
	// it is protected by pre-signed URLs instead. The key is per-process: grants
	// are short-lived and never persisted, so a restart simply invalidates any
	// still-outstanding URL. With authentication off there is nothing to protect.
	var fileStoreKey []byte
	if !opts.DisableAuth {
		fileStoreKey = make([]byte, 32)
		if _, err := rand.Read(fileStoreKey); err != nil {
			return nil, fmt.Errorf("generate file store key: %w", err)
		}
	}

	s := &Server{
		opts:          opts,
		store:         st,
		adminKey:      auth.EncodePrivateKeyPEM(adminPriv),
		validatorKeys: validatorKeys,
		keyCache:      auth.NewPublicKeyCache(),
		webuiPub:      webuiPub,
		fileStoreKey:  fileStoreKey,
	}
	apiInstance := api.New(st,
		api.WithACLEnforcement(opts.EnforceACL),
		api.WithFileStoreKey(fileStoreKey),
	)
	s.api = apiInstance
	handler := apiInstance.Handler()
	if !opts.DisableAuth {
		handler = s.authMiddleware(handler)
	}
	// Measure outside authentication, so requests rejected before they reach a
	// route are counted too — a flood of bad credentials is worth seeing.
	handler = apiInstance.Instrument(handler)
	// Cap the request body outermost, so the limit is in force before any layer
	// (auth, or a handler on an auth-exempt path) reads the body.
	if opts.MaxBodyBytes > 0 {
		handler = limitBody(handler, opts.MaxBodyBytes)
	}
	s.handler = handler
	return s, nil
}

// generateKeys generates n RSA key pairs concurrently and returns them in order.
// Key generation is CPU-bound and independent, so running it in parallel cuts
// startup well below the serial (n × keygen) cost. Each goroutine reads entropy
// through its own buffered reader so they do not serialize on crypto/rand's
// global lock during prime search.
func generateKeys(n int) ([]*rsa.PrivateKey, error) {
	keys := make([]*rsa.PrivateKey, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range keys {
		go func(i int) {
			defer wg.Done()
			keys[i], errs[i] = auth.GenerateKeyFrom(bufio.NewReaderSize(rand.Reader, 1<<16))
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
	}
	return keys, nil
}

// Start binds the listener and serves in a background goroutine.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.url = "http://" + ln.Addr().String()
	s.httpSrv = &http.Server{Handler: s.handler}
	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Serve errors after Close are expected; nothing to do here.
			_ = err
		}
	}()

	// Warm the serving path so the first real client request is not the one that
	// pays for cold connection handling, code paths, pools, and GC heap growth.
	s.prewarm()
	return nil
}

// Stop gracefully shuts the server down and releases the store backend (e.g.
// closes the SQLite handle).
func (s *Server) Stop(ctx context.Context) error {
	if s.httpSrv == nil {
		return s.store.Close()
	}
	err := s.httpSrv.Shutdown(ctx)
	if cerr := s.store.Close(); err == nil {
		err = cerr
	}
	return err
}

// URL is the base URL the server is listening on (valid after Start).
func (s *Server) URL() string { return s.url }

// AdminKey returns the PEM-encoded private key for the admin user. Sign
// requests with this key (and AdminName) to act as the administrator.
func (s *Server) AdminKey() []byte { return s.adminKey }

// AdminName returns the bootstrap admin user name.
func (s *Server) AdminName() string { return s.opts.AdminName }

// ValidatorKey returns the PEM-encoded private key for an organization's
// "<org>-validator" client, or nil if the org was not created at bootstrap.
// This is the key chef-client uses to register new nodes.
func (s *Server) ValidatorKey(org string) []byte { return s.validatorKeys[org] }

// Store exposes the underlying store for programmatic seeding and inspection.
func (s *Server) Store() *store.Store { return s.store }

// Metrics returns the server's instrument registry, so an embedding program can
// gather the same numbers /_stats serves.
func (s *Server) Metrics() *metrics.Registry { return s.api.Metrics() }
