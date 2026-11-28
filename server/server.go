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
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/api"
	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/metrics"
	"github.com/cinc-project/cinc-server-ng/internal/repo"
	"github.com/cinc-project/cinc-server-ng/internal/state"
	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
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
	// MaxBodyBytes caps the size of an API request body, which the server reads
	// into memory whole (a signed body's hash is part of its signature). A body
	// over it is refused with 413, as Chef Infra Server refuses one over
	// opscode_erchef['max_request_size'], whose default of 2,000,000 bytes is
	// this one's. Set a negative value to disable the limit.
	MaxBodyBytes int64
	// MaxFileStoreBytes caps the size of a cookbook file uploaded to the
	// pre-signed file-store URL, whose handler also reads it into memory.
	// Defaults to 250 MiB, the nginx['client_max_body_size'] that is Chef
	// Infra Server's only limit on cookbook files. Set a negative value to
	// disable the limit.
	MaxFileStoreBytes int64
	// Logger receives server-side diagnostics, such as the specific reason a
	// request failed to authenticate (the client is told only that it did).
	// Defaults to slog.Default().
	Logger *slog.Logger
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
	// StatsUser is the HTTP Basic user name that GET /_stats accepts. As on
	// Chef Infra Server, /_stats is not protected by Mixlib signing but by Basic
	// auth (nginx's job there). Defaults to "statsuser", Chef Infra Server's.
	StatsUser string
	// StatsPassword is the HTTP Basic password for StatsUser. When empty, a
	// random password is generated at New (Chef Infra Server likewise generates
	// its stats_password at install) and is readable via StatsCredentials.
	// Ignored, like all authentication, when DisableAuth is set.
	StatsPassword string
	// ExternalURL is the public scheme://host[:port] clients reach the server
	// on, used for every absolute URL in a response (erchef's
	// base_resource_url). Leave it empty to derive the prefix from each
	// request's Host and X-Forwarded-Proto; set it when a load balancer
	// rewrites Host or terminates TLS without sending X-Forwarded-Proto.
	ExternalURL string
	// TLSCertFile and TLSKeyFile are a PEM certificate (chain) and private key
	// to serve HTTPS with. Set both or neither; when empty the server speaks
	// plain HTTP and expects TLS to be terminated in front of it. The pair is
	// read at New and again on ReloadTLS.
	TLSCertFile string
	TLSKeyFile  string
	// BootstrapUser, when set, names a human administrator created at startup
	// with BootstrapPassword, so a fresh server has someone who can log in to a
	// web console (cinc-console authenticates by password, then signs as the
	// user with the webui key). The user joins the global server-admins group
	// and becomes a member of every organization in Orgs and of its users and
	// admins groups. On a store that already holds the user (a restart on
	// SQLite), its password and profile are left alone, since an operator may
	// have changed them; only the memberships are ensured. BootstrapPassword is
	// required with it, and neither it nor BootstrapEmail may be set without it.
	BootstrapUser     string
	BootstrapPassword string
	// BootstrapEmail is the bootstrap user's email address, which a password
	// user must have. Defaults to "<BootstrapUser>@localhost.localdomain".
	BootstrapEmail string
	// Backend, when non-nil, is used directly and overrides Storage/DB. It lets
	// embedding tests inject a specific store.Backend (e.g. a shared in-memory
	// SQLite DB).
	Backend store.Backend
}

// The default body caps, Chef Infra Server's: opscode_erchef's
// max_request_size as packaged (erchef's built-in fallback is 1,000,000; every
// Chef Infra Server package sets 2,000,000, and pedant checks a body of exactly
// that size is accepted), and nginx's client_max_body_size of 250m, the only
// cap on a cookbook file.
const (
	DefaultMaxBodyBytes      = 2000000
	DefaultMaxFileStoreBytes = 250 << 20
)

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
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.StatsUser == "" {
		o.StatsUser = DefaultStatsUser
	}
	if o.MaxBodyBytes == 0 {
		o.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if o.MaxFileStoreBytes == 0 {
		o.MaxFileStoreBytes = DefaultMaxFileStoreBytes
	}
}

// bootstrapUser validates the Bootstrap* options and returns the user to
// create, or nil when none is configured. Called after withDefaults, so
// AdminName is set.
func (o *Options) bootstrapUser() (*api.BootstrapUser, error) {
	if o.BootstrapUser == "" {
		if o.BootstrapPassword != "" || o.BootstrapEmail != "" {
			return nil, errors.New("BootstrapPassword and BootstrapEmail require BootstrapUser (--bootstrap-user)")
		}
		return nil, nil
	}
	if o.BootstrapUser == o.AdminName {
		return nil, fmt.Errorf("bootstrap user %q is the superuser (--admin); choose another name", o.BootstrapUser)
	}
	u := &api.BootstrapUser{Name: o.BootstrapUser, Password: o.BootstrapPassword, Email: o.BootstrapEmail}
	if err := u.Validate(); err != nil {
		return nil, err
	}
	return u, nil
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
	users         *userNames     // global user names, for resolveAuth
	webuiPub      *rsa.PublicKey // verifies X-Ops-Request-Source: web requests
	fileStoreKey  []byte         // signs/verifies pre-signed cookbook file-store URLs
	api           *api.API
	url           string
	certs         *certLoader // nil unless serving TLS
	// bootstrapWarning says why the bootstrap user was not granted its
	// memberships at startup, or is empty.
	bootstrapWarning string
}

// upgradeOrgACLs brings every org in st to erchef's org ACL policy (see
// api.UpgradeOrgACLs). It is idempotent and a no-op on a fresh store.
func upgradeOrgACLs(st *store.Store) error {
	names, err := st.ListOrgs()
	if err != nil {
		return err
	}
	for _, name := range names {
		org, ok, err := st.Org(name)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := api.UpgradeOrgACLs(org); err != nil {
			return fmt.Errorf("upgrade org %q ACLs: %w", name, err)
		}
	}
	return nil
}

// upgradeACLActors types the ACL entries of the global space and every org
// (see api.UpgradeACLActors). On a store with none to convert it reads each
// acls collection once and writes nothing.
func upgradeACLActors(st *store.Store) error {
	if err := api.UpgradeACLActors(st.Global(), nil); err != nil {
		return fmt.Errorf("upgrade user ACLs: %w", err)
	}
	names, err := st.ListOrgs()
	if err != nil {
		return err
	}
	for _, name := range names {
		org, ok, err := st.Org(name)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := api.UpgradeACLActors(st.Global(), org); err != nil {
			return fmt.Errorf("upgrade org %q ACL actors: %w", name, err)
		}
	}
	return nil
}

// upgradeValidatorClientACLs takes each org's validators off the stored ACLs
// of the clients they registered (see api.UpgradeValidatorClientACLs).
func upgradeValidatorClientACLs(st *store.Store) error {
	names, err := st.ListOrgs()
	if err != nil {
		return err
	}
	for _, name := range names {
		org, ok, err := st.Org(name)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := api.UpgradeValidatorClientACLs(org); err != nil {
			return fmt.Errorf("upgrade org %q client ACLs: %w", name, err)
		}
	}
	return nil
}

// upgradeObjectACLs stores every org's objects' creation ACLs (see
// api.UpgradeObjectACLs). On a store with nothing to change it writes nothing.
func upgradeObjectACLs(st *store.Store) error {
	names, err := st.ListOrgs()
	if err != nil {
		return err
	}
	for _, name := range names {
		org, ok, err := st.Org(name)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := api.UpgradeObjectACLs(org); err != nil {
			return fmt.Errorf("upgrade org %q object ACLs: %w", name, err)
		}
	}
	return nil
}

// upgradePasswords hashes any plain-text password a durable store holds from
// an older version, in the global scope (users) and every org. On a store
// with none it reads each passwords collection once and writes nothing.
func upgradePasswords(st *store.Store) error {
	if _, err := api.UpgradePasswords(st.Global()); err != nil {
		return fmt.Errorf("upgrade user passwords: %w", err)
	}
	names, err := st.ListOrgs()
	if err != nil {
		return err
	}
	for _, name := range names {
		org, ok, err := st.Org(name)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if _, err := api.UpgradePasswords(org); err != nil {
			return fmt.Errorf("upgrade org %q passwords: %w", name, err)
		}
	}
	return nil
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
		return nil, errors.New("options Repo and StatePath are mutually exclusive; a state directory already subsumes a chef-repo")
	}
	bootstrapUser, err := opts.bootstrapUser()
	if err != nil {
		return nil, err
	}
	if opts.ExternalURL != "" {
		base, err := normalizeExternalURL(opts.ExternalURL)
		if err != nil {
			return nil, err
		}
		opts.ExternalURL = base
	}
	var certs *certLoader
	if opts.TLSCertFile != "" || opts.TLSKeyFile != "" {
		var err error
		if certs, err = newCertLoader(opts.TLSCertFile, opts.TLSKeyFile); err != nil {
			return nil, err
		}
	}
	st, err := buildStore(opts)
	if err != nil {
		return nil, err
	}
	if opts.Now != nil {
		// Writes are stamped on the server's clock (store.Meta), the one tests pin.
		st.SetClock(opts.Now)
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

	// Orgs a durable store already held may have been created by an older
	// version, whose stored clients container ACL predates erchef's org policy.
	if err := upgradeOrgACLs(st); err != nil {
		return nil, err
	}

	// Versions before typed ACL entries stored one untyped actors list per
	// entry. It is converted before anything can create a client named like a
	// user (see api.UpgradeACLActors).
	if err := upgradeACLActors(st); err != nil {
		return nil, err
	}

	// Versions before it gave a validator every permission on each client it
	// registered. It runs after upgradeACLActors, which types the lists it edits.
	if err := upgradeValidatorClientACLs(st); err != nil {
		return nil, err
	}

	// Versions before password hashing stored passwords as plain text.
	if err := upgradePasswords(st); err != nil {
		return nil, err
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

	// Under enforcement every object needs the ACL erchef would have created
	// it with: those loaded just above have none, and an older version wrote
	// none for some kinds and an over-broad one for clients (see
	// api.UpgradeObjectACLs).
	if opts.EnforceACL {
		if err := upgradeObjectACLs(st); err != nil {
			return nil, err
		}
	}

	// After the orgs (it joins each) and any state load (which may already
	// define the user). A store that was fresh this startup holds only what
	// the operator loaded into it, so a user of the name there is trusted.
	var bootstrapWarning string
	if bootstrapUser != nil {
		res, err := bootstrapUser.Apply(st, opts.Orgs, adminFresh)
		if err != nil {
			return nil, err
		}
		bootstrapWarning = res.Refused
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

	// No fixed default password: one shipped in the source would be public. A
	// fresh one per process is what an unconfigured server gets instead.
	if opts.StatsPassword == "" {
		if opts.StatsPassword, err = generateStatsPassword(); err != nil {
			return nil, err
		}
	}

	users, err := newUserNames(st)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	s := &Server{
		users:         users,
		opts:          opts,
		store:         st,
		adminKey:      auth.EncodePrivateKeyPEM(adminPriv),
		validatorKeys: validatorKeys,
		keyCache:      auth.NewPublicKeyCache(),
		webuiPub:      webuiPub,
		fileStoreKey:  fileStoreKey,
		certs:         certs,

		bootstrapWarning: bootstrapWarning,
	}
	apiInstance := api.New(st,
		api.WithACLEnforcement(opts.EnforceACL),
		api.WithFileStoreKey(fileStoreKey),
		api.WithClock(opts.Now),
		api.WithExternalURL(opts.ExternalURL),
	)
	s.api = apiInstance
	handler := s.enforceBodySize(apiInstance.Handler())
	if !opts.DisableAuth {
		handler = s.authMiddleware(handler)
	}
	// erchef judges the API version header in service_available, before the
	// signature: an unacceptable version is a 406 even unsigned, and a 401
	// carries the negotiation header too.
	handler = api.WithAPIVersion(handler)
	// Measure outside authentication, so requests rejected before they reach a
	// route are counted too — a flood of bad credentials is worth seeing.
	handler = apiInstance.Instrument(handler)
	// Cap the request body outermost, so the limit is in force before any layer
	// (auth, or a handler on an auth-exempt path) reads the body.
	handler = s.limitBody(handler)
	// Trim a trailing slash before anything judges the path, so that the body
	// cap, the auth layer's exemptions (/_status, /_stats with HTTP Basic, the
	// pre-signed file store) and the router all decide on the same path. The
	// signature is unaffected: Mixlib's canonical path drops a trailing slash.
	handler = api.WithoutTrailingSlash(handler)
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
	s.httpSrv = &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
	serve := s.httpSrv.Serve
	if s.certs != nil {
		s.url = "https://" + ln.Addr().String()
		s.httpSrv.TLSConfig = s.certs.config()
		// The certificate comes from TLSConfig.GetCertificate, so no files here.
		serve = func(ln net.Listener) error { return s.httpSrv.ServeTLS(ln, "", "") }
	}
	go func() {
		if err := serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	if err != nil {
		// The deadline passed with requests still in flight: cut them off rather
		// than leave them running against a closed store.
		_ = s.httpSrv.Close()
	}
	if cerr := s.store.Close(); err == nil {
		err = cerr
	}
	return err
}

// Drain starts a graceful shutdown as a load balancer sees it: /_status fails
// with 503 so the health check removes this instance from rotation, and each
// connection is closed after its current response so clients reconnect through
// the load balancer, while requests keep being served. Call Stop once the load
// balancer has had time to notice (a few health-check intervals).
func (s *Server) Drain() {
	s.api.Drain()
	if s.httpSrv != nil {
		s.httpSrv.SetKeepAlivesEnabled(false)
	}
}

// URL is the base URL the server is listening on (valid after Start).
func (s *Server) URL() string { return s.url }

// AdminKey returns the PEM-encoded private key for the admin user. Sign
// requests with this key (and AdminName) to act as the administrator.
func (s *Server) AdminKey() []byte { return s.adminKey }

// AdminName returns the bootstrap admin user name.
func (s *Server) AdminName() string { return s.opts.AdminName }

// BootstrapWarning says why the configured bootstrap user (BootstrapUser) was
// not made an admin at startup: a user of that name exists that the bootstrap
// did not create. It is empty when the user was created or granted as usual.
func (s *Server) BootstrapWarning() string { return s.bootstrapWarning }

// ValidatorKey returns the PEM-encoded private key for an organization's
// "<org>-validator" client, or nil if the org was not created at bootstrap.
// This is the key chef-client uses to register new nodes.
func (s *Server) ValidatorKey(org string) []byte { return s.validatorKeys[org] }

// StatsCredentials returns the HTTP Basic user and password GET /_stats
// accepts, including a password generated because none was configured.
func (s *Server) StatsCredentials() (user, password string) {
	return s.opts.StatsUser, s.opts.StatsPassword
}

// Store exposes the underlying store for programmatic seeding and inspection.
func (s *Server) Store() *store.Store { return s.store }

// Metrics returns the server's instrument registry, so an embedding program can
// gather the same numbers /_stats serves.
func (s *Server) Metrics() *metrics.Registry { return s.api.Metrics() }

// readHeaderTimeout bounds how long a client may take to send its request
// headers (the Slowloris defence). Real chef-client and knife send headers
// immediately. Only the header phase is bounded: a ReadTimeout or WriteTimeout
// would cap whole bodies and cut off large cookbook transfers on slow links.
var readHeaderTimeout = 10 * time.Second

// idleTimeout closes keep-alive connections that sit unused, so idle sockets
// cannot accumulate either. Clients reconnect transparently.
var idleTimeout = 2 * time.Minute
