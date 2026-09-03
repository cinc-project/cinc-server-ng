package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
)

// Fleet check-in benchmarks measured through the *whole* server stack —
// Mixlib signature verification, API version negotiation, ACL enforcement, and
// the store — which is the configuration the standalone binary actually runs.
// The api-package benchmarks bypass authentication and authorization entirely,
// so they cannot show what a real fleet costs.
//
// Requests are pre-signed outside the timer: signing is an RSA *private* key
// operation that happens on the client (the node), and paying it in the loop
// would measure chef-client rather than cinc-server-ng.

const benchFleetNodes = 512

// benchKeys is the RSA pair the whole simulated fleet signs with. It is
// generated once per process rather than embedded, so no private key lives in
// the repository. Sharing one pair across clients does not weaken the
// measurement: every request still runs a full signature verification, and the
// server's key cache is keyed by PEM, which a real fleet of distinct keys hits
// just as cheaply (one map lookup either way).
var benchKeys = sync.OnceValues(func() (privPEM string, pubPEM string) {
	key, err := auth.GenerateKey()
	if err != nil {
		panic("bench key generation: " + err.Error())
	}
	pub, err := auth.EncodePublicKeyPEM(&key.PublicKey)
	if err != nil {
		panic("bench key encoding: " + err.Error())
	}
	return string(auth.EncodePrivateKeyPEM(key)), string(pub)
})

func benchPrivPEM() string { p, _ := benchKeys(); return p }
func benchPubPEM() string  { _, p := benchKeys(); return p }

func benchFleetNodeBody(name string) []byte {
	return fmt.Appendf(nil, `{"name":%q,"chef_environment":"production","json_class":"Chef::Node",`+
		`"chef_type":"node","normal":{"tags":["a","b","c"]},`+
		`"automatic":{"os":"linux","ohai_time":1700000000.0,"memory":{"total":"16gb"},`+
		`"ipaddress":"10.0.0.1","network":{"interfaces":{"eth0":{"addr":"10.0.0.1"}}}},`+
		`"default":{},"override":{},"run_list":["recipe[nginx]","recipe[base]"]}`, name)
}

// preparedReq is a signed request replayed through the handler. The header map
// is shared across iterations: the server only reads it, so cloning per
// iteration would add client-side allocation to a server-side measurement.
type preparedReq struct {
	method, url string
	body        []byte
	header      http.Header
}

func (p preparedReq) do(b *testing.B, h http.Handler) {
	var req *http.Request
	if p.body == nil {
		req = httptest.NewRequest(p.method, p.url, nil)
	} else {
		req = httptest.NewRequest(p.method, p.url, bytes.NewReader(p.body))
	}
	req.Header = p.header
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code >= 300 {
		b.Fatalf("%s %s: status %d: %s", p.method, p.url, rec.Code, rec.Body)
	}
}

// seedFleet registers n clients and the nodes they own directly in the store —
// far cheaper than driving the API, and it lets every client share one RSA key
// pair so setup does not spend n key generations. Each request still performs a
// full signature verification, which is what the benchmark is measuring.
func seedFleet(b *testing.B, srv *Server, n int) {
	b.Helper()
	org, ok, err := srv.Store().Org("acme")
	if err != nil || !ok {
		b.Fatalf("org acme: ok=%v err=%v", ok, err)
	}
	clients := make([]string, n)
	for i := range n {
		name := fmt.Sprintf("node%d", i)
		clients[i] = name
		if err := org.Put("clients", name, fmt.Appendf(nil,
			`{"name":%q,"clientname":%q,"validator":false,"public_key":%q}`,
			name, name, benchPubPEM())); err != nil {
			b.Fatal(err)
		}
		if err := org.Put("nodes", name, benchFleetNodeBody(name)); err != nil {
			b.Fatal(err)
		}
		// The node's own client owns it, as it would after a real bootstrap.
		acl := fmt.Appendf(nil, `{"create":{"actors":[%q],"groups":["admins"]},`+
			`"read":{"actors":[%q],"groups":["admins"]},`+
			`"update":{"actors":[%q],"groups":["admins"]},`+
			`"delete":{"actors":[%q],"groups":["admins"]},`+
			`"grant":{"actors":[%q],"groups":["admins"]}}`, name, name, name, name, name)
		if err := org.Put("acls", "nodes/"+name, acl); err != nil {
			b.Fatal(err)
		}
	}
	// One "clients" group listing the whole fleet, as a real org has.
	members := make([]byte, 0, n*12)
	members = append(members, '[')
	for i, c := range clients {
		if i > 0 {
			members = append(members, ',')
		}
		members = fmt.Appendf(members, "%q", c)
	}
	members = append(members, ']')
	if err := org.Put("groups", "clients", fmt.Appendf(nil,
		`{"name":"clients","groupname":"clients","actors":%s,"users":[],"clients":%s,"groups":[]}`,
		members, members)); err != nil {
		b.Fatal(err)
	}
}

// prepareCheckins builds the pre-signed GET+PUT pair each node issues on a run.
func prepareCheckins(b *testing.B, srv *Server, n int, sign bool) []preparedReq {
	b.Helper()
	key, err := auth.ParsePrivateKey([]byte(benchPrivPEM()))
	if err != nil {
		b.Fatal(err)
	}
	reqs := make([]preparedReq, 0, n*2)
	ts := time.Now().UTC().Format(time.RFC3339)
	for i := range n {
		name := fmt.Sprintf("node%d", i)
		url := "http://127.0.0.1/organizations/acme/nodes/" + name
		body := benchFleetNodeBody(name)
		for _, p := range []preparedReq{
			{method: "GET", url: url},
			{method: "PUT", url: url, body: body},
		} {
			req := httptest.NewRequest(p.method, p.url, nil)
			req.Header.Set("X-Ops-Server-API-Version", "1")
			if sign {
				if err := auth.SignRequest(req, name, ts, p.body, key); err != nil {
					b.Fatal(err)
				}
			}
			p.header = req.Header
			reqs = append(reqs, p)
		}
	}
	return reqs
}

func benchFleetCheckin(b *testing.B, opts Options, sign bool, inFlight int) {
	opts.Orgs = []string{"acme"}
	srv, err := New(opts)
	if err != nil {
		b.Fatal(err)
	}
	// An injected Backend registers its own close; closing the store here too
	// would double-close it (which the coalescer does not survive).
	if opts.Backend == nil {
		b.Cleanup(func() { srv.Store().Close() })
	}
	seedFleet(b, srv, benchFleetNodes)
	reqs := prepareCheckins(b, srv, benchFleetNodes, sign)
	h := srv.handler

	var seq atomic.Int64
	b.ResetTimer()
	// Real fleet load arrives on thousands of connections, so many more
	// requests are in flight than there are cores: writes queue up in the store
	// and the group committer has deep batches to coalesce. RunParallel's
	// default of one goroutine per core would understate that, so callers can
	// raise the in-flight count independently of GOMAXPROCS.
	if inFlight > 0 {
		b.SetParallelism(inFlight)
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reqs[int(seq.Add(1))%len(reqs)].do(b, h)
		}
	})
}

func benchSQLiteBackend(b *testing.B, opts ...sqlite.Option) store.Backend {
	be, err := sqlite.Open(filepath.Join(b.TempDir(), "fleet.db"), opts...)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { be.Close() })
	return be
}

// The production default: signatures verified, ACLs enforced.
func BenchmarkFleetCheckinEnforced(b *testing.B) {
	benchFleetCheckin(b, Options{EnforceACL: true}, true, 0)
}

// The realistic authorization shape. seedFleet names each client directly in
// its node's ACL, which actorAllowed satisfies without ever resolving group
// membership. Real orgs mostly grant through groups (Chef's default ACL grants
// admins/users/clients), which forces actorGroups on every request — a scan of
// every group in the org. This prices that path, and how it scales with fleet
// size, since the "clients" group holds one entry per node.
func benchFleetCheckinGroupGranted(b *testing.B, fleet int) {
	srv, err := New(Options{Orgs: []string{"acme"}, EnforceACL: true})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { srv.Store().Close() })
	seedFleet(b, srv, fleet)

	// Re-grant every node through the "clients" group instead of naming the
	// client, so authorization has to resolve membership.
	org, _, _ := srv.Store().Org("acme")
	for i := range fleet {
		acl := []byte(`{"create":{"actors":[],"groups":["clients"]},` +
			`"read":{"actors":[],"groups":["clients"]},` +
			`"update":{"actors":[],"groups":["clients"]},` +
			`"delete":{"actors":[],"groups":["clients"]},` +
			`"grant":{"actors":[],"groups":["admins"]}}`)
		if err := org.Put("acls", fmt.Sprintf("nodes/node%d", i), acl); err != nil {
			b.Fatal(err)
		}
	}
	reqs := prepareCheckins(b, srv, fleet, true)
	h := srv.handler

	var seq atomic.Int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reqs[int(seq.Add(1))%len(reqs)].do(b, h)
		}
	})
}

func BenchmarkFleetCheckinGroupGranted128(b *testing.B) { benchFleetCheckinGroupGranted(b, 128) }
func BenchmarkFleetCheckinGroupGranted512(b *testing.B) { benchFleetCheckinGroupGranted(b, 512) }
func BenchmarkFleetCheckinGroupGranted2048(b *testing.B) {
	benchFleetCheckinGroupGranted(b, 2048)
}

// Same, minus ACL enforcement, to price authorization separately.
func BenchmarkFleetCheckinAuthOnly(b *testing.B) {
	benchFleetCheckin(b, Options{}, true, 0)
}

// Neither, to price signature verification separately.
func BenchmarkFleetCheckinNoAuth(b *testing.B) {
	benchFleetCheckin(b, Options{DisableAuth: true}, false, 0)
}

// Durable storage under the same fleet load, with and without group commit.
func BenchmarkFleetCheckinEnforcedSQLite(b *testing.B) {
	benchFleetCheckin(b, Options{EnforceACL: true, Backend: benchSQLiteBackend(b)}, true, 0)
}

func BenchmarkFleetCheckinEnforcedSQLiteGroupCommit(b *testing.B) {
	benchFleetCheckin(b, Options{EnforceACL: true, Backend: benchSQLiteBackend(b, sqlite.WithGroupCommit())}, true, 0)
}

// The same pair with many requests in flight per core, which is what a fleet
// checking in at once actually looks like. Group commit needs a queue to
// coalesce, so this is the configuration that shows what it is worth.
func BenchmarkFleetCheckinEnforcedSQLiteBusy(b *testing.B) {
	benchFleetCheckin(b, Options{EnforceACL: true, Backend: benchSQLiteBackend(b)}, true, 64)
}

func BenchmarkFleetCheckinEnforcedSQLiteBusyGroupCommit(b *testing.B) {
	benchFleetCheckin(b, Options{EnforceACL: true, Backend: benchSQLiteBackend(b, sqlite.WithGroupCommit())}, true, 64)
}

// Search is on the chef-client run path, and under enforcement every result is
// filtered against the actor's read ACL. These price that filter.
func benchFleetSearch(b *testing.B, enforce bool) {
	srv, err := New(Options{Orgs: []string{"acme"}, EnforceACL: enforce})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { srv.Store().Close() })
	seedFleet(b, srv, benchFleetNodes)

	key, err := auth.ParsePrivateKey([]byte(benchPrivPEM()))
	if err != nil {
		b.Fatal(err)
	}
	url := "http://127.0.0.1/organizations/acme/search/node?q=chef_environment:production"
	req := httptest.NewRequest("GET", url, nil)
	req.Header.Set("X-Ops-Server-API-Version", "1")
	if err := auth.SignRequest(req, "node0", time.Now().UTC().Format(time.RFC3339), nil, key); err != nil {
		b.Fatal(err)
	}
	p := preparedReq{method: "GET", url: url, header: req.Header}
	h := srv.handler

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p.do(b, h)
		}
	})
}

func BenchmarkFleetSearchEnforced(b *testing.B)    { benchFleetSearch(b, true) }
func BenchmarkFleetSearchNotEnforced(b *testing.B) { benchFleetSearch(b, false) }

// Sanity: the seeded fleet actually authenticates and authorizes, so the
// benchmarks above are exercising the full path rather than erroring out.
func TestFleetBenchSeedIsUsable(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	org, _, _ := srv.Store().Org("acme")
	if err := org.Put("clients", "node0", []byte(fmt.Sprintf(
		`{"name":"node0","clientname":"node0","validator":false,"public_key":%q}`, benchPubPEM()))); err != nil {
		t.Fatal(err)
	}
	if err := org.Put("nodes", "node0", benchFleetNodeBody("node0")); err != nil {
		t.Fatal(err)
	}
	if err := org.Put("acls", "nodes/node0", []byte(
		`{"read":{"actors":["node0"],"groups":[]},"update":{"actors":["node0"],"groups":[]}}`)); err != nil {
		t.Fatal(err)
	}
	if code := statusOf(t, signedAs(t, "node0", []byte(benchPrivPEM()), "GET",
		srv.URL()+"/organizations/acme/nodes/node0", "")); code != http.StatusOK {
		t.Fatalf("seeded client read own node = %d, want 200", code)
	}
	// And the ACL is real: it cannot read a node it does not own.
	if err := org.Put("nodes", "other", benchFleetNodeBody("other")); err != nil {
		t.Fatal(err)
	}
	if err := org.Put("acls", "nodes/other", []byte(
		`{"read":{"actors":["someone-else"],"groups":[]}}`)); err != nil {
		t.Fatal(err)
	}
	if code := statusOf(t, signedAs(t, "node0", []byte(benchPrivPEM()), "GET",
		srv.URL()+"/organizations/acme/nodes/other", "")); code != http.StatusForbidden {
		t.Fatalf("seeded client read foreign node = %d, want 403", code)
	}
}
