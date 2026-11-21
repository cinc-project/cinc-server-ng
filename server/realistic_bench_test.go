package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
)

// The fleet benchmarks use a node a few hundred bytes long. A real node, with
// the automatic attributes Ohai collects, is tens of kilobytes, and every
// chef-client run saves the whole document back; how the server decodes,
// stores and indexes that body dominates the cost of a run. These benchmarks
// use a captured real node (23 KB, from the development seed repository)
// through the whole stack: signature verification, ACL enforcement, store,
// and search index.

var realisticNode = sync.OnceValue(func() []byte {
	body, err := os.ReadFile("../dev/test-repo/organizations/acme/nodes/prod-db-08.json")
	if err != nil {
		panic("realistic node: " + err.Error())
	}
	return body
})

func realisticNodeBody(name string) []byte {
	return bytes.Replace(realisticNode(), []byte(`"name": "prod-db-08"`), fmt.Appendf(nil, `"name": %q`, name), 1)
}

// seedRealisticFleet registers n clients through seedFleet, then saves each
// one's realistic node through the API, so every version stores the document
// the way its own write path does.
func seedRealisticFleet(b *testing.B, srv *Server, n int) []preparedReq {
	b.Helper()
	seedFleet(b, srv, n)
	key, err := auth.ParsePrivateKey([]byte(benchPrivPEM()))
	if err != nil {
		b.Fatal(err)
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	reqs := make([]preparedReq, 0, n*2)
	for i := range n {
		name := fmt.Sprintf("node%d", i)
		url := "http://127.0.0.1/organizations/acme/nodes/" + name
		body := realisticNodeBody(name)
		for _, p := range []preparedReq{{method: "GET", url: url}, {method: "PUT", url: url, body: body}} {
			req := httptest.NewRequest(p.method, p.url, nil)
			req.Header.Set("X-Ops-Server-API-Version", "1")
			if err := auth.SignRequest(req, name, ts, p.body, key); err != nil {
				b.Fatal(err)
			}
			p.header = req.Header
			reqs = append(reqs, p)
		}
		reqs[len(reqs)-1].do(b, srv.handler) // store the realistic node
	}
	return reqs
}

func newRealisticServer(b *testing.B, opts Options) *Server {
	b.Helper()
	opts.Orgs = []string{"acme"}
	opts.EnforceACL = true
	srv, err := New(opts)
	if err != nil {
		b.Fatal(err)
	}
	if opts.Backend == nil {
		b.Cleanup(func() { srv.Store().Close() })
	}
	return srv
}

// One node saving its realistic document, one request at a time: the latency
// a single chef-client run's final PUT sees.
func BenchmarkRealisticNodeSave(b *testing.B) {
	srv := newRealisticServer(b, Options{})
	reqs := seedRealisticFleet(b, srv, 1)
	put := reqs[1]
	b.SetBytes(int64(len(put.body)))
	b.ResetTimer()
	for b.Loop() {
		put.do(b, srv.handler)
	}
}

// A fleet of 512 realistic nodes checking in concurrently: each run's GET and
// PUT of its own node.
func benchRealisticCheckin(b *testing.B, opts Options) {
	srv := newRealisticServer(b, opts)
	reqs := seedRealisticFleet(b, srv, benchFleetNodes)
	var seq atomic.Int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reqs[int(seq.Add(1))%len(reqs)].do(b, srv.handler)
		}
	})
}

func BenchmarkRealisticCheckin(b *testing.B) { benchRealisticCheckin(b, Options{}) }
func BenchmarkRealisticCheckinSQLite(b *testing.B) {
	benchRealisticCheckin(b, Options{Backend: benchSQLiteBackend(b)})
}

// A search over 512 realistic nodes that one node is authorized to read a
// result of: the index lookup, the ACL filter, and the row it returns.
func BenchmarkRealisticSearch(b *testing.B) {
	srv := newRealisticServer(b, Options{})
	seedRealisticFleet(b, srv, benchFleetNodes)
	key, err := auth.ParsePrivateKey([]byte(benchPrivPEM()))
	if err != nil {
		b.Fatal(err)
	}
	url := "http://127.0.0.1/organizations/acme/search/node?q=name:node7"
	req := httptest.NewRequest("GET", url, nil)
	req.Header.Set("X-Ops-Server-API-Version", "1")
	if err := auth.SignRequest(req, "node7", time.Now().UTC().Format(time.RFC3339), nil, key); err != nil {
		b.Fatal(err)
	}
	p := preparedReq{method: "GET", url: url, header: req.Header}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p.do(b, srv.handler)
		}
	})
}

// The realistic seed actually authorizes the reads and writes it benchmarks.
func TestRealisticBenchSeedIsUsable(t *testing.T) {
	res := testing.Benchmark(func(b *testing.B) {
		srv := newRealisticServer(b, Options{})
		reqs := seedRealisticFleet(b, srv, 2)
		for _, r := range reqs {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(r.method, r.url, bytes.NewReader(r.body))
			req.Header = r.header
			srv.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				b.Fatalf("%s %s = %d: %s", r.method, r.url, rec.Code, rec.Body)
			}
		}
	})
	if res.N == 0 {
		t.Fatal("realistic seed failed")
	}
}
