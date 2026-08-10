package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tas50/cinc-server-ng/internal/auth"
)

// Scale benchmarks: how cost grows with fleet size, rather than what one
// request costs at a fixed size. A server for thousands of nodes is judged on
// the slope, not the intercept — anything super-linear here is a wall.

// seedScaleFleet registers n clients, their nodes, and a per-node ACL naming
// the owning client, then returns the org handle.
func seedScaleFleet(b *testing.B, srv *Server, n int) {
	b.Helper()
	org, ok, err := srv.Store().Org("acme")
	if err != nil || !ok {
		b.Fatalf("org acme: ok=%v err=%v", ok, err)
	}
	for i := range n {
		name := fmt.Sprintf("node%d", i)
		if err := org.Put("clients", name, fmt.Appendf(nil,
			`{"name":%q,"clientname":%q,"validator":false,"public_key":%q}`,
			name, name, benchPubPEM())); err != nil {
			b.Fatal(err)
		}
		if err := org.Put("nodes", name, benchFleetNodeBody(name)); err != nil {
			b.Fatal(err)
		}
		if err := org.Put("acls", "nodes/"+name, fmt.Appendf(nil,
			`{"read":{"actors":[%q],"groups":["admins"]}}`, name)); err != nil {
			b.Fatal(err)
		}
	}
}

// benchSearchAtScale measures one enforced search against a fleet of n nodes,
// with the caches already warm, so the number reflects steady-state query cost.
func benchSearchAtScale(b *testing.B, n int, query string) {
	srv, err := New(Options{Orgs: []string{"acme"}, EnforceACL: true})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { srv.Store().Close() })
	seedScaleFleet(b, srv, n)

	key, err := auth.ParsePrivateKey([]byte(benchPrivPEM()))
	if err != nil {
		b.Fatal(err)
	}
	url := "http://127.0.0.1/organizations/acme/search/node?q=" + query
	req := httptest.NewRequest("GET", url, nil)
	req.Header.Set("X-Ops-Server-API-Version", "1")
	if err := auth.SignRequest(req, "node0", time.Now().UTC().Format(time.RFC3339), nil, key); err != nil {
		b.Fatal(err)
	}
	hdr := req.Header
	h := srv.handler

	do := func() {
		r := httptest.NewRequest("GET", url, nil)
		r.Header = hdr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			b.Fatalf("search: status %d: %s", rec.Code, rec.Body)
		}
	}
	for range 3 { // warm any lazily-built state
		do()
	}
	b.ResetTimer()
	for range b.N {
		do()
	}
}

// An exact field match — the overwhelmingly common chef-client search shape
// ("give me the nodes in this environment / with this role").
func BenchmarkSearchScaleExact512(b *testing.B) {
	benchSearchAtScale(b, 512, "chef_environment:production")
}
func BenchmarkSearchScaleExact2048(b *testing.B) {
	benchSearchAtScale(b, 2048, "chef_environment:production")
}
func BenchmarkSearchScaleExact8192(b *testing.B) {
	benchSearchAtScale(b, 8192, "chef_environment:production")
}

// A selective match: one node out of the fleet. Cost should track the number of
// results, not the size of the collection.
func BenchmarkSearchScaleSelective512(b *testing.B) {
	benchSearchAtScale(b, 512, "name:node7")
}
func BenchmarkSearchScaleSelective2048(b *testing.B) {
	benchSearchAtScale(b, 2048, "name:node7")
}
func BenchmarkSearchScaleSelective8192(b *testing.B) {
	benchSearchAtScale(b, 8192, "name:node7")
}
