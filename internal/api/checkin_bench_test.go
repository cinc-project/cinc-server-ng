package api

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/store"
	"github.com/tas50/cinc-server-ng/internal/store/sqlite"
)

// nodeBody is a representative chef-client node document (the shape fleetsim
// round-trips on every check-in: a GET then a PUT of the same object).
func benchNodeBody(name string) []byte {
	return []byte(fmt.Sprintf(`{"name":%q,"chef_environment":"production","json_class":"Chef::Node",`+
		`"chef_type":"node","normal":{"tags":["a","b","c"]},`+
		`"automatic":{"os":"linux","ohai_time":1700000000.0,"memory":{"total":"16gb"},`+
		`"ipaddress":"10.0.0.1","network":{"interfaces":{"eth0":{"addr":"10.0.0.1"}}}},`+
		`"default":{},"override":{},"run_list":["recipe[nginx]","recipe[base]"]}`, name))
}

// benchCheckins drives a check-in workload (GET node + PUT node) concurrently
// against a store backed by mk. It models the fleetsim/chef-client steady state:
// every worker repeatedly reads and writes a node it "owns".
func benchCheckins(b *testing.B, nodes int, mk func(b *testing.B) *store.Store) {
	st := mk(b)
	org, err := st.CreateOrg("acme")
	if err != nil {
		b.Fatal(err)
	}
	for i := range nodes {
		if err := org.Put("nodes", fmt.Sprintf("node%d", i), benchNodeBody(fmt.Sprintf("node%d", i))); err != nil {
			b.Fatal(err)
		}
	}
	h := New(st).Handler()

	var seq atomic.Int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			name := fmt.Sprintf("node%d", int(seq.Add(1))%nodes)
			get := httptest.NewRequest("GET", "http://127.0.0.1/organizations/acme/nodes/"+name, nil)
			grec := httptest.NewRecorder()
			h.ServeHTTP(grec, get)
			if grec.Code != 200 {
				b.Fatalf("GET %s: status %d", name, grec.Code)
			}
			put := httptest.NewRequest("PUT", "http://127.0.0.1/organizations/acme/nodes/"+name, bytes.NewReader(benchNodeBody(name)))
			prec := httptest.NewRecorder()
			h.ServeHTTP(prec, put)
			if prec.Code != 200 && prec.Code != 201 {
				b.Fatalf("PUT %s: status %d", name, prec.Code)
			}
		}
	})
}

func memStore(b *testing.B) *store.Store { return store.New() }

func sqliteStore(b *testing.B) *store.Store {
	be, err := sqlite.Open(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { be.Close() })
	return store.NewWithBackend(be)
}

func BenchmarkCheckinsMemory(b *testing.B) { benchCheckins(b, 1107, memStore) }
func BenchmarkCheckinsSQLite(b *testing.B) { benchCheckins(b, 1107, sqliteStore) }
