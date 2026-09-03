package sqlite_test

import (
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
)

// nodeBody is a representative chef-client node document, the shape the fleet
// check-in path round-trips on every request.
func nodeBody(name string) []byte {
	return []byte(fmt.Sprintf(`{"name":%q,"chef_environment":"production","json_class":"Chef::Node",`+
		`"chef_type":"node","normal":{"tags":["a","b","c"]},`+
		`"automatic":{"os":"linux","ohai_time":1700000000.0,"memory":{"total":"16gb"},`+
		`"ipaddress":"10.0.0.1","network":{"interfaces":{"eth0":{"addr":"10.0.0.1"}}}},`+
		`"default":{},"override":{},"run_list":["recipe[nginx]","recipe[base]"]}`, name))
}

func benchBackend(b *testing.B) *sqlite.Backend {
	be, err := sqlite.Open(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { be.Close() })
	return be
}

// BenchmarkGet measures single-row read latency through the backend (the GET
// half of a check-in). It is dominated by the driver's per-call statement
// handling, not I/O, since the row is already cached.
func BenchmarkGet(b *testing.B) {
	be := benchBackend(b)
	if err := be.Put("acme", "nodes", "node0", nodeBody("node0")); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok, err := be.Get("acme", "nodes", "node0"); err != nil || !ok {
			b.Fatalf("get: ok=%v err=%v", ok, err)
		}
	}
}

// BenchmarkPut measures single-row write (upsert) latency through the backend
// (the PUT half of a check-in).
func BenchmarkPut(b *testing.B) {
	be := benchBackend(b)
	body := nodeBody("node0")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := be.Put("acme", "nodes", "node0", body); err != nil {
			b.Fatal(err)
		}
	}
}

func openBench(b *testing.B, opts ...sqlite.Option) *sqlite.Backend {
	be, err := sqlite.Open(filepath.Join(b.TempDir(), "bench.db"), opts...)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { be.Close() })
	return be
}

func seedNodes(b *testing.B, be *sqlite.Backend, nodes int) {
	for i := 0; i < nodes; i++ {
		n := fmt.Sprintf("node%d", i)
		if err := be.Put("acme", "nodes", n, nodeBody(n)); err != nil {
			b.Fatal(err)
		}
	}
}

// benchCheckin models the steady-state fleet workload: a GET of a node followed
// by a PUT of the same node, run concurrently across the fleet.
func benchCheckin(b *testing.B, be *sqlite.Backend) {
	const nodes = 1107
	seedNodes(b, be, nodes)
	var seq atomic.Int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n := fmt.Sprintf("node%d", int(seq.Add(1))%nodes)
			if _, _, err := be.Get("acme", "nodes", n); err != nil {
				b.Fatal(err)
			}
			if err := be.Put("acme", "nodes", n, nodeBody(n)); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkCheckin / BenchmarkCheckinGroupCommit: concurrent fleet load. Group
// commit batches the concurrently-pending PUTs into shared transactions,
// amortizing the per-commit WAL syscalls — the win this workload targets.
func BenchmarkCheckin(b *testing.B) { benchCheckin(b, openBench(b)) }
func BenchmarkCheckinGroupCommit(b *testing.B) {
	benchCheckin(b, openBench(b, sqlite.WithGroupCommit()))
}

// benchSerialPut is the single-client write path (no concurrency, so no batch
// ever forms). Group commit's extra goroutine handoff makes this slightly slower
// — the documented latency cost that keeps it opt-in.
func benchSerialPut(b *testing.B, be *sqlite.Backend) {
	body := nodeBody("node0")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := be.Put("acme", "nodes", "node0", body); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSerialPut(b *testing.B) { benchSerialPut(b, openBench(b)) }
func BenchmarkSerialPutGroupCommit(b *testing.B) {
	benchSerialPut(b, openBench(b, sqlite.WithGroupCommit()))
}

// BenchmarkHasOrg measures the org-existence probe that the API layer runs on
// every request (a.org → HasOrg) before the actual data operation.
func BenchmarkHasOrg(b *testing.B) {
	be := benchBackend(b)
	if err := be.CreateOrg("acme"); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, err := be.HasOrg("acme"); err != nil || !ok {
			b.Fatalf("hasorg: ok=%v err=%v", ok, err)
		}
	}
}

// BenchmarkHasBlob measures the blob-existence probe that the cookbook upload
// (sandbox) path runs for every file checksum a client offers.
func BenchmarkHasBlob(b *testing.B) {
	be := benchBackend(b)
	if err := be.PutBlob("acme", "abc123", []byte("file contents")); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, err := be.HasBlob("acme", "abc123"); err != nil || !ok {
			b.Fatalf("hasblob: ok=%v err=%v", ok, err)
		}
	}
}
