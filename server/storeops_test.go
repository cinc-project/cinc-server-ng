package server

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// Store-operation accounting for the fleet hot path.
//
// Throughput on a durable backend is set less by how fast one store operation
// is than by how many of them a single request performs: on SQLite each read is
// a round trip through the driver, so read amplification in the authentication
// and authorization layers costs more than the write the request came to make.
// This pins the count down so a regression in it is visible.

// countingBackend wraps a Backend and tallies the operations performed.
type countingBackend struct {
	store.Backend
	gets, puts, ranges, keys atomic.Int64
}

func (c *countingBackend) Get(org, coll, key string) ([]byte, bool, error) {
	c.gets.Add(1)
	return c.Backend.Get(org, coll, key)
}

func (c *countingBackend) Put(org, coll, key string, val []byte) error {
	c.puts.Add(1)
	return c.Backend.Put(org, coll, key, val)
}

func (c *countingBackend) Range(org, coll string, fn func(string, []byte) bool) error {
	c.ranges.Add(1)
	return c.Backend.Range(org, coll, fn)
}

func (c *countingBackend) Keys(org, coll string) ([]string, error) {
	c.keys.Add(1)
	return c.Backend.Keys(org, coll)
}

func (c *countingBackend) reset() {
	c.gets.Store(0)
	c.puts.Store(0)
	c.ranges.Store(0)
	c.keys.Store(0)
}

func (c *countingBackend) String() string {
	return fmt.Sprintf("gets=%d puts=%d ranges=%d keys=%d",
		c.gets.Load(), c.puts.Load(), c.ranges.Load(), c.keys.Load())
}

// TestCheckinStoreOpCount records how many store operations one node check-in
// costs. The numbers are asserted loosely (an upper bound) so the test documents
// the shape of the cost and fails if it regresses, without churning on every
// unrelated change.
func TestCheckinStoreOpCount(t *testing.T) {
	counting := &countingBackend{Backend: store.NewMemoryBackend()}
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true, Backend: counting})

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
	url := srv.URL() + "/organizations/acme/nodes/node0"
	key := []byte(benchPrivPEM())

	for _, c := range []struct {
		name, method, body string
		maxGets            int64
	}{
		// A GET must not read the node twice. Authorization checks the object's
		// existence before allowing the request, and the handler then needs the
		// same bytes; that read is handed forward rather than repeated.
		{"GET node", "GET", "", 3},
		{"PUT node", "PUT", string(benchFleetNodeBody("node0")), 3},
	} {
		counting.reset()
		if code := statusOf(t, signedAs(t, "node0", key, c.method, url, c.body)); code != http.StatusOK {
			t.Fatalf("%s = %d, want 200", c.name, code)
		}
		t.Logf("%-9s %s", c.name, counting)
		if got := counting.gets.Load(); got > c.maxGets {
			t.Errorf("%s performed %d store reads, want at most %d — read amplification "+
				"on the fleet hot path dominates durable-backend throughput",
				c.name, got, c.maxGets)
		}
	}
}

// A group-granted ACL forces membership resolution, which scans every group in
// the org. That makes per-request cost grow with fleet size.
func TestCheckinGroupResolutionScansGroups(t *testing.T) {
	counting := &countingBackend{Backend: store.NewMemoryBackend()}
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true, Backend: counting})

	org, _, _ := srv.Store().Org("acme")
	if err := org.Put("clients", "node0", []byte(fmt.Sprintf(
		`{"name":"node0","clientname":"node0","validator":false,"public_key":%q}`, benchPubPEM()))); err != nil {
		t.Fatal(err)
	}
	if err := org.Put("nodes", "node0", benchFleetNodeBody("node0")); err != nil {
		t.Fatal(err)
	}
	// Granted through a group rather than by name, as Chef's default ACL is.
	if err := org.Put("acls", "nodes/node0", []byte(
		`{"read":{"actors":[],"groups":["clients"]}}`)); err != nil {
		t.Fatal(err)
	}
	if err := org.Put("groups", "clients", []byte(
		`{"name":"clients","groupname":"clients","actors":["node0"],"users":[],"clients":["node0"],"groups":[]}`)); err != nil {
		t.Fatal(err)
	}

	counting.reset()
	if code := statusOf(t, signedAs(t, "node0", []byte(benchPrivPEM()), "GET",
		srv.URL()+"/organizations/acme/nodes/node0", "")); code != http.StatusOK {
		t.Fatalf("group-granted read = %d, want 200", code)
	}
	t.Logf("group-granted GET %s", counting)
	if counting.ranges.Load() == 0 {
		t.Error("expected a groups scan; if this stops happening, membership resolution changed")
	}
}
