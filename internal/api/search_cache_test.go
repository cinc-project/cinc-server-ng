package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/search"
	"github.com/tas50/cinc-server-ng/internal/store"
)

// cacheLen counts the live entries in the flatten cache.
func cacheLen(c *searchCache) int {
	n := 0
	c.m.Range(func(_, _ any) bool { n++; return true })
	return n
}

// TestSearchMatchAllSkipsFlatten asserts the match-all fast path: a *:* search
// with no partial body returns every document (sorted by id) without flattening
// any of them, so the flatten cache stays empty.
func TestSearchMatchAllSkipsFlatten(t *testing.T) {
	st := store.New()
	if _, err := st.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	a := New(st)
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	base := srv.URL + "/organizations/acme"
	for _, n := range []string{"web02", "db01", "web01"} {
		seedNode(t, base, n, "production", "x")
	}

	var res searchResult
	_, body := do(t, "GET", base+"/search/node?q=*:*", "")
	json.Unmarshal([]byte(body), &res)
	if res.Total != 3 || len(res.Rows) != 3 {
		t.Fatalf("*:* total=%d rows=%d, want 3/3: %s", res.Total, len(res.Rows), body)
	}
	if n := cacheLen(a.search); n != 0 {
		t.Fatalf("match-all search flattened %d docs; the fast path must skip flatten (want 0)", n)
	}
	// Rows are sorted by id.
	var prev string
	for _, raw := range res.Rows {
		var node struct {
			Name string `json:"name"`
		}
		json.Unmarshal(raw, &node)
		if prev != "" && node.Name <= prev {
			t.Fatalf("rows not sorted by id: %q after %q", node.Name, prev)
		}
		prev = node.Name
	}
}

// TestSearchParallelScanConsistency seeds enough nodes to exercise the parallel
// cold-build path and asserts a filtered scan returns exactly the matching set,
// sorted — guarding correctness when the per-doc flatten+match runs concurrently.
func TestSearchParallelScanConsistency(t *testing.T) {
	st := store.New()
	if _, err := st.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	a := New(st)
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	base := srv.URL + "/organizations/acme"

	const n = 200
	want := 0
	for i := range n {
		env := "staging"
		if i%2 == 0 {
			env = "production"
			want++
		}
		seedNode(t, base, fmt.Sprintf("node%03d", i), env, "x")
	}

	var res searchResult
	_, body := do(t, "GET", base+"/search/node?q=chef_environment:production&rows=1000", "")
	json.Unmarshal([]byte(body), &res)
	if res.Total != want || len(res.Rows) != want {
		t.Fatalf("filtered total=%d rows=%d, want %d: %s", res.Total, len(res.Rows), want, body)
	}
	var prev string
	for _, raw := range res.Rows {
		var node struct {
			Name string `json:"name"`
		}
		json.Unmarshal(raw, &node)
		if prev != "" && node.Name <= prev {
			t.Fatalf("rows not sorted by id: %q after %q", node.Name, prev)
		}
		prev = node.Name
	}
}

// benchSearchOrg seeds n nodes with nested attributes for the search benchmarks.
func benchSearchOrg(b *testing.B, n int) (*API, *store.Org, searchIndex, search.Query) {
	b.Helper()
	st := store.New()
	org, _ := st.CreateOrg("acme")
	a := New(st)
	for i := range n {
		doc := fmt.Sprintf(`{"name":"node%d","chef_environment":"production",`+
			`"normal":{"foo":{"bar":"baz%d"},"tags":["a","b","c"]},`+
			`"automatic":{"os":"linux","memory":{"total":"16gb"},`+
			`"network":{"interfaces":{"eth0":{"addr":"10.0.0.%d"}}}},`+
			`"run_list":["recipe[nginx]","recipe[base]"]}`, i, i, i%256)
		if err := org.Put("nodes", fmt.Sprintf("node%d", i), []byte(doc)); err != nil {
			b.Fatal(err)
		}
	}
	idx, _, err := a.resolveIndex(nil, org, "node")
	if err != nil {
		b.Fatal(err)
	}
	q, err := search.Parse("chef_environment:production")
	if err != nil {
		b.Fatal(err)
	}
	return a, org, idx, q
}

// BenchmarkSearchScanCold measures a scan that re-unmarshals and re-flattens
// every document — the cost paid on every query before caching (and on the
// first query of any object after a write).
func BenchmarkSearchScanCold(b *testing.B) {
	a, org, idx, q := benchSearchOrg(b, 200)
	b.ReportAllocs()
	for b.Loop() {
		a.search = newSearchCache() // force a full recompute each iteration
		if _, err := a.collectMatches(org, idx, q); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSearchScanWarm measures a scan served entirely from the flatten
// cache — the steady-state cost of repeated queries over unchanged objects.
func BenchmarkSearchScanWarm(b *testing.B) {
	a, org, idx, q := benchSearchOrg(b, 200)
	if _, err := a.collectMatches(org, idx, q); err != nil { // warm the cache
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := a.collectMatches(org, idx, q); err != nil {
			b.Fatal(err)
		}
	}
}

// mapPtr returns the runtime identity of a map, so tests can assert whether two
// results are the same cached instance or freshly recomputed.
func mapPtr(m any) uintptr { return reflect.ValueOf(m).Pointer() }

func TestSearchDocCachesUnchangedContent(t *testing.T) {
	st := store.New()
	org, _ := st.CreateOrg("acme")
	a := New(st)
	if err := org.Put("nodes", "web", []byte(`{"name":"web","normal":{"foo":"bar"}}`)); err != nil {
		t.Fatal(err)
	}
	raw, _, err := org.View("nodes", "web")
	if err != nil {
		t.Fatal(err)
	}

	_, f1, ok1 := a.searchDoc("nodes", "web", raw, true)
	_, f2, ok2 := a.searchDoc("nodes", "web", raw, true)
	if !ok1 || !ok2 {
		t.Fatal("searchDoc returned not-ok for a valid node")
	}
	if !slices.Contains(f1["foo"], "bar") {
		t.Fatalf("flatten produced %v for foo, want it to contain bar", f1["foo"])
	}
	// Same backing slice → cache hit → the identical fields map is reused.
	if mapPtr(f1) != mapPtr(f2) {
		t.Fatal("expected the cached fields map to be reused for unchanged content")
	}
}

func TestSearchDocRecomputesAfterContentChange(t *testing.T) {
	st := store.New()
	org, _ := st.CreateOrg("acme")
	a := New(st)
	if err := org.Put("nodes", "web", []byte(`{"name":"web","normal":{"foo":"bar"}}`)); err != nil {
		t.Fatal(err)
	}
	raw1, _, err := org.View("nodes", "web")
	if err != nil {
		t.Fatal(err)
	}
	_, f1, _ := a.searchDoc("nodes", "web", raw1, true)

	// Updating the node replaces the stored slice, so the cache must recompute.
	if err := org.Put("nodes", "web", []byte(`{"name":"web","normal":{"foo":"changed"}}`)); err != nil {
		t.Fatal(err)
	}
	raw2, _, err := org.View("nodes", "web")
	if err != nil {
		t.Fatal(err)
	}
	_, f2, ok := a.searchDoc("nodes", "web", raw2, true)
	if !ok {
		t.Fatal("searchDoc returned not-ok after update")
	}
	if mapPtr(f1) == mapPtr(f2) {
		t.Fatal("stale cache entry reused after the content changed")
	}
	if !slices.Contains(f2["foo"], "changed") || slices.Contains(f2["foo"], "bar") {
		t.Fatalf("recomputed flatten produced %v for foo, want it to contain changed and not bar", f2["foo"])
	}
}

// TestSearchDocConcurrentAccess hammers searchDoc from many goroutines over a
// shared set of nodes (the search-scan access pattern) and asserts every caller
// gets a correct flattened view. Run under -race, it guards the cache against
// data races when its locking is changed.
func TestSearchDocConcurrentAccess(t *testing.T) {
	st := store.New()
	org, _ := st.CreateOrg("acme")
	a := New(st)
	const nodes = 50
	raws := make([][]byte, nodes)
	for i := range nodes {
		id := fmt.Sprintf("node%d", i)
		if err := org.Put("nodes", id, []byte(fmt.Sprintf(`{"name":%q,"normal":{"idx":%d}}`, id, i))); err != nil {
			t.Fatal(err)
		}
		raw, _, err := org.View("nodes", id)
		if err != nil {
			t.Fatal(err)
		}
		raws[i] = raw
	}

	var wg sync.WaitGroup
	for g := range 16 {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for range 100 {
				i := g % nodes
				_, fields, ok := a.searchDoc("nodes", fmt.Sprintf("node%d", i), raws[i], true)
				if !ok || !slices.Contains(fields["idx"], strconv.Itoa(i)) {
					t.Errorf("node%d: ok=%v fields[idx]=%v", i, ok, fields["idx"])
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestSearchDocReportsNotOKForInvalidJSON(t *testing.T) {
	st := store.New()
	org, _ := st.CreateOrg("acme")
	a := New(st)
	if err := org.Put("nodes", "broken", []byte(`not json`)); err != nil {
		t.Fatal(err)
	}
	raw, _, err := org.View("nodes", "broken")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := a.searchDoc("nodes", "broken", raw, false); ok {
		t.Fatal("searchDoc should report not-ok for undecodable JSON")
	}
}
