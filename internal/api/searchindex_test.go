package api

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/search"
	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// The cache must stay bounded no matter how many distinct documents are seen.
func TestSearchCacheStaysBounded(t *testing.T) {
	c := newSearchCache()
	for i := range maxSearchCacheEntries * 3 {
		c.store(fmt.Sprintf("k%d", i), searchEntry{})
	}
	n := 0
	c.m.Range(func(any, any) bool { n++; return true })
	if n > maxSearchCacheEntries {
		t.Fatalf("cache holds %d entries, bound is %d", n, maxSearchCacheEntries)
	}
}

// The index is maintained from the write stream, so a document written, changed
// or deleted after the index was built must be reflected on the next query.
func TestSearchIndexTracksWrites(t *testing.T) {
	st := store.New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	a := New(st)
	if err := org.Put("nodes", "web01", []byte(`{"name":"web01","chef_environment":"staging"}`)); err != nil {
		t.Fatal(err)
	}

	ids := func(query string) []string {
		t.Helper()
		ci, err := a.searchIdx.get(org, "nodes", true)
		if err != nil {
			t.Fatal(err)
		}
		q, err := parseForTest(query)
		if err != nil {
			t.Fatal(err)
		}
		set, ok := planForTest(q, postingsView{ci})
		if !ok {
			t.Fatalf("query %q not plannable", query)
		}
		out := make([]string, 0, len(set))
		for id := range set {
			out = append(out, id)
		}
		return out
	}

	if got := ids("chef_environment:staging"); len(got) != 1 || got[0] != "web01" {
		t.Fatalf("initial build: %v, want [web01]", got)
	}
	// A write after the build must be picked up...
	if err := org.Put("nodes", "web02", []byte(`{"name":"web02","chef_environment":"staging"}`)); err != nil {
		t.Fatal(err)
	}
	if got := ids("chef_environment:staging"); len(got) != 2 {
		t.Fatalf("after insert: %v, want two nodes", got)
	}
	// ...as must a change that moves a document out of the result set...
	if err := org.Put("nodes", "web02", []byte(`{"name":"web02","chef_environment":"production"}`)); err != nil {
		t.Fatal(err)
	}
	if got := ids("chef_environment:staging"); len(got) != 1 || got[0] != "web01" {
		t.Fatalf("after update: %v, want [web01]", got)
	}
	if got := ids("chef_environment:production"); len(got) != 1 || got[0] != "web02" {
		t.Fatalf("after update: %v, want [web02]", got)
	}
	// ...and a delete.
	if _, _, err := org.Delete("nodes", "web01"); err != nil {
		t.Fatal(err)
	}
	if got := ids("chef_environment:staging"); len(got) != 0 {
		t.Fatalf("after delete: %v, want none", got)
	}
}

// Dropping an organization must not leave its documents visible to a new
// organization that reuses the name.
func TestSearchIndexDroppedWithOrg(t *testing.T) {
	st := store.New()
	org, _ := st.CreateOrg("acme")
	a := New(st)
	if err := org.Put("nodes", "web01", []byte(`{"name":"web01"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := a.searchIdx.get(org, "nodes", true); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeleteOrg("acme"); err != nil {
		t.Fatal(err)
	}
	fresh, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	ci, err := a.searchIdx.get(fresh, "nodes", true)
	if err != nil {
		t.Fatal(err)
	}
	ci.mu.RLock()
	defer ci.mu.RUnlock()
	if ci.size() != 0 {
		t.Fatalf("recreated org inherited %d indexed documents", ci.size())
	}
}

// wideNode builds a node of about size bytes whose normal attributes are as
// many short, distinct keys as fit: the cheapest way, per body byte, to give
// the index a distinct field.
func wideNode(size int) []byte {
	var b strings.Builder
	b.WriteString(`{"name":"wide","normal":{`)
	for i := 0; b.Len() < size-32; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"%x":0`, i)
	}
	b.WriteString(`}}`)
	return []byte(b.String())
}

func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// The index keeps what a document contributes for as long as the document
// exists, so its cost per field bounds what one write can pin. A node body at
// the request cap made of short distinct keys gives it about 400K fields, each
// with one value held by one document: that shape must not cost a set (or
// several) per field.
func TestSearchIndexWideDocumentHeap(t *testing.T) {
	raw := wideNode(2_000_000)
	before := heapInUse()
	ci := newCollIndex(true)
	ci.putRaw("wide", raw)
	retained := heapInUse() - before
	fields := len(ci.fields)
	runtime.KeepAlive(ci)

	if fields < 400_000 {
		t.Fatalf("indexed %d fields, want the node's ~400K", fields)
	}
	perField := retained / uint64(fields)
	t.Logf("%d body bytes, %d fields, %d MB retained, %d bytes/field", len(raw), fields, retained>>20, perField)
	if perField > 250 {
		t.Fatalf("index retains %d bytes per field, want at most 250", perField)
	}
}

// A field moves between holding one value and several as documents come and
// go; every lookup must answer the same through those transitions.
func TestSearchIndexFieldValueTransitions(t *testing.T) {
	ci := newCollIndex(false)
	look := func(what string, got search.DocIDs, want ...string) {
		t.Helper()
		ids := make([]string, 0, len(got))
		for id := range got {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		sort.Strings(want)
		if strings.Join(ids, ",") != strings.Join(want, ",") {
			t.Fatalf("%s = %v, want %v", what, ids, want)
		}
	}
	p := postingsView{ci}
	isB := func(v string) bool { return v == "b" }

	ci.putRaw("1", []byte(`{"f":"a"}`))
	look("Exact a", p.Exact("f", "a"), "1")
	look("Exists", p.Exists("f"), "1")

	ci.putRaw("2", []byte(`{"f":"a"}`))
	ci.putRaw("3", []byte(`{"f":["b","a","b"]}`))
	look("Exact a", p.Exact("f", "a"), "1", "2", "3")
	look("Exact b", p.Exact("f", "b"), "3")
	look("Exists", p.Exists("f"), "1", "2", "3")
	look("Match b", p.Match("f", isB), "3")
	look("MatchAny b", p.MatchAny(isB), "3")

	ci.putRaw("1", []byte(`{"g":"a"}`))
	ci.remove("2")
	look("Exact a", p.Exact("f", "a"), "3")
	look("Exists", p.Exists("f"), "3")
	look("Exists g", p.Exists("g"), "1")

	ci.putRaw("3", []byte(`{"f":"b"}`))
	look("Exact a", p.Exact("f", "a"))
	look("Exact b", p.Exact("f", "b"), "3")
	look("Exists", p.Exists("f"), "3")

	ci.remove("3")
	ci.remove("1")
	look("Exists", p.Exists("f"))
	look("All", p.All())
	if len(ci.fields) != 0 {
		t.Fatalf("emptied index still holds %d fields", len(ci.fields))
	}
}
