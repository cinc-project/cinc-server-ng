package api

import (
	"fmt"
	"testing"

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
		ci.mu.RLock()
		defer ci.mu.RUnlock()
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
