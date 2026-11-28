package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// A query past the parser's limits is refused the way any unparseable query
// is: a 400 whose error says the query is invalid.
func TestSearchRefusesUnboundedQuery(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	seedNode(t, base, "web01", "production", "x")

	// Baseline: the established form for an unparseable query.
	resp, body := do(t, "GET", base+"/search/node?q=%28unclosed", "")
	if resp.StatusCode != 400 || !strings.Contains(body, "invalid search query: ") {
		t.Fatalf("unparseable query = %d %s", resp.StatusCode, body)
	}

	deep := strings.Repeat("(", 5000) + "name:web01" + strings.Repeat(")", 5000)
	resp, body = do(t, "GET", base+"/search/node?q="+url.QueryEscape(deep), "")
	if resp.StatusCode != 400 {
		t.Fatalf("deeply nested query = %d, want 400", resp.StatusCode)
	}
	var e struct{ Error []string }
	if err := json.Unmarshal([]byte(body), &e); err != nil || len(e.Error) != 1 ||
		!strings.HasPrefix(e.Error[0], "invalid search query: ") {
		t.Fatalf("deeply nested query body = %s, want the invalid-query error", body)
	}
}

// A host-list query across a large fleet, as a recipe generates it, still
// answers.
func TestSearchLongHostListQuery(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	seedNode(t, base, "web01", "production", "x")
	names := make([]string, 800)
	for i := range names {
		names[i] = fmt.Sprintf("name:node%04d.example.com", i)
	}
	names[400] = "name:web01"
	q := strings.Join(names, " OR ")
	resp, body := do(t, "GET", base+"/search/node?q="+url.QueryEscape(q), "")
	if resp.StatusCode != 200 {
		t.Fatalf("host-list query = %d: %s", resp.StatusCode, body)
	}
	var r searchResult
	if err := json.Unmarshal([]byte(body), &r); err != nil || r.Total != 1 {
		t.Fatalf("host-list query total = %d (%v), want 1", r.Total, err)
	}
}

// The postings view locks the index per lookup rather than relying on the
// caller to hold it across a whole plan, so a plan of many terms never keeps
// the writers that maintain the index waiting for all of them. Planning with
// no lock held while writes land must therefore be race-free.
func TestPostingsViewLocksPerLookup(t *testing.T) {
	st := store.New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	a := New(st)
	ci, err := a.searchIdx.get(org, "nodes", true)
	if err != nil {
		t.Fatal(err)
	}
	q, err := parseForTest("name:web* OR NOT chef_environment:prod OR web OR role:[a TO z] OR name:*")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 200 {
			id := fmt.Sprintf("web%03d", i)
			if err := org.Put("nodes", id, []byte(`{"name":"`+id+`","chef_environment":"prod"}`)); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for range 200 {
		if _, ok := planForTest(q, postingsView{ci}); !ok {
			t.Fatal("query not plannable")
		}
	}
	wg.Wait()
}
