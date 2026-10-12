package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// withBase points the harness at srv for the duration of a test.
func withBase(t *testing.T, srv *httptest.Server) {
	t.Helper()
	old := *base
	*base = srv.URL
	t.Cleanup(func() { *base = old })
}

func statusServer(t *testing.T, code int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	return srv
}

var getNode = op{"GET node", "GET", "/nodes/node0", ""}

// A server that rejects every request still answers quickly. Counting those
// answers as samples is how a run against a server holding the wrong key
// printed plausible latencies; they must be errors instead.
func TestWarmPhaseCountsNon2xxAsErrors(t *testing.T) {
	withBase(t, statusServer(t, http.StatusUnauthorized))

	p50, p95, qps1, errs := warmPhase(getNode, 50)
	if p50 != -1 || p95 != -1 || qps1 != -1 {
		t.Fatalf("warmPhase on an all-401 server = (%v, %v, %v), want all -1", p50, p95, qps1)
	}
	if errs != 50 {
		t.Fatalf("errors = %d, want 50", errs)
	}
}

func TestWarmPhaseMeasuresSuccesses(t *testing.T) {
	withBase(t, statusServer(t, http.StatusOK))

	p50, _, qps1, errs := warmPhase(getNode, 50)
	if p50 < 0 || qps1 <= 0 {
		t.Fatalf("warmPhase on a healthy server = p50 %v, qps1 %v; want measurements", p50, qps1)
	}
	if errs != 0 {
		t.Fatalf("errors = %d, want 0", errs)
	}
}

func TestTimeOneCountsNon2xxAsError(t *testing.T) {
	withBase(t, statusServer(t, http.StatusForbidden))

	if got := timeOne(getNode); got != -1 {
		t.Fatalf("timeOne on a 403 = %v, want -1", got)
	}
}

func TestQPSPhaseCountsErrors(t *testing.T) {
	withBase(t, statusServer(t, http.StatusUnauthorized))

	qps, errs := qpsPhase(getNode, 2, 50e6)
	if qps != 0 {
		t.Fatalf("qps on an all-401 server = %v, want 0", qps)
	}
	if errs == 0 {
		t.Fatal("errors = 0, want the rejected requests counted")
	}
}

func TestWriteResultRoundTrips(t *testing.T) {
	want := result{
		Label: "cinc-server-ng - SQLite",
		Base:  "http://127.0.0.1:8890/organizations/bench",
		Auth:  true,
		Conc:  10,
		Ops: []opResult{
			{Name: "GET node", ColdMS: 0.9, P50MS: 0.43, P95MS: 0.5, QPS1: 2268, QPSC: 6885},
			{Name: "PUT node", ColdMS: -1, P50MS: -1, P95MS: -1, QPS1: -1, QPSC: 0, Errors: 3000},
		},
	}
	path := filepath.Join(t.TempDir(), "r.json")
	if err := writeResult(path, want); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got result
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, want)
	}
}

func TestResultFailed(t *testing.T) {
	ok := result{Ops: []opResult{{Name: "GET node"}}}
	if ok.failed() {
		t.Fatal("a result with no errors reports failed")
	}
	bad := result{Ops: []opResult{{Name: "GET node"}, {Name: "PUT node", Errors: 1}}}
	if !bad.failed() {
		t.Fatal("a result with an erroring op does not report failed")
	}
}

// Seeding against a server that rejects the signature must not look like a
// successful seed followed by a benchmark of an empty organization.
func TestSeedReportsRejections(t *testing.T) {
	withBase(t, statusServer(t, http.StatusUnauthorized))

	created, failed := seed(5)
	if created != 0 || failed != 5 {
		t.Fatalf("seed on an all-401 server = (created %d, failed %d), want (0, 5)", created, failed)
	}
}

func TestSeedUpdatesExistingNodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	withBase(t, srv)

	created, failed := seed(3)
	if created != 0 || failed != 0 {
		t.Fatalf("seed over existing nodes = (created %d, failed %d), want (0, 0)", created, failed)
	}
}
