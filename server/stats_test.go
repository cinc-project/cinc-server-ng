package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The point of the endpoint is that the numbers move when the server does work,
// so the tests drive real traffic and then read the metrics back.

type statFamily struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Help    string `json:"help"`
	Metrics []struct {
		Labels []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"labels"`
		Value float64 `json:"value"`
	} `json:"metrics"`
	Count float64 `json:"count"`
}

// gatherStats reads /_stats as the admin and decodes the JSON families.
func gatherStats(t *testing.T, srv *Server) map[string]statFamily {
	t.Helper()
	resp, err := http.DefaultClient.Do(signed(t, srv, "GET", srv.URL()+"/_stats", ""))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/_stats = %d: %s", resp.StatusCode, raw)
	}
	var families []statFamily
	if err := json.Unmarshal(raw, &families); err != nil {
		t.Fatalf("decode /_stats: %v: %s", err, raw)
	}
	out := map[string]statFamily{}
	for _, f := range families {
		out[f.Name] = f
	}
	return out
}

// value returns a family's series for a label value, or its only series when
// label is empty.
func value(t *testing.T, f statFamily, label string) float64 {
	t.Helper()
	for _, m := range f.Metrics {
		if label == "" && len(m.Labels) == 0 {
			return m.Value
		}
		for _, l := range m.Labels {
			if l.Value == label {
				return m.Value
			}
		}
	}
	t.Fatalf("no series %q in %q", label, f.Name)
	return 0
}

func TestStatsCountsRequestsByOutcome(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"

	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes", `{"name":"web01"}`)); code != 201 {
		t.Fatalf("create node = %d", code)
	}
	if code := statusOf(t, signed(t, srv, "GET", base+"/nodes/ghost", "")); code != 404 {
		t.Fatalf("missing node = %d, want 404", code)
	}
	// An unsigned request is rejected before routing; it must still be counted.
	unsigned, _ := http.NewRequest("GET", base+"/nodes", nil)
	if code := statusOf(t, unsigned); code != http.StatusUnauthorized {
		t.Fatalf("unsigned = %d, want 401", code)
	}

	stats := gatherStats(t, srv)
	reqs, ok := stats["cinc_zero_http_requests_total"]
	if !ok {
		t.Fatal("no request counter in /_stats")
	}
	if got := value(t, reqs, "2xx"); got < 1 {
		t.Errorf("2xx = %v, want at least the created node", got)
	}
	if got := value(t, reqs, "4xx"); got < 1 {
		t.Errorf("4xx = %v, want at least the 404", got)
	}
	if got := value(t, reqs, "401"); got < 1 {
		t.Errorf("401 = %v, want the rejected unsigned request", got)
	}

	lat, ok := stats["cinc_zero_http_request_duration_seconds"]
	if !ok {
		t.Fatal("no latency histogram in /_stats")
	}
	if lat.Count < 3 {
		t.Errorf("latency count = %v, want every request observed", lat.Count)
	}
}

// Read amplification is the thing worth watching on a durable backend, so reads
// and writes are reported separately rather than as one "operations" number.
func TestStatsReportsStoreWork(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"

	before := gatherStats(t, srv)
	beforeReads := value(t, before["cinc_zero_store_reads_total"], "")
	beforeWrites := value(t, before["cinc_zero_store_writes_total"], "")

	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes", `{"name":"web01"}`)); code != 201 {
		t.Fatalf("create node = %d", code)
	}
	for range 3 {
		if code := statusOf(t, signed(t, srv, "GET", base+"/nodes/web01", "")); code != 200 {
			t.Fatalf("read node = %d", code)
		}
	}

	after := gatherStats(t, srv)
	if got := value(t, after["cinc_zero_store_reads_total"], ""); got <= beforeReads {
		t.Errorf("reads did not advance: %v then %v", beforeReads, got)
	}
	if got := value(t, after["cinc_zero_store_writes_total"], ""); got <= beforeWrites {
		t.Errorf("writes did not advance: %v then %v", beforeWrites, got)
	}
}

// A query the planner handles must be reported as indexed. If searches start
// falling back to scanning, that is the number that says so.
func TestStatsReportsSearchResolution(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	base := srv.URL() + "/organizations/acme"
	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes",
		`{"name":"web01","chef_environment":"production"}`)); code != 201 {
		t.Fatalf("create node = %d", code)
	}
	if code := statusOf(t, signed(t, srv, "GET",
		base+"/search/node?q=chef_environment:production", "")); code != 200 {
		t.Fatalf("search = %d", code)
	}

	searches := gatherStats(t, srv)["cinc_zero_search_queries_total"]
	if got := value(t, searches, "indexed"); got < 1 {
		t.Errorf("indexed searches = %v, want at least 1", got)
	}
	if got := value(t, searches, "scanned"); got != 0 {
		t.Errorf("scanned searches = %v, want 0 — a supported query should not fall back", got)
	}
}

// Scrapers speak the text exposition format; JSON stays the default so any
// existing consumer of this endpoint is unaffected.
func TestStatsServesPrometheusTextOnRequest(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})

	req := signed(t, srv, "GET", srv.URL()+"/_stats", "")
	req.Header.Set("Accept", "text/plain")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/_stats text = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	body := string(raw)
	for _, want := range []string{
		"# TYPE cinc_zero_http_requests_total counter",
		`cinc_zero_http_requests_total{outcome="2xx"}`,
		"# TYPE cinc_zero_http_request_duration_seconds histogram",
		"cinc_zero_http_request_duration_seconds_bucket{le=",
		"# TYPE cinc_zero_uptime_seconds gauge",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("text exposition missing %q:\n%s", want, body)
		}
	}
}

// The endpoint reports internal state, so it stays behind authentication.
func TestStatsRequiresAuthentication(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	req, _ := http.NewRequest("GET", srv.URL()+"/_stats", nil)
	if code := statusOf(t, req); code != http.StatusUnauthorized {
		t.Fatalf("unsigned /_stats = %d, want 401", code)
	}
}
