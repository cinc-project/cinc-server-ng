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

// statsRequest is a /_stats request carrying the server's stats credentials,
// the way a scraper or oc-chef-pedant reaches it: HTTP Basic, no signing.
func statsRequest(t *testing.T, srv *Server) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", srv.URL()+"/_stats", nil)
	if err != nil {
		t.Fatal(err)
	}
	user, password := srv.StatsCredentials()
	req.SetBasicAuth(user, password)
	return req
}

// gatherStats reads /_stats with the stats credentials and decodes the JSON
// families.
func gatherStats(t *testing.T, srv *Server) map[string]statFamily {
	t.Helper()
	resp, err := http.DefaultClient.Do(statsRequest(t, srv))
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
	reqs, ok := stats["cinc_server_ng_http_requests_total"]
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

	lat, ok := stats["cinc_server_ng_http_request_duration_seconds"]
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
	beforeReads := value(t, before["cinc_server_ng_store_reads_total"], "")
	beforeWrites := value(t, before["cinc_server_ng_store_writes_total"], "")

	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes", `{"name":"web01"}`)); code != 201 {
		t.Fatalf("create node = %d", code)
	}
	for range 3 {
		if code := statusOf(t, signed(t, srv, "GET", base+"/nodes/web01", "")); code != 200 {
			t.Fatalf("read node = %d", code)
		}
	}

	after := gatherStats(t, srv)
	if got := value(t, after["cinc_server_ng_store_reads_total"], ""); got <= beforeReads {
		t.Errorf("reads did not advance: %v then %v", beforeReads, got)
	}
	if got := value(t, after["cinc_server_ng_store_writes_total"], ""); got <= beforeWrites {
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

	searches := gatherStats(t, srv)["cinc_server_ng_search_queries_total"]
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

	req := statsRequest(t, srv)
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
		"# TYPE cinc_server_ng_http_requests_total counter",
		`cinc_server_ng_http_requests_total{outcome="2xx"}`,
		"# TYPE cinc_server_ng_http_request_duration_seconds histogram",
		"cinc_server_ng_http_request_duration_seconds_bucket{le=",
		"# TYPE cinc_server_ng_uptime_seconds gauge",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("text exposition missing %q:\n%s", want, body)
		}
	}
}

// The endpoint reports internal state, so it stays behind authentication. On
// Chef Infra Server that is HTTP Basic, enforced by nginx: the realm below is
// the one its nginx config uses.
func TestStatsRequiresBasicAuth(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, StatsPassword: "s3cret"})
	user, _ := srv.StatsCredentials()

	cases := map[string]func(*http.Request){
		"no credentials": func(*http.Request) {},
		"wrong password": func(r *http.Request) { r.SetBasicAuth(user, "nope") },
		"wrong user":     func(r *http.Request) { r.SetBasicAuth("someone", "s3cret") },
		"empty password": func(r *http.Request) { r.SetBasicAuth(user, "") },
		"not basic":      func(r *http.Request) { r.Header.Set("Authorization", "Bearer s3cret") },
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", srv.URL()+"/_stats", nil)
			set(req)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if got, want := resp.Header.Get("WWW-Authenticate"), `Basic realm="Chef Server Admin Stats"`; got != want {
				t.Errorf("WWW-Authenticate = %q, want %q", got, want)
			}
			var body struct {
				Error []string `json:"error"`
			}
			if err := json.Unmarshal(raw, &body); err != nil || len(body.Error) == 0 {
				t.Errorf("body = %s, want a JSON error", raw)
			}
		})
	}

	// Baseline: the right credentials do get in.
	req, _ := http.NewRequest("GET", srv.URL()+"/_stats", nil)
	req.SetBasicAuth(user, "s3cret")
	if code := statusOf(t, req); code != http.StatusOK {
		t.Fatalf("with stats credentials = %d, want 200", code)
	}
}

// Chef Infra Server guards /_stats with Basic auth only, so a Mixlib-signed
// request without it is turned away: a valid API key is not a stats
// credential.
func TestStatsRejectsSignedRequestWithoutBasicAuth(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	// Baseline: the admin signature is good on an ordinary route.
	if code := statusOf(t, signed(t, srv, "GET", srv.URL()+"/users", "")); code != http.StatusOK {
		t.Fatalf("signed /users = %d, want 200", code)
	}
	if code := statusOf(t, signed(t, srv, "GET", srv.URL()+"/_stats", "")); code != http.StatusUnauthorized {
		t.Fatalf("signed /_stats = %d, want 401", code)
	}
}

// The stats user defaults to Chef Infra Server's, and is configurable.
func TestStatsUserDefaultsAndIsConfigurable(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	if user, _ := srv.StatsCredentials(); user != "statsuser" {
		t.Errorf("default stats user = %q, want statsuser", user)
	}

	// Enforcing, as the binary does by default: there is no Chef actor on a
	// Basic-authenticated request, and authorization must not trip over that.
	srv = startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true, StatsUser: "prom", StatsPassword: "pw"})
	if user, password := srv.StatsCredentials(); user != "prom" || password != "pw" {
		t.Fatalf("credentials = %q/%q, want prom/pw", user, password)
	}
	req, _ := http.NewRequest("GET", srv.URL()+"/_stats", nil)
	req.SetBasicAuth("prom", "pw")
	if code := statusOf(t, req); code != http.StatusOK {
		t.Fatalf("custom credentials = %d, want 200", code)
	}
}

// With no password configured there is no safe fixed default, so each server
// generates its own (as Chef Infra Server generates stats_password at install)
// and exposes it for the operator to read.
func TestStatsPasswordGeneratedWhenUnset(t *testing.T) {
	a := startServer(t, Options{Orgs: []string{"acme"}})
	b := startServer(t, Options{Orgs: []string{"acme"}})
	_, pa := a.StatsCredentials()
	_, pb := b.StatsCredentials()
	if len(pa) < 32 {
		t.Errorf("generated password %q is too short", pa)
	}
	if pa == pb {
		t.Errorf("two servers generated the same stats password %q", pa)
	}
}

// With authentication disabled every route is open, and /_stats with them:
// requiring a credential there alone would protect nothing.
func TestStatsOpenWhenAuthDisabled(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, DisableAuth: true})
	req, _ := http.NewRequest("GET", srv.URL()+"/_stats", nil)
	if code := statusOf(t, req); code != http.StatusOK {
		t.Fatalf("no-auth /_stats = %d, want 200", code)
	}
}
