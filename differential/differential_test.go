package differential_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/differential"
	"github.com/cinc-project/cinc-server-ng/internal/auth"
	"github.com/cinc-project/cinc-server-ng/internal/chefjson"
	"github.com/cinc-project/cinc-server-ng/server"
)

// The harness is only worth anything if it is neither noisy nor vacuous: it
// must report nothing when two servers agree, and must report a real difference
// when they do not. Both are checked here against cinc-server-ng instances, so the
// mechanism is verified without needing a real Chef Infra Server — which only
// CI has.

// startTarget runs a cinc-server-ng server and returns it as a comparison target.
func startTarget(t *testing.T, name string, wrap func(http.Handler) http.Handler) *differential.Target {
	t.Helper()
	srv, err := server.New(server.Options{Orgs: []string{"acme"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Stop(ctx)
	})

	base := srv.URL()
	if wrap != nil {
		// Front the server with a proxy that can perturb responses, so a
		// deliberate difference can be introduced without touching the server.
		proxied := httptest.NewServer(wrap(passthrough(t, srv.URL())))
		t.Cleanup(proxied.Close)
		base = proxied.URL
	}

	key, err := auth.ParsePrivateKey(srv.AdminKey())
	if err != nil {
		t.Fatal(err)
	}
	return &differential.Target{
		Name:    name,
		BaseURL: base + "/organizations/acme",
		User:    srv.AdminName(),
		Key:     key,
	}
}

// passthrough forwards a request to the real server unchanged, preserving the
// signed headers.
func passthrough(t *testing.T, upstream string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequest(r.Method, upstream+r.URL.RequestURI(), r.Body)
		if err != nil {
			t.Errorf("proxy: %v", err)
			return
		}
		req.Header = r.Header.Clone()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("proxy: %v", err)
			return
		}
		defer resp.Body.Close()
		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if _, err := copyBody(w, resp.Body); err != nil {
			t.Errorf("proxy copy: %v", err)
		}
	})
}

func copyBody(w http.ResponseWriter, r interface{ Read([]byte) (int, error) }) (int64, error) {
	buf := make([]byte, 32*1024)
	var n int64
	for {
		c, err := r.Read(buf)
		if c > 0 {
			written, werr := w.Write(buf[:c])
			n += int64(written)
			if werr != nil {
				return n, werr
			}
		}
		if err != nil {
			return n, nil
		}
	}
}

// Two identical servers must produce no unexplained differences. This is what
// proves normalization is not manufacturing false positives: the two disagree
// on host, on every generated identifier, and on every generated key, and all
// of that has to normalize away without erasing anything real.
func TestIdenticalServersAgree(t *testing.T) {
	reference := startTarget(t, "reference", nil)
	candidate := startTarget(t, "candidate", nil)

	diffs, err := differential.Run(context.Background(), differential.Script("pivotal"),
		reference, candidate, differential.AcceptedDifferences())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	_, unknown := differential.Split(diffs)
	if len(unknown) != 0 {
		var sb strings.Builder
		for _, d := range unknown {
			sb.WriteString("\n" + d.String())
		}
		t.Fatalf("%d unexplained differences between two identical servers:%s", len(unknown), sb.String())
	}
}

// ...and the harness must actually catch a difference, or a green run means
// nothing. A proxy rewrites one field of one response; that must be reported.
func TestDifferenceInBodyIsDetected(t *testing.T) {
	reference := startTarget(t, "reference", nil)
	candidate := startTarget(t, "candidate", func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, "/nodes/diff-node") || r.Method != http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			var doc map[string]any
			if json.Unmarshal(rec.Body.Bytes(), &doc) == nil {
				doc["chef_environment"] = "tampered"
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(rec.Code)
			_ = json.NewEncoder(w).Encode(doc)
		})
	})

	diffs, err := differential.Run(context.Background(), differential.Script("pivotal"),
		reference, candidate, differential.AcceptedDifferences())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	_, unknown := differential.Split(diffs)
	var found bool
	for _, d := range unknown {
		if d.Field == "chef_environment" && d.Candidate == "tampered" {
			found = true
		}
	}
	if !found {
		t.Fatalf("tampered field was not reported; the harness would pass a real regression.\ngot: %v", unknown)
	}
}

// A response that holds the same values in a different member order is a
// different response to a client, and must be reported as one: decoding into
// Go maps used to make this, a float written as an integer, and an integer
// rounded past 2^53 all invisible.
func TestDifferenceInMemberOrderIsDetected(t *testing.T) {
	reference := startTarget(t, "reference", nil)
	candidate := startTarget(t, "candidate", func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasSuffix(r.URL.Path, "/nodes/diff-node") || r.Method != http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			body := rec.Body.Bytes()
			if tree, err := chefjson.Parse(body); err == nil {
				if obj, ok := tree.(*chefjson.Object); ok {
					slices.Reverse(obj.Members)
					body = chefjson.Marshal(obj)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(rec.Code)
			_, _ = w.Write(body)
		})
	})

	diffs, err := differential.Run(context.Background(), differential.Script("pivotal"),
		reference, candidate, differential.AcceptedDifferences())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	_, unknown := differential.Split(diffs)
	var found bool
	for _, d := range unknown {
		if d.Step == "node read" && d.Field == "(body){members}" {
			found = true
		}
	}
	if !found {
		t.Fatalf("reordered members were not reported.\ngot: %v", unknown)
	}
}

// A status-code difference must be caught too, since that is what clients
// branch on.
func TestDifferenceInStatusIsDetected(t *testing.T) {
	reference := startTarget(t, "reference", nil)
	candidate := startTarget(t, "candidate", func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/nodes/diff-absent") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusGone) // real server says 404
				_, _ = w.Write([]byte(`{"error":["gone"]}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	diffs, err := differential.Run(context.Background(), differential.Script("pivotal"),
		reference, candidate, differential.AcceptedDifferences())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	_, unknown := differential.Split(diffs)
	for _, d := range unknown {
		if d.Step == "node missing" && d.Field == "status" {
			return
		}
	}
	t.Fatalf("status difference was not reported.\ngot: %v", unknown)
}

// An accepted difference is reported as known rather than failing the run, and
// carries the reason.
func TestAcceptedDifferenceIsExplained(t *testing.T) {
	reference := startTarget(t, "reference", nil)
	candidate := startTarget(t, "candidate", func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/nodes/diff-absent") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusGone)
				_, _ = w.Write([]byte(`{"error":["gone"]}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	allow := append(differential.AcceptedDifferences(), differential.Accepted{
		Step: "node missing", Field: "*", Reason: "deliberate difference, for this test",
	})
	diffs, err := differential.Run(context.Background(), differential.Script("pivotal"),
		reference, candidate, allow)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	known, unknown := differential.Split(diffs)
	for _, d := range unknown {
		if d.Step == "node missing" {
			t.Fatalf("accepted difference still failed the run: %v", d)
		}
	}
	var explained bool
	for _, d := range known {
		if d.Step == "node missing" && d.Reason != "" {
			explained = true
		}
	}
	if !explained {
		t.Fatal("accepted difference was not reported as known")
	}
}

// A real Chef Infra Server indexes asynchronously, so a search issued right
// after a write can miss it there. A step marked Eventually re-asks the
// reference until it settles; a candidate that disagrees with the settled
// answer is still reported.
func TestEventuallyConsistentStepWaitsForTheReference(t *testing.T) {
	var stale atomic.Int32
	stale.Store(2)
	lagging := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/search/") && stale.Add(-1) >= 0 {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"total":0,"start":0,"rows":[]}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	reference := startTarget(t, "reference", lagging)
	candidate := startTarget(t, "candidate", nil)
	steps := []differential.Step{
		{Name: "node create", Method: "POST", Path: "/nodes", Body: `{"name":"lag-node"}`},
		{Name: "search", Method: "GET", Path: "/search/node?q=name:lag-node", Eventually: true},
	}
	// Only the search step is under test; behind a proxy, the reference's
	// self-URLs differ from its address, which is not what this is about.
	searchDiffs := func(diffs []differential.Difference) (out []differential.Difference) {
		for _, d := range diffs {
			if d.Step == "search" {
				out = append(out, d)
			}
		}
		return out
	}
	diffs, err := differential.Run(context.Background(), steps, reference, candidate, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := searchDiffs(diffs); len(got) != 0 {
		t.Errorf("a lagging reference was reported as a difference: %v", got)
	}

	// Without the mark, the same lag is a difference: the retry is what hides it.
	stale.Store(2)
	steps[0].Body = `{"name":"lag-node-2"}`
	steps[1] = differential.Step{Name: "search", Method: "GET", Path: "/search/node?q=name:lag-node-2"}
	if diffs, _ := differential.Run(context.Background(), steps, reference, candidate, nil); len(searchDiffs(diffs)) == 0 {
		t.Error("an unmarked step did not report the lagging reference")
	}
}
