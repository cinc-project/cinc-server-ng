package differential_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tas50/cinc-server-ng/differential"
	"github.com/tas50/cinc-server-ng/internal/auth"
	"github.com/tas50/cinc-server-ng/server"
)

// The harness is only worth anything if it is neither noisy nor vacuous: it
// must report nothing when two servers agree, and must report a real difference
// when they do not. Both are checked here against cinc-zero instances, so the
// mechanism is verified without needing a real Chef Infra Server — which only
// CI has.

// startTarget runs a cinc-zero server and returns it as a comparison target.
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
