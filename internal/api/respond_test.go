package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// X-Forwarded-Proto is set by a reverse proxy, but on a direct connection it
// arrives from the client — and it decides the scheme of every URL the server
// hands back, including the pre-signed cookbook file-store URLs a chef-client
// then fetches. Only a scheme this server can actually be reached on is honored.
func TestRequestBaseURLForwardedProto(t *testing.T) {
	cases := []struct {
		name, header, want string
	}{
		{"absent", "", "http://example.test"},
		{"https", "https", "https://example.test"},
		{"http", "http", "http://example.test"},
		{"mixed case", "HTTPS", "https://example.test"},
		{"padded", "  https  ", "https://example.test"},
		// A chained proxy appends; the first entry is the original client's.
		{"chained", "https, http", "https://example.test"},
		// Anything else is not a scheme this server serves, so it is ignored
		// rather than pasted into a URL handed to a client.
		{"javascript", "javascript:alert(1)", "http://example.test"},
		{"crafted", "https://evil.example", "http://example.test"},
		{"empty element", ",", "http://example.test"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example.test/organizations/acme/nodes", nil)
			if c.header != "" {
				r.Header.Set("X-Forwarded-Proto", c.header)
			}
			if got := requestBaseURL(r); got != c.want {
				t.Errorf("requestBaseURL = %q, want %q", got, c.want)
			}
		})
	}
}

// Behind a load balancer that rewrites Host (or terminates TLS without saying
// so), the request alone cannot tell the server its public address. A
// configured external URL, erchef's base_resource_url, wins over both the Host
// header and X-Forwarded-Proto for every URL the server hands back.
func TestExternalURLOverridesRequestBase(t *testing.T) {
	st := store.New()
	if _, err := st.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(st, WithExternalURL("https://chef.example.com")).Handler())
	t.Cleanup(srv.Close)

	req, err := http.NewRequest("POST", srv.URL+"/organizations/acme/nodes", strings.NewReader(`{"name":"web1"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "10.0.0.5:8889"
	req.Header.Set("X-Forwarded-Proto", "http")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct{ URI string }
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if want := "https://chef.example.com/organizations/acme/nodes/web1"; body.URI != want {
		t.Fatalf("uri = %q, want %q", body.URI, want)
	}

	// Baseline: without the option the same request reports the Host it came in on.
	r := httptest.NewRequest("GET", "http://10.0.0.5:8889/", nil)
	if got := requestBaseURL(r); got != "http://10.0.0.5:8889" {
		t.Fatalf("baseline requestBaseURL = %q", got)
	}
}
