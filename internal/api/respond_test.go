package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
