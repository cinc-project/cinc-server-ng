package server

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
)

// mixlibSigned builds a GET request for rawURL (sent on the wire exactly as
// written) whose Mixlib 1.3 signature covers signPath. The signing string is
// assembled here rather than by auth.SignRequest, so these tests pin the
// server against the protocol itself: Chef::HTTP::Authenticator signs
// `url.path`, which is the percent-escaped path as it goes on the wire.
func mixlibSigned(t *testing.T, srv *Server, rawURL, signPath string) *http.Request {
	t.Helper()
	key, err := auth.ParsePrivateKey(srv.AdminKey())
	if err != nil {
		t.Fatalf("parse admin key: %v", err)
	}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	emptyHash := sha256.Sum256(nil)
	contentHash := base64.StdEncoding.EncodeToString(emptyHash[:])
	signing := strings.Join([]string{
		"Method:GET",
		"Path:" + signPath,
		"X-Ops-Content-Hash:" + contentHash,
		"X-Ops-Sign:version=1.3",
		"X-Ops-Timestamp:" + ts,
		"X-Ops-UserId:" + srv.AdminName(),
		"X-Ops-Server-API-Version:1",
	}, "\n")
	sum := sha256.Sum256([]byte(signing))
	sig, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Ops-Server-API-Version", "1")
	req.Header.Set("X-Ops-Sign", "algorithm=sha256;version=1.3;")
	req.Header.Set("X-Ops-Userid", srv.AdminName())
	req.Header.Set("X-Ops-Timestamp", ts)
	req.Header.Set("X-Ops-Content-Hash", contentHash)
	encoded := base64.StdEncoding.EncodeToString(sig)
	for i, n := 0, 1; i < len(encoded); i, n = i+60, n+1 {
		req.Header.Set("X-Ops-Authorization-"+strconv.Itoa(n), encoded[i:min(i+60, len(encoded))])
	}
	return req
}

// TestSignatureCoversEscapedPath: a client signs the path it sends, percent
// escapes included, and erchef verifies against that raw path. A request for
// an escaped path must authenticate (and then 404 for the missing bag), not
// fail with a 401.
func TestSignatureCoversEscapedPath(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	cases := []string{
		"/organizations/acme/data/t%20bad%2095bd2c97",
		"/organizations/acme/data/bag/bad%20id",
		// A non-canonical escape is verified exactly as sent.
		"/organizations/acme/data/a%7eb",
		"/organizations/acme/cookbooks/no%2Fsuch",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			code := statusOf(t, mixlibSigned(t, srv, srv.URL()+p, p))
			if code != http.StatusNotFound {
				t.Fatalf("GET %s signed over the escaped path = %d, want 404", p, code)
			}
		})
	}
}

// TestSignatureDoesNotCoverOtherEncodings: the signature binds the raw path,
// so neither the decoded path nor a different encoding of the same decoded
// path verifies. erchef rejects both.
func TestSignatureDoesNotCoverOtherEncodings(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})

	// Baseline: the plain path, signed as sent, authenticates.
	if code := statusOf(t, mixlibSigned(t, srv, srv.URL()+"/organizations/acme/nodes", "/organizations/acme/nodes")); code != http.StatusOK {
		t.Fatalf("baseline signed GET = %d, want 200", code)
	}

	cases := []struct{ sent, signed string }{
		// Signed over the decoded form of an escaped path.
		{"/organizations/acme/data/t%20bad", "/organizations/acme/data/t bad"},
		// Signed over the unescaped path, sent with an escaped (but
		// equivalent once decoded) segment.
		{"/organizations/acme/n%6Fdes", "/organizations/acme/nodes"},
		// Signed over one escaping, sent with another.
		{"/organizations/acme/data/a%7Eb", "/organizations/acme/data/a%7eb"},
	}
	for _, c := range cases {
		t.Run(c.sent, func(t *testing.T) {
			code := statusOf(t, mixlibSigned(t, srv, srv.URL()+c.sent, c.signed))
			if code != http.StatusUnauthorized {
				t.Fatalf("GET %s signed over %q = %d, want 401", c.sent, c.signed, code)
			}
		})
	}
}

// TestSignRequestSignsEscapedPath: auth.SignRequest (used by the differential
// harness, fleetsim and loadtest) must sign the path the Go client sends.
func TestSignRequestSignsEscapedPath(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	code := statusOf(t, signed(t, srv, "GET", srv.URL()+"/organizations/acme/data/t%20bad", ""))
	if code != http.StatusNotFound {
		t.Fatalf("SignRequest for an escaped path = %d, want 404", code)
	}
}
