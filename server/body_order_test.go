package server

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
)

// Real Chef Infra Server checks the authentication headers (presence, protocol
// version, clock skew) and the declared body size before it reads a request
// body, and reads at most max_request_size bytes of it. cinc-server-ng must
// not buffer a body, up to its cap, for a request that can be refused from its
// headers alone.

// countingBody is an endless request body that counts the bytes read from it.
type countingBody struct{ n int64 }

func (c *countingBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	c.n += int64(len(p))
	return len(p), nil
}

func (c *countingBody) Close() error { return nil }

// serveBody runs a request with a counting body through the server's full
// handler chain, declaring contentLength (-1 for a chunked body).
func serveBody(t *testing.T, srv *Server, req *http.Request, contentLength int64) (*httptest.ResponseRecorder, *countingBody) {
	t.Helper()
	body := &countingBody{}
	req.Body = body
	req.ContentLength = contentLength
	rec := httptest.NewRecorder()
	srv.handler.ServeHTTP(rec, req)
	return rec, body
}

// signedEmpty returns a request signed by the admin over an empty body, for
// tests whose body is swapped in afterwards: the refusal under test must come
// before the signature is ever checked against the body.
func signedEmpty(t *testing.T, srv *Server, method, url string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, url, nil)
	key, err := auth.ParsePrivateKey(srv.AdminKey())
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Ops-Server-API-Version", "1")
	if err := auth.SignRequest(req, srv.AdminName(), time.Now().UTC().Format(time.RFC3339), nil, key); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestRequestRefusedFromHeadersIsNotRead(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	const url = "/organizations/acme/nodes"

	cases := map[string]func() *http.Request{
		"no signature headers": func() *http.Request {
			return httptest.NewRequest("POST", url, nil)
		},
		"unknown actor": func() *http.Request {
			req := signedEmpty(t, srv, "POST", url)
			req.Header.Set("X-Ops-Userid", "nobody")
			return req
		},
		"clock skew": func() *http.Request {
			req := httptest.NewRequest("POST", url, nil)
			key, _ := auth.ParsePrivateKey(srv.AdminKey())
			old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
			if err := auth.SignRequest(req, srv.AdminName(), old, nil, key); err != nil {
				t.Fatal(err)
			}
			return req
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			rec, body := serveBody(t, srv, build(), 1000)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: %s", rec.Code, rec.Body)
			}
			if body.n != 0 {
				t.Fatalf("read %d body bytes of a request refused from its headers, want 0", body.n)
			}
		})
	}
}

// erchef's refusal (chef_wm_enforce, halted with 413 in malformed_request):
// the error is a string, not the usual list.
func TestDeclaredOversizeBodyIsRefusedUnread(t *testing.T) {
	for name, opts := range map[string]Options{
		"signed":  {Orgs: []string{"acme"}},
		"no auth": {Orgs: []string{"acme"}, DisableAuth: true},
	} {
		t.Run(name, func(t *testing.T) {
			srv := startServer(t, opts)
			req := signedEmpty(t, srv, "PUT", "/organizations/acme/nodes/n1")
			rec, body := serveBody(t, srv, req, 2000001)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413: %s", rec.Code, rec.Body)
			}
			if got, want := rec.Body.String(), `{"error":"JSON must be no more than 2000000 bytes."}`; got != want {
				t.Fatalf("body = %s, want %s", got, want)
			}
			if body.n != 0 {
				t.Fatalf("read %d bytes of a body declared over the cap, want 0", body.n)
			}
		})
	}
}

func TestChunkedOversizeBodyIsCutOffAtTheCap(t *testing.T) {
	const limit = 4096
	for name, opts := range map[string]Options{
		"signed":  {Orgs: []string{"acme"}, MaxBodyBytes: limit},
		"no auth": {Orgs: []string{"acme"}, MaxBodyBytes: limit, DisableAuth: true},
	} {
		t.Run(name, func(t *testing.T) {
			srv := startServer(t, opts)
			req := signedEmpty(t, srv, "POST", "/organizations/acme/nodes")
			rec, body := serveBody(t, srv, req, -1)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413: %s", rec.Code, rec.Body)
			}
			if got, want := rec.Body.String(), `{"error":"JSON must be no more than 4096 bytes."}`; got != want {
				t.Fatalf("body = %s, want %s", got, want)
			}
			// MaxBytesReader reads one buffer past the cap to notice it.
			if body.n > 2*limit {
				t.Fatalf("read %d bytes of an endless body with a %d-byte cap", body.n, limit)
			}
		})
	}
}

// A body of exactly the cap is allowed, as pedant's respects_maximum_payload_size
// checks against erchef.
func TestSignedBodyAtTheCapIsAccepted(t *testing.T) {
	const limit = 512
	srv := startServer(t, Options{Orgs: []string{"acme"}, MaxBodyBytes: limit})
	prefix, suffix := `{"name":"n1","normal":{"pad":"`, `"}}`
	body := prefix + strings.Repeat("a", limit-len(prefix)-len(suffix)) + suffix
	if len(body) != limit {
		t.Fatalf("test body is %d bytes, want %d", len(body), limit)
	}
	if code := statusOf(t, signed(t, srv, "POST", srv.URL()+"/organizations/acme/nodes", body)); code != http.StatusCreated {
		t.Fatalf("signed node at the cap = %d, want 201", code)
	}
	if code := statusOf(t, signed(t, srv, "PUT", srv.URL()+"/organizations/acme/nodes/n1", body+" ")); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("signed node one byte over the cap = %d, want 413", code)
	}
}

// Cookbook files go to the pre-signed file-store URL, not through signed JSON
// routes, and are not held to the JSON cap: Chef Infra Server's only limit on
// them is nginx's client_max_body_size, 250 MB.
func TestFileStoreUploadHasItsOwnCap(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, MaxBodyBytes: 512, MaxFileStoreBytes: 8192})

	content := strings.Repeat("x", 4096)
	sum := md5.Sum([]byte(content))
	checksum := hex.EncodeToString(sum[:])
	uploadURL := sandboxUploadURL(t, srv, checksum)
	if code, body := rawRequest(t, "PUT", uploadURL, content); code != http.StatusOK {
		t.Fatalf("file over the JSON cap, under the file cap = %d, want 200: %s", code, body)
	}

	req := httptest.NewRequest("PUT", uploadURL, nil)
	rec, body := serveBody(t, srv, req, 8193)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("file declared over the file cap = %d, want 413: %s", rec.Code, rec.Body)
	}
	if body.n != 0 {
		t.Fatalf("read %d bytes of a file declared over the cap, want 0", body.n)
	}

	rec, body = serveBody(t, srv, httptest.NewRequest("PUT", uploadURL, nil), -1)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked file over the file cap = %d, want 413: %s", rec.Code, rec.Body)
	}
	if body.n > 2*8192 {
		t.Fatalf("read %d bytes of an endless file with an 8192-byte cap", body.n)
	}
}

// A file-store request without a valid grant is refused before its body is read.
func TestUngrantedFileStoreUploadIsNotRead(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	req := httptest.NewRequest("PUT", "/organizations/acme/file_store/"+strings.Repeat("0", 32), nil)
	rec, body := serveBody(t, srv, req, 1000)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if body.n != 0 {
		t.Fatalf("read %d bytes of an ungranted upload, want 0", body.n)
	}
}

func TestBodyCapDefaultsMatchChefInfraServer(t *testing.T) {
	o := Options{}
	o.withDefaults()
	if o.MaxBodyBytes != 2000000 {
		t.Errorf("default MaxBodyBytes = %d, want 2000000 (opscode_erchef['max_request_size'])", o.MaxBodyBytes)
	}
	if o.MaxFileStoreBytes != 250<<20 {
		t.Errorf("default MaxFileStoreBytes = %d, want 250 MiB (nginx['client_max_body_size'])", o.MaxFileStoreBytes)
	}
}

var _ io.ReadCloser = (*countingBody)(nil)

// The unauthenticated system endpoints and /_stats take no body; one sent
// anyway is not read.
func TestBodylessEndpointsDoNotReadABody(t *testing.T) {
	for name, opts := range map[string]Options{
		"signed":  {Orgs: []string{"acme"}},
		"no auth": {Orgs: []string{"acme"}, DisableAuth: true},
	} {
		t.Run(name, func(t *testing.T) {
			srv := startServer(t, opts)
			for _, path := range []string{"/_status", "/_stats"} {
				rec, body := serveBody(t, srv, httptest.NewRequest("GET", path, nil), 1000)
				if body.n != 0 {
					t.Fatalf("GET %s read %d body bytes (status %d), want 0", path, body.n, rec.Code)
				}
			}
		})
	}
}

// A path whose file_store segment ends in an escaped slash is not the file
// store: it is not exempt from signing, and its body is held to the API cap,
// not the file store's, before any signature is checked. (The signature here
// covers an empty body, so it never verifies against the one sent.)
func TestEscapedFileStorePathGetsTheAPICap(t *testing.T) {
	const limit, fileLimit = 512, 1 << 20
	const url = "/organizations/acme/file_store%2Fx"
	cases := map[string]struct {
		opts  Options
		build func(srv *Server) *http.Request
	}{
		"signed": {
			Options{Orgs: []string{"acme"}, MaxBodyBytes: limit, MaxFileStoreBytes: fileLimit},
			func(srv *Server) *http.Request { return signedEmpty(t, srv, "PUT", url) },
		},
		"web": {
			Options{Orgs: []string{"acme"}, MaxBodyBytes: limit, MaxFileStoreBytes: fileLimit},
			func(srv *Server) *http.Request {
				req := signedEmpty(t, srv, "PUT", url)
				req.Header.Set("X-Ops-Request-Source", "web")
				return req
			},
		},
		"no auth": {
			Options{Orgs: []string{"acme"}, MaxBodyBytes: limit, MaxFileStoreBytes: fileLimit, DisableAuth: true},
			func(srv *Server) *http.Request { return httptest.NewRequest("PUT", url, nil) },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := startServer(t, tc.opts)
			want := `{"error":"JSON must be no more than 512 bytes."}`

			rec, body := serveBody(t, srv, tc.build(srv), limit+1)
			if rec.Code != http.StatusRequestEntityTooLarge || rec.Body.String() != want {
				t.Fatalf("declared over the API cap = %d %s, want 413 %s", rec.Code, rec.Body, want)
			}
			if body.n != 0 {
				t.Fatalf("read %d bytes of a body declared over the API cap, want 0", body.n)
			}

			rec, body = serveBody(t, srv, tc.build(srv), -1)
			if rec.Code != http.StatusRequestEntityTooLarge || rec.Body.String() != want {
				t.Fatalf("chunked over the API cap = %d %s, want 413 %s", rec.Code, rec.Body, want)
			}
			if body.n > 2*limit {
				t.Fatalf("read %d bytes of an endless body with a %d-byte API cap", body.n, limit)
			}
		})
	}
}

// A web-sourced request naming no actor is refused before its body is read,
// as a request signed by the actor itself is.
func TestWebRequestForUnknownActorIsNotRead(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	req := signedEmpty(t, srv, "POST", "/organizations/acme/nodes")
	req.Header.Set("X-Ops-Request-Source", "web")
	req.Header.Set("X-Ops-Userid", "nobody")
	rec, body := serveBody(t, srv, req, 1000)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", rec.Code, rec.Body)
	}
	if body.n != 0 {
		t.Fatalf("read %d body bytes of a web request for an unknown actor, want 0", body.n)
	}
}
