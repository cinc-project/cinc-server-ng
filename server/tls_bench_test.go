package server

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
)

// What serving TLS natively costs, against the same server over plain HTTP.
// Each benchmark runs a signed GET of one node through the whole stack
// (signature verification included), so the TLS share is measured against a
// real request rather than an empty handler.
//
//   - Reuse is a kept-alive connection, as chef-client holds one for a run:
//     the steady-state cost of record encryption.
//   - NewConn opens a connection per request: the full handshake every time,
//     the worst case (a client or load balancer that never reuses).
//
// The request is signed once outside the timer and replayed; signing is the
// node's cost, not the server's.

func benchTransport(b *testing.B, useTLS, reuse bool) {
	opts := Options{}
	var pool *x509.CertPool
	if useTLS {
		cert := writeTestCert(b, b.TempDir(), "bench")
		opts.TLSCertFile, opts.TLSKeyFile = cert.certFile, cert.keyFile
		pool = x509.NewCertPool()
		pool.AddCert(cert.leaf)
	}
	srv, err := New(opts)
	if err != nil {
		b.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { srv.Stop(b.Context()) })

	url := srv.URL() + "/organizations/acme/nodes/web1"
	key, err := auth.ParsePrivateKey(srv.AdminKey())
	if err != nil {
		b.Fatal(err)
	}
	sign := func(method, target, body string) http.Header {
		req, _ := http.NewRequest(method, target, nil)
		req.Header.Set("X-Ops-Server-API-Version", "1")
		if err := auth.SignRequest(req, srv.AdminName(), time.Now().UTC().Format(time.RFC3339), []byte(body), key); err != nil {
			b.Fatal(err)
		}
		return req.Header
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool},
		DisableKeepAlives:   !reuse,
		MaxIdleConnsPerHost: 64,
	}}
	b.Cleanup(client.CloseIdleConnections)

	create := srv.URL() + "/organizations/acme/nodes"
	body := `{"name":"web1","chef_type":"node","json_class":"Chef::Node","run_list":["recipe[base]"]}`
	seed, _ := http.NewRequest("POST", create, strings.NewReader(body))
	seed.Header = sign("POST", create, body)
	seed.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(seed)
	if err != nil {
		b.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b.Fatalf("seed POST = %d", resp.StatusCode)
	}

	hdr := sign("GET", url, "")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("GET", url, nil)
			req.Header = hdr.Clone()
			resp, err := client.Do(req)
			if err != nil {
				b.Error(err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b.Errorf("GET = %d", resp.StatusCode)
				return
			}
		}
	})
}

func BenchmarkTransportHTTPReuse(b *testing.B)    { benchTransport(b, false, true) }
func BenchmarkTransportHTTPSReuse(b *testing.B)   { benchTransport(b, true, true) }
func BenchmarkTransportHTTPNewConn(b *testing.B)  { benchTransport(b, false, false) }
func BenchmarkTransportHTTPSNewConn(b *testing.B) { benchTransport(b, true, false) }
