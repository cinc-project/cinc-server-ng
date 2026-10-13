package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCert is a self-signed certificate for 127.0.0.1 written to disk, as an
// operator would hand the server a cert and key pair.
type testCert struct {
	certFile, keyFile string
	leaf              *x509.Certificate
}

// writeTestCert writes a fresh self-signed certificate named cn into dir,
// replacing any certificate already there.
func writeTestCert(t testing.TB, dir, cn string) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	c := testCert{
		certFile: filepath.Join(dir, "server.crt"),
		keyFile:  filepath.Join(dir, "server.key"),
		leaf:     leaf,
	}
	if err := os.WriteFile(c.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// trustingClient is an HTTPS client that trusts exactly the given certificates
// and opens a fresh connection per request, so each request sees whatever
// certificate the server presents at that moment.
func trustingClient(certs ...*x509.Certificate) *http.Client {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		DisableKeepAlives: true,
	}}
}

// servedCert returns the leaf certificate a fresh TLS handshake with srv sees.
func servedCert(t *testing.T, srv *Server) *x509.Certificate {
	t.Helper()
	conn, err := tls.Dial("tcp", srv.listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // inspecting the served certificate, not trusting it
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0]
}

func TestTLSServesHTTPS(t *testing.T) {
	cert := writeTestCert(t, t.TempDir(), "a")
	srv := startServer(t, Options{TLSCertFile: cert.certFile, TLSKeyFile: cert.keyFile})

	if !strings.HasPrefix(srv.URL(), "https://") {
		t.Fatalf("URL() = %q, want https://", srv.URL())
	}
	resp, err := trustingClient(cert.leaf).Get(srv.URL() + "/_status")
	if err != nil {
		t.Fatalf("GET /_status over TLS: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/_status = %d, want 200", resp.StatusCode)
	}
}

// The URLs the server hands back must name the scheme the client used, or a
// chef-client is pointed at plain HTTP on a port that only speaks TLS.
func TestTLSResponseURLsAreHTTPS(t *testing.T) {
	cert := writeTestCert(t, t.TempDir(), "a")
	srv := startServer(t, Options{TLSCertFile: cert.certFile, TLSKeyFile: cert.keyFile})

	req := signed(t, srv, "POST", srv.URL()+"/organizations/acme/nodes", `{"name":"web1"}`)
	resp, err := trustingClient(cert.leaf).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct{ URI string }
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if want := srv.URL() + "/organizations/acme/nodes/web1"; body.URI != want {
		t.Fatalf("uri = %q, want %q", body.URI, want)
	}
}

func TestTLSRefusesPlainHTTP(t *testing.T) {
	cert := writeTestCert(t, t.TempDir(), "a")
	srv := startServer(t, Options{TLSCertFile: cert.certFile, TLSKeyFile: cert.keyFile})

	resp, err := http.Get("http://" + srv.listener.Addr().String() + "/_status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("plain HTTP to the TLS port = %d, want 400", resp.StatusCode)
	}
}

func TestTLSRejectsLegacyProtocolVersions(t *testing.T) {
	cert := writeTestCert(t, t.TempDir(), "a")
	srv := startServer(t, Options{TLSCertFile: cert.certFile, TLSKeyFile: cert.keyFile})

	pool := x509.NewCertPool()
	pool.AddCert(cert.leaf)
	// Baseline: TLS 1.2 is accepted.
	conn, err := tls.Dial("tcp", srv.listener.Addr().String(), &tls.Config{RootCAs: pool, MaxVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("TLS 1.2 handshake: %v", err)
	}
	conn.Close()
	if conn, err := tls.Dial("tcp", srv.listener.Addr().String(), &tls.Config{RootCAs: pool, MaxVersion: tls.VersionTLS11}); err == nil { //nolint:gosec // asserting the server refuses it
		conn.Close()
		t.Fatal("TLS 1.1 handshake succeeded, want refusal")
	}
}

func TestTLSNeedsBothCertAndKey(t *testing.T) {
	cert := writeTestCert(t, t.TempDir(), "a")
	for _, opts := range []Options{{TLSCertFile: cert.certFile}, {TLSKeyFile: cert.keyFile}} {
		if _, err := New(opts); err == nil {
			t.Errorf("New(%+v) succeeded, want an error naming the missing half", opts)
		}
	}
}

// A bad certificate is an operator error worth failing on at startup, not at
// the first client handshake.
func TestTLSUnreadableCertFailsAtNew(t *testing.T) {
	dir := t.TempDir()
	cert := writeTestCert(t, dir, "a")
	if err := os.WriteFile(cert.certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{TLSCertFile: cert.certFile, TLSKeyFile: cert.keyFile}); err == nil {
		t.Fatal("New with a garbage certificate succeeded")
	}
}

// Certificates are renewed in place (certbot, cert-manager); a reload must pick
// up the new pair without restarting, so in-memory state survives renewal.
func TestTLSReloadServesRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	first := writeTestCert(t, dir, "first")
	srv := startServer(t, Options{TLSCertFile: first.certFile, TLSKeyFile: first.keyFile})
	if got := servedCert(t, srv); !got.Equal(first.leaf) {
		t.Fatalf("baseline: served %q, want %q", got.Subject.CommonName, "first")
	}

	second := writeTestCert(t, dir, "second")
	if got := servedCert(t, srv); !got.Equal(first.leaf) {
		t.Fatalf("certificate changed before a reload: served %q", got.Subject.CommonName)
	}
	if err := srv.ReloadTLS(); err != nil {
		t.Fatalf("ReloadTLS: %v", err)
	}
	if got := servedCert(t, srv); !got.Equal(second.leaf) {
		t.Fatalf("after reload: served %q, want %q", got.Subject.CommonName, "second")
	}
}

// A renewal caught half-written must not take the server down: the reload
// fails and the previous certificate keeps serving.
func TestTLSFailedReloadKeepsServingPreviousCertificate(t *testing.T) {
	dir := t.TempDir()
	first := writeTestCert(t, dir, "first")
	srv := startServer(t, Options{TLSCertFile: first.certFile, TLSKeyFile: first.keyFile})

	if err := os.WriteFile(first.keyFile, []byte("truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := srv.ReloadTLS(); err == nil {
		t.Fatal("ReloadTLS with a garbage key succeeded")
	}
	if got := servedCert(t, srv); !got.Equal(first.leaf) {
		t.Fatalf("after a failed reload: served %q, want %q", got.Subject.CommonName, "first")
	}
	resp, err := trustingClient(first.leaf).Get(srv.URL() + "/_status")
	if err != nil {
		t.Fatalf("GET /_status after a failed reload: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func TestReloadTLSWithoutTLSIsAnError(t *testing.T) {
	srv := startServer(t, Options{})
	if err := srv.ReloadTLS(); err == nil {
		t.Fatal("ReloadTLS on a plain-HTTP server succeeded")
	}
}

// The startup pre-warm talks to the server's own listener; under TLS it has to
// complete handshakes too, or the first real client pays the cold path.
func TestTLSPrewarmReachesHandlers(t *testing.T) {
	cert := writeTestCert(t, t.TempDir(), "a")
	srv := startServer(t, Options{TLSCertFile: cert.certFile, TLSKeyFile: cert.keyFile})
	if n := srv.prewarm(); n == 0 {
		t.Fatal("pre-warm completed no requests over TLS")
	}
}

// HTTP/2 comes from net/http configuring ALPN when the TLS config leaves
// NextProtos unset. Setting NextProtos (say, to restrict protocols) would
// silently drop it, so pin that clients which offer h2 get it.
func TestTLSNegotiatesHTTP2(t *testing.T) {
	cert := writeTestCert(t, t.TempDir(), "a")
	srv := startServer(t, Options{TLSCertFile: cert.certFile, TLSKeyFile: cert.keyFile})

	pool := x509.NewCertPool()
	pool.AddCert(cert.leaf)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2: true,
	}}
	defer client.CloseIdleConnections()
	resp, err := client.Do(signed(t, srv, "GET", srv.URL()+"/organizations/acme/nodes", ""))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		t.Fatalf("signed GET = %d over %s, want 200 over HTTP/2", resp.StatusCode, resp.Proto)
	}
}
