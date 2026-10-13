package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/server"
)

// writeCert writes a self-signed certificate named cn for 127.0.0.1 to
// dir/server.crt and dir/server.key, replacing any pair already there.
func writeCert(t *testing.T, dir, cn string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// servedCN is the common name of the certificate a fresh handshake sees.
func servedCN(t *testing.T, addr string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // inspecting the served certificate, not trusting it
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
}

func started(t *testing.T, opts server.Options) *server.Server {
	t.Helper()
	opts.DisableAuth = true
	srv, err := server.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	return srv
}

// serveAsync runs serveUntilSignal in the background and returns a channel
// that yields its result.
func serveAsync(srv *server.Server, sigs chan os.Signal, delay time.Duration, out io.Writer) <-chan error {
	done := make(chan error, 1)
	go func() { done <- serveUntilSignal(srv, sigs, delay, 5*time.Second, out) }()
	return done
}

func awaitReturn(t *testing.T, done <-chan error, within time.Duration) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveUntilSignal: %v", err)
		}
	case <-time.After(within):
		t.Fatalf("serveUntilSignal did not return within %v", within)
	}
}

// SIGHUP is how certbot deploy hooks and similar tooling announce a renewed
// certificate; the server must pick it up and keep running.
func TestSIGHUPReloadsCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCert(t, dir, "first")
	srv := started(t, server.Options{TLSCertFile: certFile, TLSKeyFile: keyFile})
	addr := strings.TrimPrefix(srv.URL(), "https://")
	sigs := make(chan os.Signal, 1)
	var out bytes.Buffer
	done := serveAsync(srv, sigs, 0, &out)

	writeCert(t, dir, "second")
	if got := servedCN(t, addr); got != "first" {
		t.Fatalf("certificate changed before SIGHUP: %q", got)
	}
	sigs <- syscall.SIGHUP
	deadline := time.Now().Add(5 * time.Second)
	for servedCN(t, addr) != "second" {
		if time.Now().After(deadline) {
			t.Fatal("SIGHUP did not reload the certificate")
		}
		time.Sleep(10 * time.Millisecond)
	}

	sigs <- syscall.SIGTERM
	awaitReturn(t, done, 5*time.Second)
}

// A SIGHUP on a plain-HTTP server has nothing to reload; it must not stop it.
func TestSIGHUPWithoutTLSKeepsServing(t *testing.T) {
	srv := started(t, server.Options{})
	sigs := make(chan os.Signal, 1)
	done := serveAsync(srv, sigs, 0, io.Discard)

	sigs <- syscall.SIGHUP
	select {
	case err := <-done:
		t.Fatalf("SIGHUP stopped a plain-HTTP server: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	sigs <- syscall.SIGTERM
	awaitReturn(t, done, 5*time.Second)
}

// During the shutdown delay the server drains: the health check fails while
// requests are still served, giving the load balancer time to stop routing.
func TestShutdownDelayDrainsBeforeStopping(t *testing.T) {
	srv := started(t, server.Options{})
	sigs := make(chan os.Signal, 1)
	done := serveAsync(srv, sigs, 300*time.Millisecond, io.Discard)

	sigs <- syscall.SIGTERM
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(srv.URL() + "/_status")
		if err != nil {
			t.Fatalf("server stopped before draining: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusServiceUnavailable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("/_status never reported draining")
		}
		time.Sleep(5 * time.Millisecond)
	}
	resp, err := http.Get(srv.URL() + "/organizations/acme/nodes")
	if err != nil {
		t.Fatalf("API request during drain: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("API request during drain = %d, want 200", resp.StatusCode)
	}
	awaitReturn(t, done, 5*time.Second)
	if _, err := http.Get(srv.URL() + "/_status"); err == nil {
		t.Fatal("server still serving after shutdown")
	}
}

// An operator who presses Ctrl-C twice wants out now, not after the drain.
func TestSecondSignalSkipsShutdownDelay(t *testing.T) {
	srv := started(t, server.Options{})
	sigs := make(chan os.Signal, 2)
	done := serveAsync(srv, sigs, time.Hour, io.Discard)

	sigs <- syscall.SIGTERM
	sigs <- os.Interrupt
	awaitReturn(t, done, 5*time.Second)
}

// Stop must not wait forever on a client that never finishes its request.
func TestShutdownTimeoutBoundsStop(t *testing.T) {
	srv := started(t, server.Options{})
	addr := strings.TrimPrefix(srv.URL(), "http://")
	// An upload that never finishes keeps one request in flight.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "PUT /organizations/acme/nodes/x HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\n{")
	time.Sleep(50 * time.Millisecond) // let the server start reading the body

	sigs := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() { done <- serveUntilSignal(srv, sigs, 0, 200*time.Millisecond, io.Discard) }()
	sigs <- syscall.SIGTERM
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
			t.Fatalf("serveUntilSignal = %v, want a deadline error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timeout did not bound Stop")
	}
	// Past the timeout the straggler is cut off, not left attached to a server
	// whose store is closed.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("stuck connection left open after the shutdown timeout: %v", err)
	}
}

func TestLoadBalancerFlags(t *testing.T) {
	f, err := parseFlags([]string{
		"--tls-cert", "/c.pem", "--tls-key", "/k.pem",
		"--external-url", "https://chef.example.com",
		"--shutdown-delay", "15s", "--shutdown-timeout", "45s",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if f.tlsCert != "/c.pem" || f.tlsKey != "/k.pem" || f.externalURL != "https://chef.example.com" ||
		f.shutdownDelay != 15*time.Second || f.shutdownTimeout != 45*time.Second {
		t.Fatalf("parsed %+v", f)
	}
}

// Container deployments configure through the environment, like --storage.
func TestLoadBalancerFlagsFromEnv(t *testing.T) {
	t.Setenv("CINC_SERVER_NG_TLS_CERT", "/c.pem")
	t.Setenv("CINC_SERVER_NG_TLS_KEY", "/k.pem")
	t.Setenv("CINC_SERVER_NG_EXTERNAL_URL", "https://chef.example.com")
	f, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if f.tlsCert != "/c.pem" || f.tlsKey != "/k.pem" || f.externalURL != "https://chef.example.com" {
		t.Fatalf("parsed %+v", f)
	}
}

// By default nothing changes for test pipelines: no drain delay, so a stop is
// immediate, and a bounded wait for in-flight requests.
func TestLoadBalancerFlagDefaults(t *testing.T) {
	f, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if f.shutdownDelay != 0 || f.shutdownTimeout != 30*time.Second {
		t.Fatalf("shutdown delay/timeout = %v/%v, want 0/30s", f.shutdownDelay, f.shutdownTimeout)
	}
}
