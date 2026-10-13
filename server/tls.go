package server

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"sync/atomic"
)

// certLoader serves the certificate and key pair read from disk, and swaps in a
// renewed pair on reload without dropping the listener. Real Chef Infra Server
// leaves TLS to its bundled nginx; serving it here keeps the single binary
// deployable without a proxy in front.
type certLoader struct {
	certFile, keyFile string
	current           atomic.Pointer[tls.Certificate]
}

// newCertLoader reads the pair once, so a bad certificate fails at startup
// instead of at the first client's handshake.
func newCertLoader(certFile, keyFile string) (*certLoader, error) {
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("TLS needs both a certificate and a key (Options.TLSCertFile and Options.TLSKeyFile / --tls-cert and --tls-key)")
	}
	l := &certLoader{certFile: certFile, keyFile: keyFile}
	if err := l.reload(); err != nil {
		return nil, err
	}
	return l, nil
}

// reload re-reads the pair. On failure the previous certificate stays in
// service: a renewal caught half-written must not take the server down.
func (l *certLoader) reload() error {
	cert, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate %q and key %q: %w", l.certFile, l.keyFile, err)
	}
	l.current.Store(&cert)
	return nil
}

// config is the listener's TLS configuration. The certificate is looked up per
// handshake, so a reload applies to every connection opened after it.
func (l *certLoader) config() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return l.current.Load(), nil
		},
	}
}

// selfClientConfig is for the server's own requests to its listener (the
// startup pre-warm). The listener address rarely matches a name on the
// certificate, so instead of hostname verification it accepts exactly the leaf
// the server is serving.
func (l *certLoader) selfClientConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection pins the server's own certificate instead
		VerifyConnection: func(cs tls.ConnectionState) error {
			cur := l.current.Load()
			if len(cs.PeerCertificates) == 0 || len(cur.Certificate) == 0 ||
				!bytes.Equal(cs.PeerCertificates[0].Raw, cur.Certificate[0]) {
				return errors.New("pre-warm reached a listener not serving this server's certificate")
			}
			return nil
		},
	}
}

// ReloadTLS re-reads the certificate and key files, so a renewed certificate
// takes effect without a restart (and, on the memory backend, without losing
// state). Connections opened after it see the new certificate. If the files
// cannot be loaded the server keeps serving the previous certificate and the
// error is returned. It is an error on a server not configured for TLS.
func (s *Server) ReloadTLS() error {
	if s.certs == nil {
		return errors.New("server is not serving TLS")
	}
	return s.certs.reload()
}
