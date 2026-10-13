package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// healthcheck probes a running server's /_status and returns an error unless it
// answers 200. It backs the container HEALTHCHECK: the distroless image has no
// shell or curl, so the binary checks itself.
func healthcheck(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("cinc-server-ng healthcheck", flag.ContinueOnError)
	fs.SetOutput(out)
	addr := fs.String("addr", "127.0.0.1:8889", "address of the server to probe (host:port)")
	timeout := fs.Duration("timeout", 3*time.Second, "give up after this long")
	useTLS := fs.Bool("tls", os.Getenv("CINC_SERVER_NG_TLS_CERT") != "", "probe over HTTPS (default on when CINC_SERVER_NG_TLS_CERT is set, as for a server started with --tls-cert); the certificate is not verified, since it names the public host rather than the address probed")
	if err := fs.Parse(args); err != nil {
		return err
	}

	host, port, err := net.SplitHostPort(*addr)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	// A wildcard listen address (the image serves on 0.0.0.0) is not dialable
	// everywhere; probe loopback instead.
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}

	client := &http.Client{Timeout: *timeout}
	scheme := "http"
	if *useTLS {
		scheme = "https"
		// A liveness probe sends nothing secret and trusts nothing it reads
		// beyond the status code, so an unverified handshake is enough.
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, //nolint:gosec // see above
		}}
	}
	resp, err := client.Get(scheme + "://" + net.JoinHostPort(host, port) + "/_status")
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: /_status returned %s", resp.Status)
	}
	return nil
}
