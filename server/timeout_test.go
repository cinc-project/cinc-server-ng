package server

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestSlowHeadersAreDisconnected pins the Slowloris defence: a client that
// opens a connection and never finishes its request headers is dropped once
// readHeaderTimeout elapses, instead of holding the connection forever.
func TestSlowHeadersAreDisconnected(t *testing.T) {
	old := readHeaderTimeout
	readHeaderTimeout = 200 * time.Millisecond
	t.Cleanup(func() { readHeaderTimeout = old })

	srv := startServer(t, Options{})
	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /_status HTTP/1.1\r\nHost: x\r\n"); err != nil {
		t.Fatal(err)
	}

	// Baseline: well inside the timeout, the server is still waiting on us.
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	var nerr net.Error
	if _, err := conn.Read(make([]byte, 1)); !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("connection closed before the header timeout: %v", err)
	}

	// Past the timeout the server gives up on the request.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("server did not close a connection with unfinished headers: %v", err)
	}
}

// TestNoWholeRequestTimeouts pins that only the header phase is bounded. A
// ReadTimeout or WriteTimeout caps the whole body, which would cut off large
// cookbook uploads and downloads through the file store on slow links.
func TestNoWholeRequestTimeouts(t *testing.T) {
	srv := startServer(t, Options{})
	if srv.httpSrv.ReadHeaderTimeout <= 0 {
		t.Errorf("ReadHeaderTimeout = %v, want > 0", srv.httpSrv.ReadHeaderTimeout)
	}
	if srv.httpSrv.ReadTimeout != 0 || srv.httpSrv.WriteTimeout != 0 {
		t.Errorf("ReadTimeout = %v, WriteTimeout = %v, want both 0", srv.httpSrv.ReadTimeout, srv.httpSrv.WriteTimeout)
	}
}
