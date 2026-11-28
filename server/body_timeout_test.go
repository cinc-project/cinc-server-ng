package server

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// sendHead writes req's request line and headers to conn, declaring a body of
// length bytes, and none of the body.
func sendHead(t *testing.T, conn net.Conn, req *http.Request, length int) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n", req.Method, req.URL.RequestURI(), req.URL.Host, length)
	for name, vals := range req.Header {
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", name, v)
		}
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		t.Fatal(err)
	}
}

// trickle writes body to conn one byte per interval until it is done, the
// connection fails, or stop closes.
func trickle(conn net.Conn, body string, interval time.Duration, stop <-chan struct{}) {
	for i := range len(body) {
		select {
		case <-stop:
			return
		case <-time.After(interval):
		}
		if _, err := io.WriteString(conn, body[i:i+1]); err != nil {
			return
		}
	}
}

// stillOpen reports whether the server is still waiting on conn: a short read
// times out rather than seeing a response or the connection closing.
func stillOpen(conn net.Conn, wait time.Duration) bool {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	_, err := conn.Read(make([]byte, 1))
	var nerr net.Error
	return errors.As(err, &nerr) && nerr.Timeout()
}

// serverHangsUp reports whether the server ends the connection within wait.
func serverHangsUp(conn net.Conn, wait time.Duration) bool {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	_, err := io.ReadAll(conn)
	var nerr net.Error
	return !errors.As(err, &nerr) || !nerr.Timeout()
}

// An API body is read before its signature is checked, so a client that
// declares one and then trickles it must not hold the connection (and the
// buffer read so far) for longer than BodyTimeout, however steadily it keeps
// sending.
func TestSlowAPIBodyIsDisconnected(t *testing.T) {
	srv := startServer(t, Options{BodyTimeout: 300 * time.Millisecond})
	body := `{"name":"slow","padding":"` + strings.Repeat("a", 200) + `"}`
	req := signed(t, srv, "POST", srv.URL()+"/organizations/acme/nodes", body)

	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendHead(t, conn, req, len(body))
	stop := make(chan struct{})
	defer close(stop)
	// A byte every 20ms: never idle for long, but the whole body would take
	// four seconds.
	go trickle(conn, body, 20*time.Millisecond, stop)

	// Baseline: well inside the timeout, the server is still reading.
	if !stillOpen(conn, 100*time.Millisecond) {
		t.Fatal("server gave up on the body before BodyTimeout")
	}
	if !serverHangsUp(conn, 3*time.Second) {
		t.Fatal("server kept reading a trickled API body past BodyTimeout")
	}
}

// A body is bounded even when no layer reads it: one sent to /_status, which
// takes none, is discarded by net/http after the response, and that discard
// must not wait on the client forever either.
func TestUnreadBodyDiscardIsBounded(t *testing.T) {
	srv := startServer(t, Options{BodyTimeout: 300 * time.Millisecond})
	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req, _ := http.NewRequest("POST", srv.URL()+"/organizations/acme/nodes", nil)
	// Unsigned: refused from its headers, so the body is never read.
	sendHead(t, conn, req, 100000)
	if _, err := io.WriteString(conn, "{"); err != nil {
		t.Fatal(err)
	}
	if !serverHangsUp(conn, 3*time.Second) {
		t.Fatal("server waited forever to discard an unread body")
	}
}

// A file-store upload may be large and slow, so it has no overall deadline:
// it is cut off only when it stops sending for BodyTimeout.
func TestSlowFileStoreUploadCompletesWhileDataFlows(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, BodyTimeout: 300 * time.Millisecond})
	content := strings.Repeat("x", 40)
	checksum := md5hex(content)
	upload := sandboxUploadURL(t, srv, checksum)
	u, err := url.Parse(upload)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("PUT", srv.URL()+u.RequestURI(), nil)

	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendHead(t, conn, req, len(content))
	start := time.Now()
	// 40 bytes at one per 25ms is a second in all, past BodyTimeout, but never
	// idle for long.
	trickle(conn, content, 25*time.Millisecond, nil)
	if time.Since(start) < 600*time.Millisecond {
		t.Fatal("upload finished too quickly to exercise the timeout")
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Fatalf("slow but steady upload = %d, want success", resp.StatusCode)
	}
}

func TestStalledFileStoreUploadIsDisconnected(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, BodyTimeout: 300 * time.Millisecond})
	checksum := md5hex("stalled")
	u, err := url.Parse(sandboxUploadURL(t, srv, checksum))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("PUT", srv.URL()+u.RequestURI(), nil)
	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendHead(t, conn, req, len("stalled"))
	if _, err := io.WriteString(conn, "st"); err != nil {
		t.Fatal(err)
	}
	if !stillOpen(conn, 100*time.Millisecond) {
		t.Fatal("server gave up on the upload before BodyTimeout")
	}
	if !serverHangsUp(conn, 3*time.Second) {
		t.Fatal("server kept waiting on a stalled upload past BodyTimeout")
	}
}

// Once a body has arrived, the handler is not on the clock: a keep-alive
// connection that sent a body is still usable well after BodyTimeout.
func TestBodyTimeoutEndsWithTheBody(t *testing.T) {
	srv := startServer(t, Options{BodyTimeout: 200 * time.Millisecond})
	client := &http.Client{Transport: &http.Transport{MaxIdleConns: 1, MaxConnsPerHost: 1}}
	for i, name := range []string{"one", "two"} {
		resp, err := client.Do(signed(t, srv, "POST", srv.URL()+"/organizations/acme/nodes", `{"name":"`+name+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("request %d = %d, want 201", i, resp.StatusCode)
		}
		time.Sleep(400 * time.Millisecond)
	}
}

func TestBodyTimeoutDefault(t *testing.T) {
	o := Options{}
	o.withDefaults()
	if o.BodyTimeout != DefaultBodyTimeout || DefaultBodyTimeout < time.Minute {
		t.Fatalf("default BodyTimeout = %v (DefaultBodyTimeout %v), want a generous positive default", o.BodyTimeout, DefaultBodyTimeout)
	}
}

// A negative BodyTimeout turns the deadline off.
func TestBodyTimeoutNegativeDisables(t *testing.T) {
	srv := startServer(t, Options{BodyTimeout: -1})
	body := `{"name":"slow"}`
	req := signed(t, srv, "POST", srv.URL()+"/organizations/acme/nodes", body)
	conn, err := net.Dial("tcp", srv.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sendHead(t, conn, req, len(body))
	if !stillOpen(conn, 300*time.Millisecond) {
		t.Fatal("server gave up on a body with the timeout disabled")
	}
}

// MaxConnections caps how many connections the server holds at once; one past
// it waits to be accepted until another closes.
func TestMaxConnections(t *testing.T) {
	srv := startServer(t, Options{MaxConnections: 1})
	addr := srv.listener.Addr().String()
	status := "GET /_status HTTP/1.1\r\nHost: x\r\n\r\n"

	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(first, status); err != nil {
		t.Fatal(err)
	}
	_ = first.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(first), nil)
	if err != nil {
		t.Fatalf("first connection: %v", err)
	}
	resp.Body.Close()

	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := io.WriteString(second, status); err != nil {
		t.Fatal(err)
	}
	if !stillOpen(second, 200*time.Millisecond) {
		t.Fatal("a connection past MaxConnections was served")
	}
	first.Close()
	_ = second.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err = http.ReadResponse(bufio.NewReader(second), nil)
	if err != nil {
		t.Fatalf("second connection after the first closed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second connection = %d, want 200", resp.StatusCode)
	}
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
