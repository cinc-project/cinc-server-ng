package server

import (
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// deadlineBody puts a request body's reads on the clock. Header reads are
// bounded by readHeaderTimeout, but net/http clears the connection's read
// deadline once the headers are in, so without this a client could declare a
// body and send it a byte at a time, or never, and hold the connection, its
// goroutine and the buffer read so far for as long as it liked; an API body is
// read before its signature is checked, so anyone could.
//
// The deadline is the connection's, so it also bounds net/http's discard of a
// body no handler read. It is cleared when the body reaches EOF: once the body
// is in, net/http watches the connection in the background, and a read
// deadline passing then would cancel a request still being handled.
type deadlineBody struct {
	io.ReadCloser
	rc *http.ResponseController
	// idle, when positive, makes the deadline rolling: each read may wait this
	// long for data. Otherwise the deadline set at the start stands.
	idle time.Duration
	done bool
}

// withBodyDeadline gives r's body a deadline: an absolute one, timeout from
// now, or when idle is true a rolling one that only a gap of timeout between
// reads trips. A request with no body, or a timeout of zero or less, is left
// alone.
func withBodyDeadline(w http.ResponseWriter, r *http.Request, timeout time.Duration, idle bool) {
	if timeout <= 0 || r.Body == nil || r.Body == http.NoBody {
		return
	}
	rc := http.NewResponseController(w)
	// A writer that cannot take a deadline (a test recorder, say) is left
	// unbounded rather than failed.
	if err := rc.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return
	}
	b := &deadlineBody{ReadCloser: r.Body, rc: rc}
	if idle {
		b.idle = timeout
	}
	r.Body = b
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	if b.idle > 0 && !b.done {
		_ = b.rc.SetReadDeadline(time.Now().Add(b.idle))
	}
	n, err := b.ReadCloser.Read(p)
	// Only a body read to its end clears the deadline; after any other error
	// the connection is not reused, and what net/http discards of it stays
	// bounded.
	if errors.Is(err, io.EOF) && !b.done {
		b.done = true
		_ = b.rc.SetReadDeadline(time.Time{})
	}
	return n, err
}

// limitListener caps the connections ln hands out at n: Accept waits while n
// are open, leaving any more in the kernel's listen backlog.
func limitListener(ln net.Listener, n int) net.Listener {
	return &limitedListener{Listener: ln, sem: make(chan struct{}, n), done: make(chan struct{})}
}

type limitedListener struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func (l *limitedListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitedConn{Conn: c, release: func() { <-l.sem }}, nil
}

func (l *limitedListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
