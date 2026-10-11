package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// statusServer serves /_status with the given code and returns its host:port.
func statusServer(t *testing.T, code int) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_status" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(ts.Close)
	return strings.TrimPrefix(ts.URL, "http://")
}

// TestHealthcheckHealthy: the container HEALTHCHECK runs this subcommand, so a
// serving /_status must exit cleanly.
func TestHealthcheckHealthy(t *testing.T) {
	addr := statusServer(t, http.StatusOK)
	if err := run([]string{"healthcheck", "--addr", addr}, &bytes.Buffer{}); err != nil {
		t.Fatalf("healthy server reported unhealthy: %v", err)
	}
}

func TestHealthcheckUnhealthyStatus(t *testing.T) {
	addr := statusServer(t, http.StatusServiceUnavailable)
	if err := run([]string{"healthcheck", "--addr", addr}, &bytes.Buffer{}); err == nil {
		t.Fatal("503 from /_status reported healthy")
	}
}

func TestHealthcheckUnreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if err := run([]string{"healthcheck", "--addr", addr}, &bytes.Buffer{}); err == nil {
		t.Fatal("nothing listening reported healthy")
	}
}

// TestHealthcheckWildcardAddr: the image serves on --addr 0.0.0.0:8889, which
// is a listen address, not one to dial; the check must probe loopback instead.
func TestHealthcheckWildcardAddr(t *testing.T) {
	addr := statusServer(t, http.StatusOK)
	_, port, _ := net.SplitHostPort(addr)
	for _, host := range []string{"0.0.0.0", "", "::"} {
		if err := run([]string{"healthcheck", "--addr", net.JoinHostPort(host, port)}, &bytes.Buffer{}); err != nil {
			t.Errorf("host %q: %v", host, err)
		}
	}
}
