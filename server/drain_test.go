package server

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// Drain is what a load balancer needs before a server stops: the health check
// fails so no new traffic is routed here, while requests that still arrive
// (the LB has not noticed yet) are served rather than refused.
func TestDrainFailsHealthCheckButKeepsServing(t *testing.T) {
	srv := startServer(t, Options{})

	resp, err := http.Get(srv.URL() + "/_status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("baseline /_status = %d, want 200", resp.StatusCode)
	}

	srv.Drain()

	resp, err = http.Get(srv.URL() + "/_status")
	if err != nil {
		t.Fatal(err)
	}
	var status struct{ Status string }
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("draining /_status is not JSON: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || status.Status != "draining" {
		t.Fatalf("draining /_status = %d %q, want 503 \"draining\"", resp.StatusCode, status.Status)
	}

	resp, err = http.DefaultClient.Do(signed(t, srv, "GET", srv.URL()+"/organizations/acme/nodes", ""))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("API request while draining = %d, want 200", resp.StatusCode)
	}
	// Kept-alive connections would pin a client to this server past the drain;
	// closing each one after its response sends the next request through the
	// load balancer to a healthy peer.
	if !resp.Close {
		t.Fatal("response while draining did not close the connection")
	}
}
