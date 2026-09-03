package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/server"
)

func TestRunDrivesConvergingNotStuck(t *testing.T) {
	srv, err := server.New(server.Options{Orgs: []string{"acme"}, DisableAuth: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}

	base := srv.URL() + "/organizations/acme"
	c, _ := newClient(base, "", "", 5*time.Second)

	// Close the client's keep-alive connections before shutting the in-process
	// server down, and bound the shutdown: graceful Stop otherwise waits for the
	// lingering idle sockets to drain, adding seconds to the test. (In real use
	// fleetsim is only the client and never stops the server.)
	defer func() {
		c.http.CloseIdleConnections()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Stop(sctx)
	}()

	const N = 10
	names := make([]string, N)
	for i := range N {
		names[i] = fmt.Sprintf("node%02d", i)
		body := fmt.Sprintf(`{"name":%q,"chef_environment":"_default","automatic":{"ohai_time":1000.0}}`, names[i])
		if _, status, err := c.do(context.Background(), "POST", "/nodes", []byte(body)); err != nil || status != http.StatusCreated {
			t.Fatalf("seed %s: status %d err %v", names[i], status, err)
		}
	}

	cfg := config{
		client: c, interval: 20 * time.Millisecond, splay: 10 * time.Millisecond,
		speed: 1, stuckFrac: 0.2, seed: 42, concurrency: 8, summaryEvery: time.Hour,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if err := run(ctx, cfg); err != nil {
		t.Fatal(err)
	}

	stuck := selectStuck(names, cfg.stuckFrac, rand.New(rand.NewSource(cfg.seed)))
	if len(stuck) != 2 {
		t.Fatalf("expected 2 stuck, got %d", len(stuck))
	}
	for _, name := range names {
		body, status, _ := c.do(context.Background(), "GET", "/nodes/"+name, nil)
		if status != http.StatusOK {
			t.Fatalf("get %s: status %d", name, status)
		}
		var n map[string]any
		json.Unmarshal(body, &n)
		ohai := n["automatic"].(map[string]any)["ohai_time"].(float64)
		if stuck[name] && ohai != 1000.0 {
			t.Errorf("stuck node %s checked in (ohai_time=%v)", name, ohai)
		}
		if !stuck[name] && ohai == 1000.0 {
			t.Errorf("converging node %s never checked in", name)
		}
	}
}
