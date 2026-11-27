package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
)

// statusBody is /_status as erchef's chef_wm_status:check_health builds it:
// status, upstreams, keygen, indexing, in that order, with the keygen members
// in chef_keygen_cache:status_for_json's order.
func statusBody(status, sql string) string {
	return `{"status":"` + status + `",` +
		`"upstreams":{"chef_solr":"pong","chef_sql":"` + sql + `","oc_chef_authz":"pong"},` +
		`"keygen":{"keys":0,"max":0,"max_workers":0,"cur_max_workers":0,"inflight":0,"avail_workers":0,"start_size":0},` +
		`"indexing":{"mode":"inline"}}`
}

func getStatus(t *testing.T, st *store.Store) (int, string) {
	t.Helper()
	srv := httptest.NewServer(New(st).Handler())
	t.Cleanup(srv.Close)
	resp, body := do(t, http.MethodGet, srv.URL+"/_status", "")
	return resp.StatusCode, strings.TrimSpace(body)
}

func TestStatusReportsErchefShape(t *testing.T) {
	code, body := getStatus(t, store.New())
	if code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", code, body)
	}
	if want := statusBody("pong", "pong"); body != want {
		t.Fatalf("body\n got %s\nwant %s", body, want)
	}
}

func TestStatusPingsSQLite(t *testing.T) {
	be, err := sqlite.Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewWithBackend(be)
	if code, body := getStatus(t, st); code != http.StatusOK || body != statusBody("pong", "pong") {
		t.Fatalf("open database: %d %s", code, body)
	}
	if err := be.Close(); err != nil {
		t.Fatal(err)
	}
	code, body := getStatus(t, st)
	if code != http.StatusInternalServerError {
		t.Fatalf("closed database: status %d, want 500: %s", code, body)
	}
	if want := statusBody("fail", "fail"); body != want {
		t.Fatalf("closed database body\n got %s\nwant %s", body, want)
	}
}

// pingBackend is a memory backend whose health check is ping.
type pingBackend struct {
	store.Backend
	ping func(context.Context) error
}

func (b pingBackend) Ping(ctx context.Context) error { return b.ping(ctx) }

func TestStatusFailsWhenStorePingFails(t *testing.T) {
	st := store.NewWithBackend(pingBackend{store.NewMemoryBackend(), func(context.Context) error {
		return errors.New("disk on fire")
	}})
	code, body := getStatus(t, st)
	if code != http.StatusInternalServerError || body != statusBody("fail", "fail") {
		t.Fatalf("got %d %s", code, body)
	}
}

// erchef reports an upstream that does not answer within health_ping_timeout
// as "fail" rather than waiting on it.
func TestStatusFailsWhenStorePingHangs(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	st := store.NewWithBackend(pingBackend{store.NewMemoryBackend(), func(context.Context) error {
		<-release // ignores its context, as a wedged driver would
		return nil
	}})
	code, body := getStatus(t, st)
	if code != http.StatusInternalServerError || body != statusBody("fail", "fail") {
		t.Fatalf("got %d %s", code, body)
	}
}
