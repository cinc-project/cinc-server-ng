package server

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestWritesRecordTimesAndActor: every object written through the API records
// when it was created and last changed, on the server's clock, and which actor
// changed it last, typed as a user or a client, as erchef records created_at,
// updated_at and last_updated_by.
func TestWritesRecordTimesAndActor(t *testing.T) {
	for _, storage := range []string{"memory", "sqlite"} {
		t.Run(storage, func(t *testing.T) { testWritesRecordTimesAndActor(t, storage) })
	}
}

func testWritesRecordTimesAndActor(t *testing.T, storage string) {
	// Options.Now also drives the signature skew check, so the clock stays near
	// real time and moves forward by a minute rather than jumping.
	var mu sync.Mutex
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func() { mu.Lock(); now = now.Add(time.Minute); mu.Unlock() }

	opts := Options{Orgs: []string{"acme"}, EnforceACL: true, Now: clock, Storage: storage}
	if storage == "sqlite" {
		opts.DB = filepath.Join(t.TempDir(), "state.db")
	}
	srv := startServer(t, opts)
	base := srv.URL() + "/organizations/acme"
	admin := "users/" + srv.AdminName()

	t0 := clock()
	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes", `{"name":"web01"}`)); code != 201 {
		t.Fatalf("create node = %d", code)
	}
	if code := statusOf(t, signed(t, srv, "POST", srv.URL()+"/users", validUserBody(t, `{"name":"alice"}`))); code != 201 {
		t.Fatalf("create user = %d", code)
	}
	advance()
	t1 := clock()
	if code := statusOf(t, signed(t, srv, "PUT", base+"/nodes/web01", `{"name":"web01","run_list":["recipe[x]"]}`)); code != 200 {
		t.Fatalf("update node = %d", code)
	}
	if code := statusOf(t, signedAs(t, "acme-validator", srv.ValidatorKey("acme"), "POST", base+"/clients", `{"name":"node1"}`)); code != 201 {
		t.Fatalf("register client = %d", code)
	}

	org, ok, err := srv.Store().Org("acme")
	if err != nil || !ok {
		t.Fatalf("org: ok=%v err=%v", ok, err)
	}
	check := func(what string, created, updated time.Time, by string, get func() (createdAt, updatedAt time.Time, updatedBy string, ok bool, err error)) {
		t.Helper()
		c, u, b, ok, err := get()
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", what, ok, err)
		}
		if !c.Equal(created) || !u.Equal(updated) || b != by {
			t.Errorf("%s: created %v, updated %v by %q; want created %v, updated %v by %q", what, c, u, b, created, updated, by)
		}
	}
	check("node web01", t0, t1, admin, func() (time.Time, time.Time, string, bool, error) {
		m, ok, err := org.Meta("nodes", "web01")
		return m.CreatedAt, m.UpdatedAt, m.UpdatedBy, ok, err
	})
	check("client node1", t1, t1, "clients/acme-validator", func() (time.Time, time.Time, string, bool, error) {
		m, ok, err := org.Meta("clients", "node1")
		return m.CreatedAt, m.UpdatedAt, m.UpdatedBy, ok, err
	})
	check("user alice", t0, t0, admin, func() (time.Time, time.Time, string, bool, error) {
		m, ok, err := srv.Store().Global().Meta("users", "alice")
		return m.CreatedAt, m.UpdatedAt, m.UpdatedBy, ok, err
	})
}
