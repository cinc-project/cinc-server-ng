package store

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCreateOrgAndLookup(t *testing.T) {
	s := New()
	if _, ok, err := s.Org("acme"); err != nil || ok {
		t.Fatalf("org should not exist yet: ok=%v err=%v", ok, err)
	}
	org, err := s.CreateOrg("acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if org == nil {
		t.Fatal("expected org")
	}
	got, ok, err := s.Org("acme")
	if err != nil || !ok || got.Name() != "acme" {
		t.Fatalf("Org lookup: got=%v ok=%v err=%v", got, ok, err)
	}
}

func TestCreateOrgConflict(t *testing.T) {
	s := New()
	if _, err := s.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOrg("acme"); err != ErrConflict {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestListAndDeleteOrgs(t *testing.T) {
	s := New()
	mustCreateOrg(t, s, "b")
	mustCreateOrg(t, s, "a")
	got, err := s.ListOrgs()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("ListOrgs not sorted: %v", got)
	}
	if existed, err := s.DeleteOrg("a"); err != nil || !existed {
		t.Fatalf("DeleteOrg should report existed: existed=%v err=%v", existed, err)
	}
	if existed, err := s.DeleteOrg("a"); err != nil || existed {
		t.Fatalf("second DeleteOrg should report not-existed: existed=%v err=%v", existed, err)
	}
	if got, err := s.ListOrgs(); err != nil || len(got) != 1 {
		t.Fatalf("org not deleted: %v err=%v", got, err)
	}
}

func TestOrgCreateGetDelete(t *testing.T) {
	s := New()
	org, _ := s.CreateOrg("acme")

	if _, ok, err := org.Get("nodes", "web"); err != nil || ok {
		t.Fatalf("node should not exist: ok=%v err=%v", ok, err)
	}
	if err := org.Create("nodes", "web", []byte(`{"name":"web"}`)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := org.Create("nodes", "web", []byte(`{}`)); err != ErrConflict {
		t.Fatalf("expected ErrConflict on duplicate, got %v", err)
	}
	got, ok, err := org.Get("nodes", "web")
	if err != nil || !ok || string(got) != `{"name":"web"}` {
		t.Fatalf("Get returned %q ok=%v err=%v", got, ok, err)
	}
	deleted, ok, err := org.Delete("nodes", "web")
	if err != nil || !ok || string(deleted) != `{"name":"web"}` {
		t.Fatalf("Delete returned %q ok=%v err=%v", deleted, ok, err)
	}
	if _, ok, _ := org.Get("nodes", "web"); ok {
		t.Fatal("node should be gone after delete")
	}
}

func TestOrgPutUpsertsAndKeysSorted(t *testing.T) {
	s := New()
	org, _ := s.CreateOrg("acme")
	mustPut(t, org, "roles", "z", `{"v":1}`)
	mustPut(t, org, "roles", "a", `{"v":1}`)
	mustPut(t, org, "roles", "a", `{"v":2}`) // upsert
	keys, err := org.Keys("roles")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] != "a" || keys[1] != "z" {
		t.Fatalf("Keys not sorted unique: %v", keys)
	}
	got, _, _ := org.Get("roles", "a")
	if string(got) != `{"v":2}` {
		t.Fatalf("Put did not upsert: %s", got)
	}
}

func TestStoredValueIsCopied(t *testing.T) {
	s := New()
	org, _ := s.CreateOrg("acme")
	val := []byte(`{"name":"web"}`)
	mustPut(t, org, "nodes", "web", string(val))
	val[2] = 'X' // mutate caller's slice
	got, _, _ := org.Get("nodes", "web")
	if string(got) != `{"name":"web"}` {
		t.Fatalf("store aliased caller slice: %s", got)
	}
}

func TestViewReturnsStoredValue(t *testing.T) {
	s := New()
	org, _ := s.CreateOrg("acme")
	mustPut(t, org, "nodes", "web", `{"name":"web"}`)
	got, ok, err := org.View("nodes", "web")
	if err != nil || !ok || string(got) != `{"name":"web"}` {
		t.Fatalf("View returned %q ok=%v err=%v", got, ok, err)
	}
	if _, ok, _ := org.View("nodes", "missing"); ok {
		t.Fatal("View of missing key should report false")
	}
}

// TestViewReturnsIndependentCopy documents View's contract under the pluggable
// backend: it returns an owned copy (the no-copy fast path is internal to the
// backend's Range), so mutating the result must not affect stored state.
func TestViewReturnsIndependentCopy(t *testing.T) {
	s := New()
	org, _ := s.CreateOrg("acme")
	mustPut(t, org, "nodes", "web", `{"name":"web"}`)
	got, _, _ := org.View("nodes", "web")
	got[2] = 'X'
	again, _, _ := org.View("nodes", "web")
	if string(again) != `{"name":"web"}` {
		t.Fatalf("View result aliased stored value: %s", again)
	}
}

func TestRangeVisitsAllEntries(t *testing.T) {
	s := New()
	org, _ := s.CreateOrg("acme")
	mustPut(t, org, "nodes", "a", `{"n":"a"}`)
	mustPut(t, org, "nodes", "b", `{"n":"b"}`)

	seen := map[string]string{}
	if err := org.Range("nodes", func(key string, raw []byte) bool {
		seen[key] = string(raw)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen["a"] != `{"n":"a"}` || seen["b"] != `{"n":"b"}` {
		t.Fatalf("Range did not visit all entries: %v", seen)
	}

	// An empty collection yields no calls.
	calls := 0
	if err := org.Range("missing", func(string, []byte) bool { calls++; return true }); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("Range over empty collection called fn %d times", calls)
	}
}

func TestRangeStopsWhenFnReturnsFalse(t *testing.T) {
	s := New()
	org, _ := s.CreateOrg("acme")
	for _, k := range []string{"a", "b", "c"} {
		mustPut(t, org, "nodes", k, `{}`)
	}
	count := 0
	if err := org.Range("nodes", func(string, []byte) bool {
		count++
		return false // stop after the first
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("Range visited %d entries, want 1 (early stop)", count)
	}
}

func TestCollectionsListsNonEmptyOnly(t *testing.T) {
	s := New()
	org, _ := s.CreateOrg("acme")
	if got := org.Name(); got != "acme" {
		t.Fatalf("Name = %q", got)
	}
	if cols, err := org.Collections(); err != nil || len(cols) != 0 {
		t.Fatalf("expected no collections, got %v err=%v", cols, err)
	}
	mustPut(t, org, "roles", "web", `{}`)
	mustPut(t, org, "nodes", "n1", `{}`)
	if _, _, err := org.Delete("nodes", "n1"); err != nil { // empties the collection
		t.Fatal(err)
	}
	cols, err := org.Collections()
	if err != nil {
		t.Fatal(err)
	}
	if len(cols) != 1 || cols[0] != "roles" {
		t.Fatalf("Collections should list only non-empty: %v", cols)
	}
}

// TestConcurrentAccess exercises the locks; run with -race.
func TestConcurrentAccess(t *testing.T) {
	s := New()
	org, _ := s.CreateOrg("acme")
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			key := fmt.Sprintf("n%d", i%10)
			org.Put("nodes", key, []byte(`{"i":1}`))
			org.Get("nodes", key)
			org.Keys("nodes")
			s.ListOrgs()
		})
	}
	wg.Wait()
}

func TestGlobalSpaceIsStableAndSeparate(t *testing.T) {
	s := New()
	g := s.Global()
	if g == nil {
		t.Fatal("Global returned nil")
	}
	mustPut(t, g, "users", "admin", `{"name":"admin"}`)
	org, _ := s.CreateOrg("acme")
	if _, ok, _ := org.Get("users", "admin"); ok {
		t.Fatal("global users must not leak into orgs")
	}
	if got, ok, err := g.Get("users", "admin"); err != nil || !ok || string(got) != `{"name":"admin"}` {
		t.Fatal("global value not retrievable")
	}
}

func TestOrgsAreIsolated(t *testing.T) {
	s := New()
	a, _ := s.CreateOrg("a")
	b, _ := s.CreateOrg("b")
	mustPut(t, a, "nodes", "web", `{}`)
	if _, ok, _ := b.Get("nodes", "web"); ok {
		t.Fatal("orgs must not share data")
	}
}

func mustCreateOrg(t *testing.T, s *Store, name string) {
	t.Helper()
	if _, err := s.CreateOrg(name); err != nil {
		t.Fatalf("CreateOrg(%q): %v", name, err)
	}
}

func mustPut(t *testing.T, org *Org, coll, key, val string) {
	t.Helper()
	if err := org.Put(coll, key, []byte(val)); err != nil {
		t.Fatalf("Put(%q,%q): %v", coll, key, err)
	}
}

// TestOrgStampsWritesWithClockAndActor: an Org handle stamps every write with the
// store's clock and the actor it was opened As, the update keeps the creation
// time, and a transaction's handles stamp the same way.
func TestOrgStampsWritesWithClockAndActor(t *testing.T) {
	s := New()
	now := time.Date(2024, 3, 1, 17, 22, 9, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	org, err := s.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := org.As("users/alice").Create("nodes", "web", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	created := now
	now = now.Add(time.Hour)
	if err := org.As("clients/web").Put("nodes", "web", []byte(`{"v":2}`)); err != nil {
		t.Fatal(err)
	}
	m, ok, err := org.Meta("nodes", "web")
	if err != nil || !ok {
		t.Fatalf("Meta: ok=%v err=%v", ok, err)
	}
	if !m.CreatedAt.Equal(created) || !m.UpdatedAt.Equal(now) || m.UpdatedBy != "clients/web" {
		t.Fatalf("meta = %+v; want created %v, updated %v by clients/web", m, created, now)
	}

	// A handle with no actor stamps the time and no actor; so does the global space.
	if err := s.Global().Put("users", "bob", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if m, _, _ := s.Global().Meta("users", "bob"); !m.CreatedAt.Equal(now) || m.UpdatedBy != "" {
		t.Fatalf("global meta = %+v", m)
	}

	err = s.Tx(func(tx *Store) error {
		o, ok, err := tx.Org("acme")
		if err != nil || !ok {
			return fmt.Errorf("tx org: ok=%v err=%v", ok, err)
		}
		return o.As("users/carol").Put("roles", "base", []byte(`{}`))
	})
	if err != nil {
		t.Fatal(err)
	}
	if m, _, _ := org.Meta("roles", "base"); !m.CreatedAt.Equal(now) || m.UpdatedBy != "users/carol" {
		t.Fatalf("meta of a write in a transaction = %+v", m)
	}
}
