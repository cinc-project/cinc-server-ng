package store_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// Derived indexes (search postings, group membership) are maintained
// incrementally from the store's write stream. Rebuilding them per change is
// what makes a bootstrap quadratic, so the stream has to be exact: every
// committed write is reported once, and nothing that was rolled back is
// reported at all.

type recorder struct {
	mu     sync.Mutex
	events []store.Event
}

func (r *recorder) observe(ev store.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recorder) snapshot() []store.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]store.Event(nil), r.events...)
}

func TestWatchReportsWrites(t *testing.T) {
	st := store.New()
	var rec recorder
	st.Watch(rec.observe)

	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}
	if err := org.Put("nodes", "web01", []byte(`{"name":"web01"}`)); err != nil {
		t.Fatal(err)
	}
	if err := org.Create("nodes", "web02", []byte(`{"name":"web02"}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := org.Delete("nodes", "web01"); err != nil {
		t.Fatal(err)
	}

	got := rec.snapshot()
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3: %+v", len(got), got)
	}
	for i, want := range []struct {
		key     string
		deleted bool
	}{{"web01", false}, {"web02", false}, {"web01", true}} {
		if got[i].Org != "acme" || got[i].Collection != "nodes" || got[i].Key != want.key {
			t.Errorf("event %d = %+v, want acme/nodes/%s", i, got[i], want.key)
		}
		if got[i].Deleted != want.deleted {
			t.Errorf("event %d deleted = %v, want %v", i, got[i].Deleted, want.deleted)
		}
	}
	if string(got[1].Value) != `{"name":"web02"}` {
		t.Errorf("create event carried %q", got[1].Value)
	}
}

// A Create that conflicts wrote nothing, so it must report nothing.
func TestWatchIgnoresConflictingCreate(t *testing.T) {
	st := store.New()
	org, _ := st.CreateOrg("acme")
	if err := org.Create("nodes", "web01", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	var rec recorder
	st.Watch(rec.observe)
	if err := org.Create("nodes", "web01", []byte(`{}`)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second Create err = %v, want ErrConflict", err)
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("conflicting Create reported %+v, want nothing", got)
	}
}

// Deleting something absent changed nothing, so it must report nothing.
func TestWatchIgnoresMissingDelete(t *testing.T) {
	st := store.New()
	org, _ := st.CreateOrg("acme")
	var rec recorder
	st.Watch(rec.observe)
	if _, existed, err := org.Delete("nodes", "ghost"); err != nil || existed {
		t.Fatalf("Delete of absent key: existed=%v err=%v", existed, err)
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("no-op Delete reported %+v, want nothing", got)
	}
}

// Writes inside a transaction are only real once it commits. Reporting them
// early would leave an index describing data that never existed.
func TestWatchDefersTransactionUntilCommit(t *testing.T) {
	st := store.New()
	if _, err := st.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	var rec recorder
	st.Watch(rec.observe)

	var duringTx int
	if err := st.Tx(func(tx *store.Store) error {
		org, _, err := tx.Org("acme")
		if err != nil {
			return err
		}
		if err := org.Put("nodes", "web01", []byte(`{}`)); err != nil {
			return err
		}
		duringTx = len(rec.snapshot())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if duringTx != 0 {
		t.Errorf("%d events emitted before commit, want 0", duringTx)
	}
	if got := rec.snapshot(); len(got) != 1 || got[0].Key != "web01" {
		t.Fatalf("after commit got %+v, want one write of web01", got)
	}
}

func TestWatchDropsRolledBackWrites(t *testing.T) {
	st := store.New()
	if _, err := st.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	var rec recorder
	st.Watch(rec.observe)

	boom := errors.New("boom")
	if err := st.Tx(func(tx *store.Store) error {
		org, _, _ := tx.Org("acme")
		if err := org.Put("nodes", "web01", []byte(`{}`)); err != nil {
			return err
		}
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("Tx err = %v, want boom", err)
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("rolled-back write reported %+v, want nothing", got)
	}
}

// Several observers can watch the same store (search postings and membership
// both do).
func TestWatchSupportsMultipleObservers(t *testing.T) {
	st := store.New()
	var a, b recorder
	st.Watch(a.observe)
	st.Watch(b.observe)
	org, _ := st.CreateOrg("acme")
	if err := org.Put("nodes", "web01", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if len(a.snapshot()) != 1 || len(b.snapshot()) != 1 {
		t.Fatalf("observers saw %d and %d events, want 1 each", len(a.snapshot()), len(b.snapshot()))
	}
}
