package sqlite_test

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/store"
	"github.com/tas50/cinc-server-ng/internal/store/backendtest"
	"github.com/tas50/cinc-server-ng/internal/store/sqlite"
)

// TestConformanceGroupCommit runs the full backend conformance suite against a
// group-commit backend. Coalescing writes into shared transactions must not
// change any observable behavior: Create conflicts, Delete semantics, Tx
// commit/rollback, concurrency and org lifecycle all still hold.
func TestConformanceGroupCommit(t *testing.T) {
	backendtest.Run(t, func(t *testing.T) store.Backend {
		db := filepath.Join(t.TempDir(), "gc.db")
		b, err := sqlite.Open(db, sqlite.WithGroupCommit())
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		t.Cleanup(func() { b.Close() })
		return b
	})
}

// TestGroupCommitDurableAndVisible proves the commit contract under load: when a
// concurrent Put returns, its write is already committed and visible to a
// subsequent read (the coalescer must not acknowledge a write before its batch
// commits). Every distinct key written must be present afterward — no lost
// updates from batching.
func TestGroupCommitDurableAndVisible(t *testing.T) {
	b, err := sqlite.Open(filepath.Join(t.TempDir(), "gc.db"), sqlite.WithGroupCommit())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	const n = 500
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("node%d", i)
			body := []byte(fmt.Sprintf(`{"i":%d}`, i))
			if err := b.Put("acme", "nodes", key, body); err != nil {
				t.Errorf("put %s: %v", key, err)
				return
			}
			// The write must be visible immediately after Put returns.
			got, ok, err := b.Get("acme", "nodes", key)
			if err != nil || !ok || string(got) != string(body) {
				t.Errorf("read-after-write %s: got=%q ok=%v err=%v", key, got, ok, err)
			}
		}(i)
	}
	wg.Wait()

	keys, err := b.Keys("acme", "nodes")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != n {
		t.Fatalf("expected %d keys after concurrent writes, got %d", n, len(keys))
	}
}
