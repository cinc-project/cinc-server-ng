package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/store"
	"github.com/cinc-project/cinc-server-ng/internal/store/sqlite"
)

// TestReadsNotBlockedByOpenWriteTx asserts WAL's defining guarantee: a reader
// can complete while a writer holds an open transaction. The fleet check-in
// path keeps the single writer busy continuously; if reads share that one
// connection (SetMaxOpenConns(1) on the only pool) a dashboard scan blocks
// behind in-flight writes. A dedicated read-only pool on the same WAL file lets
// the read proceed against the last committed snapshot.
func TestReadsNotBlockedByOpenWriteTx(t *testing.T) {
	b, err := sqlite.Open(filepath.Join(t.TempDir(), "concurrent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })

	if err := b.Put("acme", "nodes", "seed", []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}

	writerHoldsConn := make(chan struct{})
	releaseWriter := make(chan struct{})
	txDone := make(chan error, 1)
	go func() {
		txDone <- b.Tx(func(tx store.Backend) error {
			// Acquire the write side and then hold the connection open.
			if err := tx.Put("acme", "nodes", "writer", []byte(`{"v":2}`)); err != nil {
				return err
			}
			close(writerHoldsConn)
			<-releaseWriter
			return nil
		})
	}()

	<-writerHoldsConn // the write transaction now owns the writer connection

	readDone := make(chan error, 1)
	go func() {
		_, _, err := b.Get("acme", "nodes", "seed")
		readDone <- err
	}()

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		close(releaseWriter)
		<-txDone
		t.Fatal("read blocked behind an open write transaction: reads share the single writer connection")
	}

	close(releaseWriter)
	if err := <-txDone; err != nil {
		t.Fatalf("write tx: %v", err)
	}
}
