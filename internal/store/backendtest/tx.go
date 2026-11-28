package backendtest

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// concurrently runs write on another goroutine while a transaction is open,
// and waits for it to finish or, for a backend that holds writers back until
// the transaction ends (SQLite), for a moment. The returned channel is closed
// once write has returned.
func concurrently(write func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		write()
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
	}
	return done
}

// testTxRollbackKeepsConcurrentWrites asserts a rolled-back transaction
// discards only its own writes: what another writer committed while it was
// open, in any org and of any kind, survives.
func testTxRollbackKeepsConcurrentWrites(t *testing.T, b store.Backend) {
	mustPut(t, b, "acme", "nodes", "web", `{"v":1}`)
	mustPut(t, b, "beta", "keys", "old", `{}`)
	sentinel := errors.New("boom")
	var done <-chan struct{}
	var errs [4]error
	err := b.Tx(func(tx store.Backend) error {
		if err := tx.Put("acme", "nodes", "web", []byte(`{"v":2}`), store.Stamp{}); err != nil {
			return err
		}
		if err := tx.Create("acme", "clients", "mine", []byte(`{}`), store.Stamp{}); err != nil {
			return err
		}
		done = concurrently(func() {
			errs[0] = b.Put("beta", "nodes", "theirs", []byte(`{"v":1}`), store.Stamp{})
			_, _, errs[1] = b.Delete("beta", "keys", "old")
			errs[2] = b.PutBlob("beta", "abc", []byte("content"))
			errs[3] = b.CreateOrg("gamma")
		})
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Tx = %v, want the sentinel", err)
	}
	<-done
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent write %d: %v", i, err)
		}
	}
	if _, ok, _ := b.Get("beta", "nodes", "theirs"); !ok {
		t.Error("rollback lost a concurrent Put")
	}
	if _, ok, _ := b.Get("beta", "keys", "old"); ok {
		t.Error("rollback undid a concurrent Delete")
	}
	if ok, _ := b.HasBlob("beta", "abc"); !ok {
		t.Error("rollback lost a concurrent PutBlob")
	}
	if ok, _ := b.HasOrg("gamma"); !ok {
		t.Error("rollback lost a concurrent CreateOrg")
	}
	if got, _, _ := b.Get("acme", "nodes", "web"); string(got) != `{"v":1}` {
		t.Errorf("rolled-back overwrite leaked: %q", got)
	}
	if _, ok, _ := b.Get("acme", "clients", "mine"); ok {
		t.Error("rolled-back create leaked")
	}
}

// testTxUncommittedInvisible asserts another reader does not see a
// transaction's writes until it commits.
func testTxUncommittedInvisible(t *testing.T, b store.Backend) {
	err := b.Tx(func(tx store.Backend) error {
		if err := tx.CreateOrg("acme"); err != nil {
			return err
		}
		if err := tx.Put("acme", "nodes", "web", []byte(`{}`), store.Stamp{}); err != nil {
			return err
		}
		if _, ok, err := b.Get("acme", "nodes", "web"); err != nil || ok {
			return fmt.Errorf("uncommitted Put visible outside the transaction: ok=%v err=%v", ok, err)
		}
		if ok, err := b.HasOrg("acme"); err != nil || ok {
			return fmt.Errorf("uncommitted CreateOrg visible outside the transaction: ok=%v err=%v", ok, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := b.Get("acme", "nodes", "web"); !ok {
		t.Error("committed Put not visible")
	}
	if ok, _ := b.HasOrg("acme"); !ok {
		t.Error("committed CreateOrg not visible")
	}
}

// testTxCreateRace asserts that when a transaction and another writer create
// the same key, exactly one of them succeeds and the stored value is its.
func testTxCreateRace(t *testing.T, b store.Backend) {
	var done <-chan struct{}
	var otherErr error
	txErr := b.Tx(func(tx store.Backend) error {
		if err := tx.Create("acme", "clients", "web", []byte(`{"by":"tx"}`), store.Stamp{}); err != nil {
			return err
		}
		done = concurrently(func() {
			otherErr = b.Create("acme", "clients", "web", []byte(`{"by":"other"}`), store.Stamp{})
		})
		return nil
	})
	<-done
	got, _, _ := b.Get("acme", "clients", "web")
	switch {
	case txErr == nil && errors.Is(otherErr, store.ErrConflict):
		if string(got) != `{"by":"tx"}` {
			t.Errorf("transaction won, stored %q", got)
		}
	case otherErr == nil && errors.Is(txErr, store.ErrConflict):
		if string(got) != `{"by":"other"}` {
			t.Errorf("other writer won, stored %q", got)
		}
	default:
		t.Errorf("want exactly one create to win, the other ErrConflict: tx=%v other=%v stored=%q", txErr, otherErr, got)
	}
}

// testTxNoLostUpdate asserts a transaction that reads a key, then writes it
// back, cannot commit over another writer's change to that key made in
// between: either the transaction fails with ErrConflict or the other write
// is ordered after it. Both ways the other writer's value is what remains.
// read is how the transaction reads the key: a point read, or a Range as the
// rename scans do.
func testTxNoLostUpdate(t *testing.T, b store.Backend, read func(tx store.Backend) ([]byte, error)) {
	mustPut(t, b, "acme", "acls", "nodes/web", `{"read":["alice","bob"]}`)
	var done <-chan struct{}
	var otherErr error
	txErr := b.Tx(func(tx store.Backend) error {
		old, err := read(tx)
		if err != nil {
			return err
		}
		if string(old) != `{"read":["alice","bob"]}` {
			return fmt.Errorf("tx read %q", old)
		}
		done = concurrently(func() {
			otherErr = b.Put("acme", "acls", "nodes/web", []byte(`{"read":["alice"]}`), store.Stamp{})
		})
		return tx.Put("acme", "acls", "nodes/web", []byte(`{"read":["alicia","bob"]}`), store.Stamp{})
	})
	<-done
	if otherErr != nil {
		t.Fatalf("other writer: %v", otherErr)
	}
	if txErr != nil && !errors.Is(txErr, store.ErrConflict) {
		t.Fatalf("Tx = %v, want nil or ErrConflict", txErr)
	}
	if got, _, _ := b.Get("acme", "acls", "nodes/web"); string(got) != `{"read":["alice"]}` {
		t.Errorf("stored %q: the transaction overwrote a concurrent write (tx err %v)", got, txErr)
	}
}

func readByGet(tx store.Backend) ([]byte, error) {
	v, _, err := tx.Get("acme", "acls", "nodes/web")
	return v, err
}

func readByRange(tx store.Backend) ([]byte, error) {
	var v []byte
	err := tx.Range("acme", "acls", func(k string, raw []byte) bool {
		if k == "nodes/web" {
			v = append([]byte(nil), raw...)
		}
		return true
	})
	return v, err
}

// testTxView asserts every read inside a transaction sees its own writes,
// deletes and org drop, and that rolling it back leaves the backend as it was.
func testTxView(t *testing.T, b store.Backend) {
	for _, org := range []string{"acme", "beta"} {
		if err := b.CreateOrg(org); err != nil {
			t.Fatal(err)
		}
	}
	mustPut(t, b, "acme", "nodes", "a", `{"n":"a"}`)
	mustPut(t, b, "acme", "nodes", "b", `{"n":"b"}`)
	mustPut(t, b, "acme", "roles", "r", `{}`)
	if err := b.PutBlob("beta", "c1", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := b.Put("acme", "envs", "e", []byte(`{}`), store.Stamp{At: t1, By: "users/alice"}); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("boom")
	err := b.Tx(func(tx store.Backend) error {
		if err := txViewChecks(tx); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Tx = %v, want the sentinel", err)
	}
	if keys, _ := b.Keys("acme", "nodes"); fmt.Sprint(keys) != "[a b]" {
		t.Errorf("after rollback Keys = %v, want [a b]", keys)
	}
	if _, ok, _ := b.Get("acme", "roles", "r"); !ok {
		t.Error("rollback lost acme/roles/r")
	}
	if ok, _ := b.HasOrg("acme"); !ok {
		t.Error("rollback lost org acme")
	}
	wantMeta(t, mustMeta(t, b, "acme", "envs", "e"), t1, t1, "users/alice")
	if ok, _ := b.HasBlob("beta", "c1"); !ok {
		t.Error("rollback lost blob c1")
	}
	if ok, _ := b.HasBlob("beta", "c2"); ok {
		t.Error("rolled-back blob c2 leaked")
	}
}

// txViewChecks makes testTxView's writes through tx and checks what tx reads
// back.
func txViewChecks(tx store.Backend) error {
	if _, _, err := tx.Delete("acme", "nodes", "a"); err != nil {
		return err
	}
	if err := tx.Put("acme", "nodes", "c", []byte(`{"n":"c"}`), store.Stamp{}); err != nil {
		return err
	}
	if _, _, err := tx.Delete("acme", "roles", "r"); err != nil {
		return err
	}
	if err := tx.Put("acme", "envs", "e", []byte(`{"v":2}`), store.Stamp{At: t2, By: "users/bob"}); err != nil {
		return err
	}
	if keys, err := tx.Keys("acme", "nodes"); err != nil || fmt.Sprint(keys) != "[b c]" {
		return fmt.Errorf("keys in tx = %v (%v), want [b c]", keys, err)
	}
	seen := map[string]string{}
	if err := tx.Range("acme", "nodes", func(k string, raw []byte) bool {
		seen[k] = string(raw)
		return true
	}); err != nil {
		return err
	}
	if len(seen) != 2 || seen["b"] != `{"n":"b"}` || seen["c"] != `{"n":"c"}` {
		return fmt.Errorf("range in tx = %v", seen)
	}
	if colls, err := tx.Collections("acme"); err != nil || fmt.Sprint(colls) != "[envs nodes]" {
		return fmt.Errorf("collections in tx = %v (%v), want [envs nodes]", colls, err)
	}
	md, ok, err := tx.Meta("acme", "envs", "e")
	if err != nil {
		return err
	}
	if !ok || !md.CreatedAt.Equal(t1) || !md.UpdatedAt.Equal(t2) || md.UpdatedBy != "users/bob" {
		return fmt.Errorf("meta in tx = %+v ok=%v", md, ok)
	}
	if err := tx.SetMeta("acme", "nodes", "a", store.Meta{}); !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("SetMeta on a key deleted in tx = %v, want ErrNotFound", err)
	}
	if err := tx.SetMeta("acme", "nodes", "b", store.Meta{CreatedAt: t2, UpdatedAt: t2, UpdatedBy: "users/carol"}); err != nil {
		return err
	}
	if md, ok, _ := tx.Meta("acme", "nodes", "b"); !ok || md.UpdatedBy != "users/carol" {
		return fmt.Errorf("SetMeta not visible in tx: %+v ok=%v", md, ok)
	}
	if err := tx.DeleteBlob("beta", "c1"); err != nil {
		return err
	}
	if err := tx.PutBlob("beta", "c2", []byte("two")); err != nil {
		return err
	}
	if ok, _ := tx.HasBlob("beta", "c1"); ok {
		return errors.New("deleted blob visible in tx")
	}
	if data, ok, _ := tx.Blob("beta", "c2"); !ok || string(data) != "two" {
		return fmt.Errorf("blob written in tx = %q ok=%v", data, ok)
	}
	if existed, err := tx.DeleteOrg("acme"); err != nil || !existed {
		return fmt.Errorf("DeleteOrg in tx: existed=%v err=%v", existed, err)
	}
	if _, ok, _ := tx.Get("acme", "nodes", "b"); ok {
		return errors.New("dropped org's object visible in tx")
	}
	if ok, _ := tx.HasOrg("acme"); ok {
		return errors.New("dropped org listed in tx")
	}
	if err := tx.CreateOrg("acme"); err != nil {
		return fmt.Errorf("recreate dropped org in tx: %v", err)
	}
	if colls, _ := tx.Collections("acme"); len(colls) != 0 {
		return fmt.Errorf("recreated org in tx has collections %v", colls)
	}
	if orgs, err := tx.ListOrgs(); err != nil || fmt.Sprint(orgs) != "[acme beta]" {
		return fmt.Errorf("ListOrgs in tx = %v (%v), want [acme beta]", orgs, err)
	}
	return nil
}
