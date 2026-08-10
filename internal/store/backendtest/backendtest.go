// Package backendtest is the shared conformance suite for store.Backend
// implementations. Each backend package calls Run from its own test, so the two
// backends are held to one identical behavioral contract.
package backendtest

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/tas50/cinc-server-ng/internal/store"
)

// Run exercises the full Backend contract against a fresh backend produced by
// newBackend for each sub-test.
func Run(t *testing.T, newBackend func(t *testing.T) store.Backend) {
	t.Helper()
	t.Run("ObjectRoundTrip", func(t *testing.T) { testObjectRoundTrip(t, newBackend(t)) })
	t.Run("CopyIndependence", func(t *testing.T) { testCopyIndependence(t, newBackend(t)) })
	t.Run("CreateConflict", func(t *testing.T) { testCreateConflict(t, newBackend(t)) })
	t.Run("CreatePreservesOriginal", func(t *testing.T) { testCreatePreservesOriginal(t, newBackend(t)) })
	t.Run("DeleteSemantics", func(t *testing.T) { testDeleteSemantics(t, newBackend(t)) })
	t.Run("KeysSorted", func(t *testing.T) { testKeysSorted(t, newBackend(t)) })
	t.Run("CollectionsSorted", func(t *testing.T) { testCollectionsSorted(t, newBackend(t)) })
	t.Run("RangeEarlyStop", func(t *testing.T) { testRangeEarlyStop(t, newBackend(t)) })
	t.Run("OrgNamespacing", func(t *testing.T) { testOrgNamespacing(t, newBackend(t)) })
	t.Run("Blobs", func(t *testing.T) { testBlobs(t, newBackend(t)) })
	t.Run("OrgLifecycle", func(t *testing.T) { testOrgLifecycle(t, newBackend(t)) })
	t.Run("DeleteOrgDropsData", func(t *testing.T) { testDeleteOrgDropsData(t, newBackend(t)) })
	t.Run("DeleteOrgIsolation", func(t *testing.T) { testDeleteOrgIsolation(t, newBackend(t)) })
	t.Run("SortOrderFidelity", func(t *testing.T) { testSortOrderFidelity(t, newBackend(t)) })
	t.Run("OpaqueBodies", func(t *testing.T) { testOpaqueBodies(t, newBackend(t)) })
	t.Run("Concurrency", func(t *testing.T) { testConcurrency(t, newBackend(t)) })
	t.Run("TxCommit", func(t *testing.T) { testTxCommit(t, newBackend(t)) })
	t.Run("TxRollback", func(t *testing.T) { testTxRollback(t, newBackend(t)) })
	t.Run("TxReadsOwnWrites", func(t *testing.T) { testTxReadsOwnWrites(t, newBackend(t)) })
}

func mustPut(t *testing.T, b store.Backend, org, coll, key, val string) {
	t.Helper()
	if err := b.Put(org, coll, key, []byte(val)); err != nil {
		t.Fatalf("Put(%q,%q,%q): %v", org, coll, key, err)
	}
}

func testObjectRoundTrip(t *testing.T, b store.Backend) {
	if _, ok, err := b.Get("acme", "nodes", "web"); err != nil || ok {
		t.Fatalf("missing Get: ok=%v err=%v", ok, err)
	}
	mustPut(t, b, "acme", "nodes", "web", `{"name":"web"}`)
	got, ok, err := b.Get("acme", "nodes", "web")
	if err != nil || !ok || string(got) != `{"name":"web"}` {
		t.Fatalf("Get after Put: got=%q ok=%v err=%v", got, ok, err)
	}
}

func testCopyIndependence(t *testing.T, b store.Backend) {
	mustPut(t, b, "acme", "nodes", "web", `{"a":1}`)
	got, _, _ := b.Get("acme", "nodes", "web")
	got[0] = 'X' // mutating the returned slice must not affect stored state
	again, _, _ := b.Get("acme", "nodes", "web")
	if string(again) != `{"a":1}` {
		t.Fatalf("stored value mutated via returned slice: %q", again)
	}
}

func testCreateConflict(t *testing.T, b store.Backend) {
	if err := b.Create("acme", "roles", "base", []byte(`{}`)); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if err := b.Create("acme", "roles", "base", []byte(`{}`)); err != store.ErrConflict {
		t.Fatalf("second Create: want ErrConflict, got %v", err)
	}
}

func testDeleteSemantics(t *testing.T, b store.Backend) {
	if _, existed, err := b.Delete("acme", "nodes", "ghost"); err != nil || existed {
		t.Fatalf("delete missing: existed=%v err=%v", existed, err)
	}
	mustPut(t, b, "acme", "nodes", "web", `{"name":"web"}`)
	old, existed, err := b.Delete("acme", "nodes", "web")
	if err != nil || !existed || string(old) != `{"name":"web"}` {
		t.Fatalf("delete existing: old=%q existed=%v err=%v", old, existed, err)
	}
	if _, ok, _ := b.Get("acme", "nodes", "web"); ok {
		t.Fatal("value present after delete")
	}
}

func testKeysSorted(t *testing.T, b store.Backend) {
	mustPut(t, b, "acme", "nodes", "c", `{}`)
	mustPut(t, b, "acme", "nodes", "a", `{}`)
	mustPut(t, b, "acme", "nodes", "b", `{}`)
	keys, err := b.Keys("acme", "nodes")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 || keys[0] != "a" || keys[1] != "b" || keys[2] != "c" {
		t.Fatalf("Keys not sorted: %v", keys)
	}
	empty, err := b.Keys("acme", "missing")
	if err != nil || len(empty) != 0 {
		t.Fatalf("Keys of empty coll: %v err=%v", empty, err)
	}
}

func testCollectionsSorted(t *testing.T, b store.Backend) {
	mustPut(t, b, "acme", "roles", "x", `{}`)
	mustPut(t, b, "acme", "nodes", "x", `{}`)
	// A collection emptied by Delete must not be reported.
	mustPut(t, b, "acme", "envs", "x", `{}`)
	b.Delete("acme", "envs", "x")
	colls, err := b.Collections("acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(colls) != 2 || colls[0] != "nodes" || colls[1] != "roles" {
		t.Fatalf("Collections: %v", colls)
	}
}

func testRangeEarlyStop(t *testing.T, b store.Backend) {
	for _, k := range []string{"a", "b", "c", "d"} {
		mustPut(t, b, "acme", "nodes", k, `{}`)
	}
	seen := 0
	err := b.Range("acme", "nodes", func(key string, raw []byte) bool {
		seen++
		return seen < 2 // stop after the second
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != 2 {
		t.Fatalf("Range did not stop early: visited %d", seen)
	}
}

func testOrgNamespacing(t *testing.T, b store.Backend) {
	mustPut(t, b, "acme", "nodes", "web", `{"org":"acme"}`)
	mustPut(t, b, "other", "nodes", "web", `{"org":"other"}`)
	mustPut(t, b, "", "users", "pivotal", `{"global":true}`)
	a, _, _ := b.Get("acme", "nodes", "web")
	o, _, _ := b.Get("other", "nodes", "web")
	g, _, _ := b.Get("", "users", "pivotal")
	if string(a) != `{"org":"acme"}` || string(o) != `{"org":"other"}` || string(g) != `{"global":true}` {
		t.Fatalf("org namespaces leaked: a=%q o=%q g=%q", a, o, g)
	}
}

func testBlobs(t *testing.T, b store.Backend) {
	if ok, err := b.HasBlob("acme", "deadbeef"); err != nil || ok {
		t.Fatalf("HasBlob missing: ok=%v err=%v", ok, err)
	}
	if err := b.PutBlob("acme", "deadbeef", []byte("filecontent")); err != nil {
		t.Fatal(err)
	}
	got, ok, err := b.Blob("acme", "deadbeef")
	if err != nil || !ok || string(got) != "filecontent" {
		t.Fatalf("Blob: got=%q ok=%v err=%v", got, ok, err)
	}
	got[0] = 'X'
	again, _, _ := b.Blob("acme", "deadbeef")
	if !bytes.Equal(again, []byte("filecontent")) {
		t.Fatalf("blob mutated via returned slice: %q", again)
	}
	if err := b.DeleteBlob("acme", "deadbeef"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := b.HasBlob("acme", "deadbeef"); ok {
		t.Fatal("blob present after delete")
	}
}

func testOrgLifecycle(t *testing.T, b store.Backend) {
	if err := b.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	if err := b.CreateOrg("acme"); err != store.ErrConflict {
		t.Fatalf("CreateOrg conflict: want ErrConflict, got %v", err)
	}
	if err := b.CreateOrg("beta"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := b.HasOrg("acme"); !ok {
		t.Fatal("HasOrg acme should be true")
	}
	if ok, _ := b.HasOrg("nope"); ok {
		t.Fatal("HasOrg nope should be false")
	}
	orgs, err := b.ListOrgs()
	if err != nil || len(orgs) != 2 || orgs[0] != "acme" || orgs[1] != "beta" {
		t.Fatalf("ListOrgs: %v err=%v", orgs, err)
	}
	if existed, _ := b.DeleteOrg("acme"); !existed {
		t.Fatal("DeleteOrg acme should report existed")
	}
	if existed, _ := b.DeleteOrg("acme"); existed {
		t.Fatal("second DeleteOrg acme should report not-existed")
	}
}

func testDeleteOrgDropsData(t *testing.T, b store.Backend) {
	if err := b.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	mustPut(t, b, "acme", "nodes", "web", `{}`)
	if err := b.PutBlob("acme", "cafe", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.DeleteOrg("acme"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := b.Get("acme", "nodes", "web"); ok {
		t.Fatal("object survived DeleteOrg")
	}
	if ok, _ := b.HasBlob("acme", "cafe"); ok {
		t.Fatal("blob survived DeleteOrg")
	}
}

// testCreatePreservesOriginal asserts a conflicting Create does not overwrite the
// existing value (Create is not an upsert).
func testCreatePreservesOriginal(t *testing.T, b store.Backend) {
	if err := b.Create("acme", "roles", "base", []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := b.Create("acme", "roles", "base", []byte(`{"v":2}`)); err != store.ErrConflict {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	got, _, _ := b.Get("acme", "roles", "base")
	if string(got) != `{"v":1}` {
		t.Fatalf("conflicting Create overwrote value: %q", got)
	}
}

// testDeleteOrgIsolation asserts DeleteOrg drops only the named org's data and
// leaves other orgs (and the global space) untouched.
func testDeleteOrgIsolation(t *testing.T, b store.Backend) {
	for _, org := range []string{"acme", "beta"} {
		if err := b.CreateOrg(org); err != nil {
			t.Fatal(err)
		}
		mustPut(t, b, org, "nodes", "web", `{}`)
	}
	mustPut(t, b, "", "users", "pivotal", `{}`) // global space
	if _, err := b.DeleteOrg("acme"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := b.Get("beta", "nodes", "web"); !ok {
		t.Fatal("DeleteOrg(acme) dropped beta's data")
	}
	if _, ok, _ := b.Get("", "users", "pivotal"); !ok {
		t.Fatal("DeleteOrg(acme) dropped the global space")
	}
}

// testSortOrderFidelity asserts Keys/Collections/ListOrgs return byte-ascending
// order (Go sort.Strings), not a case-insensitive or locale collation. This guards
// the documented risk that a SQL backend's ORDER BY collation diverges from the
// memory backend's sort.Strings for mixed-case/unicode keys.
func testSortOrderFidelity(t *testing.T, b store.Backend) {
	keys := []string{"Zebra", "apple", "Banana", "10", "2", "apple2", "_under", "Ähen"}
	for _, k := range keys {
		mustPut(t, b, "acme", "nodes", k, `{}`)
	}
	want := append([]string(nil), keys...)
	sort.Strings(want)
	got, err := b.Keys("acme", "nodes")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Keys order diverges from sort.Strings:\n got=%v\nwant=%v", got, want)
	}

	colls := []string{"Roles", "nodes", "Environments", "data_bags"}
	for _, c := range colls {
		mustPut(t, b, "beta", c, "x", `{}`)
	}
	wantColls := append([]string(nil), colls...)
	sort.Strings(wantColls)
	gotColls, err := b.Collections("beta")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(gotColls) != fmt.Sprint(wantColls) {
		t.Fatalf("Collections order diverges:\n got=%v\nwant=%v", gotColls, wantColls)
	}

	orgNames := []string{"Zorg", "acme", "Beta"}
	for _, o := range orgNames {
		if err := b.CreateOrg(o); err != nil {
			t.Fatal(err)
		}
	}
	wantOrgs := append([]string(nil), orgNames...)
	sort.Strings(wantOrgs)
	gotOrgs, err := b.ListOrgs()
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(gotOrgs) != fmt.Sprint(wantOrgs) {
		t.Fatalf("ListOrgs order diverges:\n got=%v\nwant=%v", gotOrgs, wantOrgs)
	}
}

// testOpaqueBodies asserts the backend stores bodies as opaque bytes: arbitrary
// binary content (embedded NUL, non-UTF-8) round-trips exactly, for both objects
// and blobs.
func testOpaqueBodies(t *testing.T, b store.Backend) {
	body := []byte{'{', 0x00, 0xff, 0xfe, 'a', '}'}
	if err := b.Put("acme", "nodes", "bin", body); err != nil {
		t.Fatal(err)
	}
	got, ok, err := b.Get("acme", "nodes", "bin")
	if err != nil || !ok || !bytes.Equal(got, body) {
		t.Fatalf("object body not preserved: got=%v ok=%v err=%v", got, ok, err)
	}
	if err := b.PutBlob("acme", "bincs", body); err != nil {
		t.Fatal(err)
	}
	gotBlob, ok, err := b.Blob("acme", "bincs")
	if err != nil || !ok || !bytes.Equal(gotBlob, body) {
		t.Fatalf("blob content not preserved: got=%v ok=%v err=%v", gotBlob, ok, err)
	}
}

// testConcurrency hammers the backend from many goroutines to surface data races
// (under -race) and, for SQL backends, write-lock contention. Each worker owns a
// disjoint key range, and concurrent Range scans run alongside the writers.
func testConcurrency(t *testing.T, b store.Backend) {
	const workers, ops = 8, 25
	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := range ops {
				key := fmt.Sprintf("w%d-k%d", w, i)
				if err := b.Put("acme", "nodes", key, []byte(`{}`)); err != nil {
					t.Errorf("concurrent Put: %v", err)
					return
				}
				if _, ok, err := b.Get("acme", "nodes", key); err != nil || !ok {
					t.Errorf("concurrent Get: ok=%v err=%v", ok, err)
					return
				}
			}
		})
	}
	// Concurrent readers scanning while writes are in flight.
	for range 2 {
		wg.Go(func() {
			for range ops {
				if err := b.Range("acme", "nodes", func(string, []byte) bool { return true }); err != nil {
					t.Errorf("concurrent Range: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()
	keys, err := b.Keys("acme", "nodes")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != workers*ops {
		t.Fatalf("lost writes under concurrency: got %d keys, want %d", len(keys), workers*ops)
	}
}

// testTxCommit asserts a Tx that returns nil applies all of its writes atomically.
func testTxCommit(t *testing.T, b store.Backend) {
	err := b.Tx(func(tx store.Backend) error {
		if err := tx.CreateOrg("acme"); err != nil {
			return err
		}
		return tx.Put("acme", "nodes", "web", []byte(`{"v":1}`))
	})
	if err != nil {
		t.Fatalf("Tx commit: %v", err)
	}
	got, ok, err := b.Get("acme", "nodes", "web")
	if err != nil || !ok || string(got) != `{"v":1}` {
		t.Fatalf("committed write not visible: got=%q ok=%v err=%v", got, ok, err)
	}
	if ok, _ := b.HasOrg("acme"); !ok {
		t.Fatal("committed CreateOrg not visible after Tx")
	}
}

// testTxRollback asserts a Tx whose fn returns an error discards every write made
// inside it and propagates that error.
func testTxRollback(t *testing.T, b store.Backend) {
	mustPut(t, b, "acme", "nodes", "web", `{"v":1}`)
	sentinel := errors.New("boom")
	err := b.Tx(func(tx store.Backend) error {
		if err := tx.Put("acme", "nodes", "web", []byte(`{"v":2}`)); err != nil {
			return err
		}
		if err := tx.Put("acme", "roles", "base", []byte(`{}`)); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Tx should propagate fn's error, got %v", err)
	}
	got, _, _ := b.Get("acme", "nodes", "web")
	if string(got) != `{"v":1}` {
		t.Fatalf("rolled-back overwrite leaked: %q", got)
	}
	if _, ok, _ := b.Get("acme", "roles", "base"); ok {
		t.Fatal("rolled-back create leaked")
	}
}

// testTxReadsOwnWrites asserts reads inside a Tx observe that Tx's prior writes.
func testTxReadsOwnWrites(t *testing.T, b store.Backend) {
	err := b.Tx(func(tx store.Backend) error {
		if err := tx.Put("acme", "nodes", "web", []byte(`{"v":1}`)); err != nil {
			return err
		}
		got, ok, err := tx.Get("acme", "nodes", "web")
		if err != nil {
			return err
		}
		if !ok || string(got) != `{"v":1}` {
			return fmt.Errorf("tx did not read its own write: got=%q ok=%v", got, ok)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Tx: %v", err)
	}
}
