package backendtest

import (
	"sync"
	"testing"

	"github.com/cinc-project/cinc-server-ng/internal/store"
)

// blobViewer returns b as a store.BlobViewer, failing the test if it is not
// one: every backend must serve a file-store download without handing each
// request a copy of its own.
func blobViewer(t *testing.T, b store.Backend) store.BlobViewer {
	t.Helper()
	v, ok := b.(store.BlobViewer)
	if !ok {
		t.Fatalf("%T does not implement store.BlobViewer", b)
	}
	return v
}

func viewBlob(t *testing.T, v store.BlobViewer, org, sum string) ([]byte, func(), bool) {
	t.Helper()
	data, release, ok, err := v.ViewBlob(org, sum)
	if err != nil {
		t.Fatalf("ViewBlob(%q, %q): %v", org, sum, err)
	}
	if release == nil {
		t.Fatalf("ViewBlob(%q, %q) returned a nil release", org, sum)
	}
	return data, release, ok
}

func sameArray(a, b []byte) bool {
	return len(a) > 0 && len(b) > 0 && &a[0] == &b[0]
}

// testBlobViewShared pins that concurrent views of one blob share a single
// copy, so N downloads of a large file hold it in memory once, not N times.
func testBlobViewShared(t *testing.T, b store.Backend) {
	v := blobViewer(t, b)
	if _, release, ok := viewBlob(t, v, "acme", "big"); ok {
		t.Fatal("ViewBlob of a missing blob reported ok")
	} else {
		release()
	}
	if err := b.PutBlob("acme", "big", []byte("file content")); err != nil {
		t.Fatal(err)
	}

	const n = 8
	views := make([][]byte, n)
	releases := make([]func(), n)
	first, firstRelease, ok := viewBlob(t, v, "acme", "big")
	if !ok || string(first) != "file content" {
		t.Fatalf("ViewBlob = %q, ok=%v", first, ok)
	}
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, release, _, err := v.ViewBlob("acme", "big")
			if err != nil {
				t.Error(err)
				return
			}
			views[i], releases[i] = data, release
		}()
	}
	wg.Wait()
	for i, data := range views {
		if string(data) != "file content" {
			t.Fatalf("view %d = %q", i, data)
		}
		if !sameArray(first, data) {
			t.Errorf("view %d holds its own copy of the blob; want one shared copy", i)
		}
	}
	for _, release := range releases {
		if release != nil {
			release()
		}
	}
	firstRelease()
}

// testBlobViewColdStart pins that views racing to read a blob nobody holds
// yet still end up with one copy between them.
func testBlobViewColdStart(t *testing.T, b store.Backend) {
	v := blobViewer(t, b)
	if err := b.PutBlob("acme", "cold", []byte("file content")); err != nil {
		t.Fatal(err)
	}
	const n = 8
	views := make([][]byte, n)
	releases := make([]func(), n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			data, release, _, err := v.ViewBlob("acme", "cold")
			if err != nil {
				t.Error(err)
				return
			}
			views[i], releases[i] = data, release
		}()
	}
	close(start)
	wg.Wait()
	for i, data := range views {
		if string(data) != "file content" {
			t.Fatalf("view %d = %q", i, data)
		}
		if !sameArray(views[0], data) {
			t.Errorf("view %d holds its own copy of the blob; want one shared copy", i)
		}
	}
	for _, release := range releases {
		if release != nil {
			release()
		}
	}
}

// testBlobViewFollowsWrites pins that a view held across a write does not
// keep serving what the write replaced: a later view sees the overwrite, the
// delete, or the dropped organization, while the held view keeps its bytes.
func testBlobViewFollowsWrites(t *testing.T, b store.Backend) {
	v := blobViewer(t, b)
	if err := b.PutBlob("acme", "c", []byte("one")); err != nil {
		t.Fatal(err)
	}
	held, release, _ := viewBlob(t, v, "acme", "c")
	defer release()

	if err := b.PutBlob("acme", "c", []byte("two")); err != nil {
		t.Fatal(err)
	}
	// Held across the transaction below, so a shared read of "two" is live
	// when the transaction overwrites it.
	two, releaseTwo, ok := viewBlob(t, v, "acme", "c")
	defer releaseTwo()
	if !ok || string(two) != "two" {
		t.Fatalf("view after overwrite = %q, ok=%v; want \"two\"", two, ok)
	}

	if err := b.Tx(func(tx store.Backend) error { return tx.PutBlob("acme", "c", []byte("three")) }); err != nil {
		t.Fatal(err)
	}
	if got, rel, ok := viewBlob(t, v, "acme", "c"); !ok || string(got) != "three" {
		t.Fatalf("view after a transaction's overwrite = %q, ok=%v; want \"three\"", got, ok)
	} else {
		rel()
	}

	held2, release2, _ := viewBlob(t, v, "acme", "c")
	defer release2()
	if err := b.DeleteBlob("acme", "c"); err != nil {
		t.Fatal(err)
	}
	if _, rel, ok := viewBlob(t, v, "acme", "c"); ok {
		t.Fatal("view after DeleteBlob reported ok")
	} else {
		rel()
	}

	if err := b.PutBlob("acme", "d", []byte("four")); err != nil {
		t.Fatal(err)
	}
	held3, release3, _ := viewBlob(t, v, "acme", "d")
	defer release3()
	if _, err := b.DeleteOrg("acme"); err != nil {
		t.Fatal(err)
	}
	if err := b.CreateOrg("acme"); err != nil {
		t.Fatal(err)
	}
	if _, rel, ok := viewBlob(t, v, "acme", "d"); ok {
		t.Fatal("view after DeleteOrg reported ok")
	} else {
		rel()
	}

	if string(held) != "one" || string(held2) != "three" || string(held3) != "four" {
		t.Fatalf("held views changed under writes: %q %q %q", held, held2, held3)
	}
}
