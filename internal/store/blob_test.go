package store

import (
	"bytes"
	"testing"
)

func TestBlobStore(t *testing.T) {
	st := New()
	org, err := st.CreateOrg("acme")
	if err != nil {
		t.Fatal(err)
	}

	if has, err := org.HasBlob("abc123"); err != nil || has {
		t.Fatalf("blob should not exist yet: has=%v err=%v", has, err)
	}
	if _, ok, err := org.Blob("abc123"); err != nil || ok {
		t.Fatalf("Blob returned ok for missing checksum: ok=%v err=%v", ok, err)
	}

	content := []byte("file content\n")
	if err := org.PutBlob("abc123", content); err != nil {
		t.Fatal(err)
	}

	if has, err := org.HasBlob("abc123"); err != nil || !has {
		t.Fatalf("blob should exist after PutBlob: has=%v err=%v", has, err)
	}
	got, ok, err := org.Blob("abc123")
	if err != nil || !ok || !bytes.Equal(got, content) {
		t.Fatalf("Blob = %q, ok=%v err=%v; want %q", got, ok, err, content)
	}

	// Stored value is a defensive copy: mutating the input must not change it.
	content[0] = 'X'
	got, _, _ = org.Blob("abc123")
	if got[0] == 'X' {
		t.Fatal("PutBlob did not copy input")
	}
	// And mutating the returned slice must not change the stored value.
	got[1] = 'Y'
	again, _, _ := org.Blob("abc123")
	if again[1] == 'Y' {
		t.Fatal("Blob did not return a copy")
	}

	// Blobs are org-scoped.
	other, _ := st.CreateOrg("other")
	if has, _ := other.HasBlob("abc123"); has {
		t.Fatal("blobs leaked across orgs")
	}
}

// TestBlobViewLendsStoredBlob pins that a file-store read does not copy the
// blob on the memory backend: every view lends the stored bytes, so concurrent
// downloads of a large file cost no memory beyond the stored copy.
func TestBlobViewLendsStoredBlob(t *testing.T) {
	st := New()
	org, _ := st.CreateOrg("acme")
	if err := org.PutBlob("abc123", []byte("file content\n")); err != nil {
		t.Fatal(err)
	}

	got, release, ok, err := org.BlobView("abc123")
	if err != nil || !ok || string(got) != "file content\n" {
		t.Fatalf("BlobView = %q, ok=%v err=%v", got, ok, err)
	}
	defer release()
	again, release2, _, _ := org.BlobView("abc123")
	defer release2()
	if &got[0] != &again[0] {
		t.Fatal("BlobView copied the stored blob; want it lent")
	}
	if _, rel, ok, _ := org.BlobView("missing"); ok {
		t.Fatal("BlobView of missing checksum should report false")
	} else {
		rel()
	}
}
