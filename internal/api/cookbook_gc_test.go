package api

import (
	"net/http"
	"testing"
)

// Deleting a cookbook version garbage-collects the file bodies it was the last
// reference to. Overwriting one has to as well: it drops exactly the same
// references, so without it every re-upload of a cookbook leaks the bodies of
// the files that changed, for the lifetime of the store.
func TestOverwritingACookbookVersionCollectsOrphanedBlobs(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	const oldContent = "package 'nginx'\n"
	const newContent = "package 'nginx'\nservice 'nginx'\n"
	oldSum, newSum := md5hex(oldContent), md5hex(newContent)

	for content, sum := range map[string]string{oldContent: oldSum, newContent: newSum} {
		if resp, body := do(t, "PUT", base+"/file_store/"+sum, content); resp.StatusCode != http.StatusOK {
			t.Fatalf("upload = %d: %s", resp.StatusCode, body)
		}
	}
	if resp, body := do(t, "PUT", base+"/cookbooks/nginx/1.0.0",
		manifest("nginx", "1.0.0", oldSum)); resp.StatusCode >= 300 {
		t.Fatalf("first put = %d: %s", resp.StatusCode, body)
	}
	// Re-upload the same version with different content, as `knife upload` does
	// after an edit.
	if resp, body := do(t, "PUT", base+"/cookbooks/nginx/1.0.0",
		manifest("nginx", "1.0.0", newSum)); resp.StatusCode >= 300 {
		t.Fatalf("second put = %d: %s", resp.StatusCode, body)
	}

	if resp, _ := do(t, "GET", base+"/file_store/"+newSum, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("the current file body is gone = %d, want 200", resp.StatusCode)
	}
	if resp, _ := do(t, "GET", base+"/file_store/"+oldSum, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("the replaced file body survived the overwrite = %d, want 404", resp.StatusCode)
	}
}

// Content shared with another version must survive the overwrite: the blob store
// is content-addressed, so two versions of a cookbook routinely reference the
// same unchanged file.
func TestOverwriteKeepsBlobsSharedWithAnotherVersion(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	const shared = "package 'nginx'\n"
	const replacement = "service 'nginx'\n"
	sharedSum, newSum := md5hex(shared), md5hex(replacement)

	for content, sum := range map[string]string{shared: sharedSum, replacement: newSum} {
		if resp, _ := do(t, "PUT", base+"/file_store/"+sum, content); resp.StatusCode != http.StatusOK {
			t.Fatalf("upload %s failed", sum)
		}
	}
	// Two versions reference the same file body.
	for _, v := range []string{"1.0.0", "2.0.0"} {
		if resp, body := do(t, "PUT", base+"/cookbooks/nginx/"+v,
			manifest("nginx", v, sharedSum)); resp.StatusCode >= 300 {
			t.Fatalf("put %s = %d: %s", v, resp.StatusCode, body)
		}
	}
	// Overwrite one of them to point elsewhere.
	if resp, body := do(t, "PUT", base+"/cookbooks/nginx/1.0.0",
		manifest("nginx", "1.0.0", newSum)); resp.StatusCode >= 300 {
		t.Fatalf("overwrite = %d: %s", resp.StatusCode, body)
	}
	if resp, _ := do(t, "GET", base+"/file_store/"+sharedSum, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("a body still referenced by 2.0.0 was collected = %d, want 200", resp.StatusCode)
	}
}
