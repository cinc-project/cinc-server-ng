package api

import (
	"net/http"
	"testing"
)

// fileStatus returns the status code of GET /file_store/<checksum>.
func fileStatus(t *testing.T, base, checksum string) int {
	t.Helper()
	resp, _ := do(t, "GET", base+"/file_store/"+checksum, "")
	return resp.StatusCode
}

// multiChecksumManifest builds a minimal manifest referencing several checksums,
// used to exercise shared/orphaned checksum behavior across versions.
func multiChecksumManifest(checksums ...string) string {
	return checksumManifest(`{"recipes":[`, checksums)
}

// cookbookChecksumManifest is multiChecksumManifest for a cookbook version,
// with the name, cookbook_name and metadata erchef requires of one.
func cookbookChecksumManifest(name, version string, checksums ...string) string {
	return checksumManifest(`{"name":"`+name+`-`+version+`","cookbook_name":"`+name+
		`","metadata":{"version":"`+version+`"},"recipes":[`, checksums)
}

func checksumManifest(body string, checksums []string) string {
	for i, c := range checksums {
		if i > 0 {
			body += ","
		}
		body += `{"name":"f` + c[:4] + `.rb","path":"recipes/f` + c[:4] + `.rb","checksum":"` + c + `","specificity":"default"}`
	}
	return body + `]}`
}

func TestCookbookDeleteGCsOrphanedChecksums(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	shared := uploadBlob(t, base, "shared file content")
	only1 := uploadBlob(t, base, "content only in v1")
	only2 := uploadBlob(t, base, "content only in v2")

	// Two versions: v1 references shared+only1, v2 references shared+only2.
	if resp, b := do(t, "PUT", base+"/cookbooks/apache2/1.0.0", cookbookChecksumManifest("apache2", "1.0.0", shared, only1)); resp.StatusCode != 201 {
		t.Fatalf("put v1 = %d: %s", resp.StatusCode, b)
	}
	if resp, b := do(t, "PUT", base+"/cookbooks/apache2/2.0.0", cookbookChecksumManifest("apache2", "2.0.0", shared, only2)); resp.StatusCode != 201 {
		t.Fatalf("put v2 = %d: %s", resp.StatusCode, b)
	}

	// Delete v1: only1 becomes orphaned; shared and only2 survive (still on v2).
	if resp, b := do(t, "DELETE", base+"/cookbooks/apache2/1.0.0", ""); resp.StatusCode != 200 {
		t.Fatalf("delete v1 = %d: %s", resp.StatusCode, b)
	}
	if got := fileStatus(t, base, only1); got != 404 {
		t.Fatalf("orphaned checksum status = %d, want 404", got)
	}
	if got := fileStatus(t, base, shared); got != 200 {
		t.Fatalf("shared checksum status = %d, want 200 (still referenced by v2)", got)
	}
	if got := fileStatus(t, base, only2); got != 200 {
		t.Fatalf("v2-only checksum status = %d, want 200", got)
	}
}

func TestArtifactDeleteGCsButKeepsCrossReferenced(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	crossRef := uploadBlob(t, base, "referenced by a cookbook too")
	artifactOnly := uploadBlob(t, base, "only in the artifact")

	// A cookbook and an artifact both reference crossRef.
	if resp, _ := do(t, "PUT", base+"/cookbooks/web/1.0.0", cookbookChecksumManifest("web", "1.0.0", crossRef)); resp.StatusCode != 201 {
		t.Fatalf("put cookbook failed")
	}
	if resp, b := do(t, "PUT", base+"/cookbook_artifacts/web/abc123", multiChecksumManifest(crossRef, artifactOnly)); resp.StatusCode != 201 {
		t.Fatalf("put artifact = %d: %s", resp.StatusCode, b)
	}

	// Delete the artifact: artifactOnly is orphaned, crossRef survives (cookbook).
	if resp, b := do(t, "DELETE", base+"/cookbook_artifacts/web/abc123", ""); resp.StatusCode != 200 {
		t.Fatalf("delete artifact = %d: %s", resp.StatusCode, b)
	}
	if got := fileStatus(t, base, artifactOnly); got != 404 {
		t.Fatalf("orphaned artifact checksum = %d, want 404", got)
	}
	if got := fileStatus(t, base, crossRef); got != 200 {
		t.Fatalf("cross-referenced checksum = %d, want 200 (still referenced by cookbook)", got)
	}
}

func TestArtifactIsImmutable(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	c := uploadBlob(t, base, "artifact content")

	if resp, b := do(t, "PUT", base+"/cookbook_artifacts/foo/id1", multiChecksumManifest(c)); resp.StatusCode != 201 {
		t.Fatalf("first artifact PUT = %d: %s", resp.StatusCode, b)
	}
	// Re-uploading the same identifier must conflict, not overwrite.
	resp, b := do(t, "PUT", base+"/cookbook_artifacts/foo/id1", multiChecksumManifest(c))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("re-PUT artifact = %d, want 409; body %s", resp.StatusCode, b)
	}
}

func TestEmptyArtifactListingIs200(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, body := do(t, "GET", base+"/cookbook_artifacts", "")
	if resp.StatusCode != 200 {
		t.Fatalf("empty artifact listing = %d, want 200", resp.StatusCode)
	}
	if body != "{}\n" && body != "{}" {
		t.Fatalf("empty artifact listing body = %q, want {}", body)
	}
}
