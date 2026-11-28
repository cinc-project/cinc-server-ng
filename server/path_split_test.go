package server

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"testing"
)

// The auth layer and the router must read a request path the same way. A
// trailing escaped slash (%2F) is part of the last segment, not a separator:
// trimming it from the decoded path but not the escaped one would let the
// auth layer see one path (no file-store shape, so verify a signature) and the
// router another (the file store, which trusts the auth layer's grant check).
func TestFileStoreEscapedTrailingSlashNeedsAGrant(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	const content = "cookbook file body"
	sum := md5.Sum([]byte(content))
	checksum := hex.EncodeToString(sum[:])

	// Baseline: the issued grant works, unsigned or signed as chef-client's
	// ServerAPI signs it, and with a plain trailing slash.
	uploadURL := sandboxUploadURL(t, srv, checksum)
	if code, body := rawRequest(t, "PUT", uploadURL, content); code != http.StatusOK {
		t.Fatalf("upload with grant = %d, want 200: %s", code, body)
	}
	if code := statusOf(t, signed(t, srv, "PUT", uploadURL, content)); code != http.StatusOK {
		t.Fatalf("signed upload with grant = %d, want 200", code)
	}
	download := grantedDownloadURL(t, srv, "acme", checksum)
	if code, body := rawRequest(t, "GET", download, ""); code != http.StatusOK || string(body) != content {
		t.Fatalf("download with grant = %d %q, want 200", code, body)
	}
	slashed := base + "/file_store/" + checksum + "/?" + download[len(base+"/file_store/"+checksum+"?"):]
	if code, _ := rawRequest(t, "GET", slashed, ""); code != http.StatusOK {
		t.Fatalf("download with grant, trailing slash = %d, want 200", code)
	}
	// Baseline: a signed request without a grant is refused.
	if code := statusOf(t, signed(t, srv, "GET", base+"/file_store/"+checksum, "")); code != http.StatusUnauthorized {
		t.Fatalf("signed download without a grant = %d, want 401", code)
	}

	// The same, with the path ending in an escaped slash.
	for _, path := range []string{
		"/file_store/" + checksum + "%2F",
		"/file_store/" + checksum + "%2f",
		"/file_store/" + checksum + "%2F/",
		"/file_store/" + checksum + "/%2F",
		"/file_store%2F" + checksum + "%2F",
		"/file_store%2F" + checksum + "%2F/",
	} {
		if code := statusOf(t, signed(t, srv, "GET", base+path, "")); code == http.StatusOK {
			t.Errorf("signed download without a grant at %s = 200, want refused", path)
		}
	}

	const other = "another cookbook file body"
	otherSum := md5.Sum([]byte(other))
	otherChecksum := hex.EncodeToString(otherSum[:])
	for _, path := range []string{
		"/file_store/" + otherChecksum + "/%2F",
		"/file_store%2F" + otherChecksum + "%2F",
	} {
		if code := statusOf(t, signed(t, srv, "PUT", base+path, other)); code == http.StatusOK {
			t.Errorf("signed upload without a grant at %s = 200, want refused", path)
		}
	}
	org, _, err := srv.store.Org("acme")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := org.HasBlob(otherChecksum); err != nil || ok {
		t.Fatalf("blob stored without a grant (ok=%v, err=%v)", ok, err)
	}
}

// /_stats is authenticated with HTTP Basic, not a signature, and a trailing
// slash routes to the same handler: it must demand the same credentials.
func TestStatsTrailingSlashRequiresBasicAuth(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, StatsUser: "prom", StatsPassword: "pw"})

	// Baseline: the exact path refuses a signature and takes Basic.
	if code := statusOf(t, signed(t, srv, "GET", srv.URL()+"/_stats", "")); code != http.StatusUnauthorized {
		t.Fatalf("signed /_stats = %d, want 401", code)
	}
	for _, path := range []string{"/_stats", "/_stats/", "/_stats//"} {
		req, _ := http.NewRequest("GET", srv.URL()+path, nil)
		req.SetBasicAuth("prom", "pw")
		if code := statusOf(t, req); code != http.StatusOK {
			t.Errorf("Basic %s = %d, want 200", path, code)
		}
		if code := statusOf(t, signed(t, srv, "GET", srv.URL()+path, "")); code != http.StatusUnauthorized {
			t.Errorf("signed %s = %d, want 401", path, code)
		}
	}
}

// Trimming a trailing slash keeps the escaped and decoded paths in step, so
// an escaped slash inside a name still names the same object.
func TestTrailingSlashKeepsEscapedSegments(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	if code := statusOf(t, signed(t, srv, "POST", base+"/nodes/", `{"name":"web01"}`)); code != http.StatusCreated {
		t.Fatalf("create node at /nodes/ = %d, want 201", code)
	}
	for _, path := range []string{"/nodes/", "/nodes/web01/", "/nodes/web01//", "/nodes/web%30%31/"} {
		if code := statusOf(t, signed(t, srv, "GET", base+path, "")); code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, code)
		}
	}
	// web01%2F is the node "web01/", which does not exist.
	if code := statusOf(t, signed(t, srv, "GET", base+"/nodes/web01%2F", "")); code != http.StatusNotFound {
		t.Errorf("GET /nodes/web01%%2F = %d, want 404", code)
	}
}
