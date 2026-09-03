package server

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cinc-project/cinc-server-ng/internal/auth"
)

// The cookbook file store is exempt from Mixlib signing because real clients
// fetch and upload cookbook bodies at a URL the server hands them. The URL must
// therefore carry its own authorization rather than leaving the endpoint open.

// rawRequest issues an unsigned request, the way a client uses a file-store URL.
func rawRequest(t *testing.T, method, url, body string) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func TestFileStoreRejectsUnsignedRequests(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	const content = "cookbook file body"
	sum := md5.Sum([]byte(content))
	url := srv.URL() + "/organizations/acme/file_store/" + hex.EncodeToString(sum[:])

	if code, body := rawRequest(t, "PUT", url, content); code != http.StatusUnauthorized {
		t.Fatalf("unsigned upload = %d, want 401: %s", code, body)
	}
	if code, body := rawRequest(t, "GET", url, ""); code != http.StatusUnauthorized {
		t.Fatalf("unsigned download = %d, want 401: %s", code, body)
	}
}

// A download grant must not be usable to overwrite the object it points at.
func TestFileStoreGrantIsScopedToItsOperation(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}})
	const content = "cookbook file body"
	sum := md5.Sum([]byte(content))
	checksum := hex.EncodeToString(sum[:])

	uploadURL := sandboxUploadURL(t, srv, checksum)
	if code, body := rawRequest(t, "PUT", uploadURL, content); code != http.StatusOK {
		t.Fatalf("signed upload = %d, want 200: %s", code, body)
	}
	// An upload grant is not a download grant.
	if code, _ := rawRequest(t, "GET", uploadURL, ""); code != http.StatusUnauthorized {
		t.Fatalf("upload grant replayed as download = %d, want 401", code)
	}
	// Nor does it authorize a different checksum.
	other := strings.Repeat("0", 32)
	swapped := strings.Replace(uploadURL, checksum, other, 1)
	if code, _ := rawRequest(t, "PUT", swapped, ""); code != http.StatusUnauthorized {
		t.Fatalf("grant reused for another checksum = %d, want 401", code)
	}
}

// grantedDownloadURL mints a download grant with the server's own key, for
// tests that need to read a blob back without publishing a cookbook manifest
// to obtain the URL. That the server itself issues usable download URLs is
// covered end to end by TestCookbookRoundTripThroughSignedFileStore.
func grantedDownloadURL(t *testing.T, srv *Server, org, checksum string) string {
	t.Helper()
	q := auth.FileStoreQuery(srv.fileStoreKey, org, checksum, auth.FileStoreGet, time.Now().Add(time.Minute))
	return srv.URL() + "/organizations/" + org + "/file_store/" + checksum + "?" + q
}

// sandboxUploadURL runs the sandbox handshake as the admin and returns the
// upload URL the server issued for checksum.
func sandboxUploadURL(t *testing.T, srv *Server, checksum string) string {
	t.Helper()
	body := `{"checksums":{"` + checksum + `":null}}`
	resp, err := http.DefaultClient.Do(signed(t, srv, "POST", srv.URL()+"/organizations/acme/sandboxes", body))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create sandbox = %d: %s", resp.StatusCode, raw)
	}
	var doc struct {
		Checksums map[string]struct {
			URL         string `json:"url"`
			NeedsUpload bool   `json:"needs_upload"`
		} `json:"checksums"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode sandbox: %v: %s", err, raw)
	}
	entry, ok := doc.Checksums[checksum]
	if !ok || !entry.NeedsUpload || entry.URL == "" {
		t.Fatalf("sandbox did not offer an upload URL for %s: %s", checksum, raw)
	}
	return entry.URL
}

// The whole Chef cookbook upload/download flow must still work end to end using
// only the URLs the server hands out, unsigned, exactly as knife and
// chef-client use them.
func TestCookbookRoundTripThroughSignedFileStore(t *testing.T) {
	srv := startServer(t, Options{Orgs: []string{"acme"}, EnforceACL: true})
	base := srv.URL() + "/organizations/acme"
	const recipe = "package 'nginx'\n"
	sum := md5.Sum([]byte(recipe))
	checksum := hex.EncodeToString(sum[:])

	// 1. Announce the checksum and upload the body to the URL we were given.
	uploadURL := sandboxUploadURL(t, srv, checksum)
	if code, body := rawRequest(t, "PUT", uploadURL, recipe); code != http.StatusOK {
		t.Fatalf("upload = %d, want 200: %s", code, body)
	}

	// 2. Publish a manifest referencing the uploaded checksum.
	manifest := `{"name":"nginx-1.0.0","cookbook_name":"nginx","version":"1.0.0",` +
		`"all_files":[{"name":"recipes/default.rb","path":"recipes/default.rb","checksum":"` + checksum + `","specificity":"default"}]}`
	if code := statusOf(t, signed(t, srv, "PUT", base+"/cookbooks/nginx/1.0.0", manifest)); code != http.StatusCreated {
		t.Fatalf("publish cookbook = %d, want 201", code)
	}

	// 3. Read the cookbook back and follow the download URL it advertises.
	resp, err := http.DefaultClient.Do(signed(t, srv, "GET", base+"/cookbooks/nginx/1.0.0", ""))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var cookbook struct {
		AllFiles []struct {
			URL string `json:"url"`
		} `json:"all_files"`
	}
	if err := json.Unmarshal(raw, &cookbook); err != nil || len(cookbook.AllFiles) != 1 {
		t.Fatalf("decode cookbook: %v: %s", err, raw)
	}
	code, body := rawRequest(t, "GET", cookbook.AllFiles[0].URL, "")
	if code != http.StatusOK {
		t.Fatalf("download = %d, want 200: %s", code, body)
	}
	if string(body) != recipe {
		t.Fatalf("downloaded %q, want %q", body, recipe)
	}
}
