package api

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// manifest builds a minimal modern ("all_files") cookbook manifest referencing
// a single default recipe whose content hashes to checksum.
func manifest(name, version, checksum string) string {
	return fmt.Sprintf(`{
		"name": "%s-%s",
		"cookbook_name": "%s",
		"version": "%s",
		"metadata": {"name": "%s", "version": "%s", "dependencies": {}},
		"all_files": [
			{"name": "recipes/default.rb", "path": "recipes/default.rb", "checksum": "%s", "specificity": "default"}
		]
	}`, name, version, name, version, name, version, checksum)
}

func TestCookbookLifecycle(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	content := "package 'nginx'\n"
	sum := md5hex(content)

	// 1. POST /sandboxes announces the checksum; it needs upload.
	resp, body := do(t, "POST", base+"/sandboxes", fmt.Sprintf(`{"checksums":{"%s":null}}`, sum))
	if resp.StatusCode != 201 {
		t.Fatalf("create sandbox = %d: %s", resp.StatusCode, body)
	}
	var sb struct {
		SandboxID string `json:"sandbox_id"`
		Checksums map[string]struct {
			URL         string `json:"url"`
			NeedsUpload bool   `json:"needs_upload"`
		} `json:"checksums"`
	}
	if err := json.Unmarshal([]byte(body), &sb); err != nil {
		t.Fatalf("decode sandbox: %v (%s)", err, body)
	}
	entry, ok := sb.Checksums[sum]
	if !ok || !entry.NeedsUpload || entry.URL == "" {
		t.Fatalf("sandbox checksum entry = %+v", sb.Checksums)
	}

	// 2. Upload the file content to the returned URL.
	resp, body = do(t, "PUT", entry.URL, content)
	if resp.StatusCode != 200 {
		t.Fatalf("upload file = %d: %s", resp.StatusCode, body)
	}

	// 3. Commit the sandbox.
	resp, body = do(t, "PUT", base+"/sandboxes/"+sb.SandboxID, `{"is_completed":true}`)
	if resp.StatusCode != 200 {
		t.Fatalf("commit sandbox = %d: %s", resp.StatusCode, body)
	}

	// 4. A fresh sandbox for the same checksum no longer needs upload.
	_, body = do(t, "POST", base+"/sandboxes", fmt.Sprintf(`{"checksums":{"%s":null}}`, sum))
	json.Unmarshal([]byte(body), &sb)
	if sb.Checksums[sum].NeedsUpload {
		t.Fatalf("checksum still needs upload after commit: %s", body)
	}

	// 5. PUT the cookbook version.
	resp, body = do(t, "PUT", base+"/cookbooks/nginx/1.0.0", manifest("nginx", "1.0.0", sum))
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		t.Fatalf("put cookbook = %d: %s", resp.StatusCode, body)
	}

	// 6. It appears in the cookbook list with its version.
	_, body = do(t, "GET", base+"/cookbooks", "")
	var list map[string]struct {
		URL      string `json:"url"`
		Versions []struct {
			URL     string `json:"url"`
			Version string `json:"version"`
		} `json:"versions"`
	}
	json.Unmarshal([]byte(body), &list)
	if len(list["nginx"].Versions) != 1 || list["nginx"].Versions[0].Version != "1.0.0" {
		t.Fatalf("cookbook list = %s", body)
	}

	// 7. GET the version: the file entry gets a download URL injected.
	_, body = do(t, "GET", base+"/cookbooks/nginx/1.0.0", "")
	var cb map[string]any
	json.Unmarshal([]byte(body), &cb)
	files, _ := cb["all_files"].([]any)
	if len(files) != 1 {
		t.Fatalf("manifest all_files = %s", body)
	}
	fileURL, _ := files[0].(map[string]any)["url"].(string)
	if fileURL == "" {
		t.Fatalf("file url not injected: %s", body)
	}

	// 8. The injected URL serves the original content.
	resp, got := do(t, "GET", fileURL, "")
	if resp.StatusCode != 200 || got != content {
		t.Fatalf("download = %d %q; want %q", resp.StatusCode, got, content)
	}

	// 9. Add a newer version; _latest points to it.
	do(t, "PUT", base+"/cookbooks/nginx/2.0.0", manifest("nginx", "2.0.0", sum))
	_, body = do(t, "GET", base+"/cookbooks/_latest", "")
	var latest map[string]string
	json.Unmarshal([]byte(body), &latest)
	if latest["nginx"] == "" || !strings.Contains(latest["nginx"], "/cookbooks/nginx/2.0.0") {
		t.Fatalf("_latest = %s", body)
	}

	// 10. _recipes lists the default recipe by bare cookbook name.
	_, body = do(t, "GET", base+"/cookbooks/_recipes", "")
	var recipes []string
	json.Unmarshal([]byte(body), &recipes)
	if !slices.Contains(recipes, "nginx") {
		t.Fatalf("_recipes = %s", body)
	}

	// 11. GET _latest via the version alias returns the 2.0.0 manifest.
	_, body = do(t, "GET", base+"/cookbooks/nginx/_latest", "")
	json.Unmarshal([]byte(body), &cb)
	if cb["version"] != "2.0.0" {
		t.Fatalf("_latest manifest = %s", body)
	}

	// 12. Delete 1.0.0; only 2.0.0 remains.
	resp, _ = do(t, "DELETE", base+"/cookbooks/nginx/1.0.0", "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete cookbook = %d", resp.StatusCode)
	}
	resp, _ = do(t, "GET", base+"/cookbooks/nginx/1.0.0", "")
	if resp.StatusCode != 404 {
		t.Fatalf("get deleted version = %d", resp.StatusCode)
	}
	resp, _ = do(t, "GET", base+"/cookbooks/nginx/2.0.0", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get surviving version = %d", resp.StatusCode)
	}
}

func TestCookbookPutMissingChecksum(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	// Reference a checksum that was never uploaded.
	resp, body := do(t, "PUT", base+"/cookbooks/nginx/1.0.0", manifest("nginx", "1.0.0", md5hex("never uploaded")))
	if resp.StatusCode != 400 {
		t.Fatalf("put with missing checksum = %d, want 400: %s", resp.StatusCode, body)
	}
}

// erchef (chef_cookbook_version:validate_cookbook) checks the URL name against
// chef_regex's cookbook_name rule (letters, digits, '.', '_', '-'), and
// metadata.name and the keys of metadata.dependencies and metadata.platforms
// against the same rule, answering 400 and storing nothing otherwise.
func TestCookbookPutRejectsInvalidNames(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	body := func(name, meta string) string {
		return fmt.Sprintf(`{"name":"%s-1.0.0","cookbook_name":"%s","version":"1.0.0","metadata":%s,"all_files":[]}`, name, name, meta)
	}
	cases := []struct {
		url, body, want string
	}{
		{"bad@name", body("bad@name", `{"name":"bad@name","version":"1.0.0"}`),
			"Invalid cookbook name 'bad@name' using regex: 'Malformed cookbook name. Must only contain A-Z, a-z, 0-9, _, . or -'."},
		{"bad!name", body("bad!name", `{"version":"1.0.0"}`), "Invalid cookbook name 'bad!name'"},
		{"good", body("good", `{"name":"bad@meta","version":"1.0.0"}`), "Field 'metadata.name' invalid"},
		{"good", body("good", `{"name":"good","version":"1.0.0","dependencies":{"dep@bad":">= 0.0.0"}}`),
			"Invalid key 'dep@bad' for metadata.dependencies"},
		{"good", body("good", `{"name":"good","version":"1.0.0","platforms":{"ubu ntu":">= 0.0.0"}}`),
			"Invalid key 'ubu ntu' for metadata.platforms"},
	}
	for _, c := range cases {
		resp, out := do(t, "PUT", base+"/cookbooks/"+c.url+"/1.0.0", c.body)
		if resp.StatusCode != 400 || !strings.Contains(out, c.want) {
			t.Errorf("PUT %s %s = %d %s, want 400 %q", c.url, c.body, resp.StatusCode, out, c.want)
		}
	}
	if _, out := do(t, "GET", base+"/cookbooks", ""); strings.TrimSpace(out) != "{}" {
		t.Errorf("refused cookbooks were stored: %s", out)
	}

	ok := body("good_1.x-y", `{"name":"good_1.x-y","version":"1.0.0","dependencies":{"dep.ok_1-2":">= 0.0.0"},"platforms":{"ubuntu":">= 0.0.0"}}`)
	if resp, out := do(t, "PUT", base+"/cookbooks/good_1.x-y/1.0.0", ok); resp.StatusCode != 201 {
		t.Errorf("valid cookbook = %d %s, want 201", resp.StatusCode, out)
	}
}

func TestCookbookGetMissing404(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, _ := do(t, "GET", base+"/cookbooks/ghost", "")
	if resp.StatusCode != 404 {
		t.Fatalf("missing cookbook = %d, want 404", resp.StatusCode)
	}
	resp, _ = do(t, "GET", base+"/cookbooks/ghost/1.0.0", "")
	if resp.StatusCode != 404 {
		t.Fatalf("missing version = %d, want 404", resp.StatusCode)
	}
}

func TestFileStoreChecksumMismatch(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	// PUT content under a checksum that does not match it.
	resp, _ := do(t, "PUT", base+"/file_store/"+md5hex("real"), "different content")
	if resp.StatusCode != 400 {
		t.Fatalf("checksum mismatch = %d, want 400", resp.StatusCode)
	}
}
