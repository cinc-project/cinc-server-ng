package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCookbookArtifactsEmptyList(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, body := doAt(t, "2", "GET", base+"/cookbook_artifacts", "")
	if resp.StatusCode != 200 {
		t.Fatalf("empty list = %d, want 200: %s", resp.StatusCode, body)
	}
	if strings.TrimSpace(body) != "{}" {
		t.Fatalf("empty list body = %q, want {}", body)
	}
}

func TestCookbookArtifactImmutableReupload(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	sum := uploadBlob(t, base, "package 'nginx'\n")
	const ident = "1234567890abcdef1234567890abcdef12345678"
	if resp, body := doAt(t, "2", "PUT", base+"/cookbook_artifacts/nginx/"+ident, manifest("nginx", "1.0.0", sum)); resp.StatusCode != 201 {
		t.Fatalf("first put = %d: %s", resp.StatusCode, body)
	}
	resp, body := doAt(t, "2", "PUT", base+"/cookbook_artifacts/nginx/"+ident, manifest("nginx", "1.0.0", sum))
	if resp.StatusCode != 409 {
		t.Fatalf("re-upload = %d, want 409: %s", resp.StatusCode, body)
	}
}

// uploadBlob pushes content into the file store so a manifest referencing its
// checksum will validate. Returns the checksum.
func uploadBlob(t *testing.T, base, content string) string {
	t.Helper()
	sum := md5hex(content)
	resp, body := doAt(t, "2", "PUT", base+"/file_store/"+sum, content)
	if resp.StatusCode != 200 {
		t.Fatalf("upload blob = %d: %s", resp.StatusCode, body)
	}
	return sum
}

func TestCookbookArtifactLifecycle(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	sum := uploadBlob(t, base, "package 'nginx'\n")
	const ident = "1234567890abcdef1234567890abcdef12345678"

	// PUT the artifact under an opaque identifier.
	resp, body := doAt(t, "2", "PUT", base+"/cookbook_artifacts/nginx/"+ident, manifest("nginx", "1.0.0", sum))
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		t.Fatalf("put artifact = %d: %s", resp.StatusCode, body)
	}

	// List exposes the artifact keyed by identifier (not version).
	_, body = doAt(t, "2", "GET", base+"/cookbook_artifacts", "")
	var list map[string]struct {
		URL      string `json:"url"`
		Versions []struct {
			URL        string `json:"url"`
			Identifier string `json:"identifier"`
		} `json:"versions"`
	}
	json.Unmarshal([]byte(body), &list)
	if len(list["nginx"].Versions) != 1 || list["nginx"].Versions[0].Identifier != ident {
		t.Fatalf("artifact list = %s", body)
	}

	// GET the artifact: file URLs injected from the shared blob store.
	_, body = doAt(t, "2", "GET", base+"/cookbook_artifacts/nginx/"+ident, "")
	var cb map[string]any
	json.Unmarshal([]byte(body), &cb)
	files, _ := cb["all_files"].([]any)
	if len(files) != 1 {
		t.Fatalf("artifact all_files = %s", body)
	}
	if url, _ := files[0].(map[string]any)["url"].(string); url == "" {
		t.Fatalf("artifact file url not injected: %s", body)
	}

	// GET single artifact by name.
	resp, body = doAt(t, "2", "GET", base+"/cookbook_artifacts/nginx", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get artifact by name = %d: %s", resp.StatusCode, body)
	}

	// Delete it.
	resp, _ = doAt(t, "2", "DELETE", base+"/cookbook_artifacts/nginx/"+ident, "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete artifact = %d", resp.StatusCode)
	}
	resp, _ = doAt(t, "2", "GET", base+"/cookbook_artifacts/nginx/"+ident, "")
	if resp.StatusCode != 404 {
		t.Fatalf("get deleted artifact = %d", resp.StatusCode)
	}
}

func TestCookbookArtifactMissingChecksum(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, body := doAt(t, "2", "PUT", base+"/cookbook_artifacts/nginx/abc", manifest("nginx", "1.0.0", md5hex("nope")))
	if resp.StatusCode != 400 {
		t.Fatalf("artifact with missing checksum = %d, want 400: %s", resp.StatusCode, body)
	}
}

func TestCookbookArtifactMissing404(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	resp, _ := doAt(t, "2", "GET", base+"/cookbook_artifacts/ghost", "")
	if resp.StatusCode != 404 {
		t.Fatalf("missing artifact = %d, want 404", resp.StatusCode)
	}
	resp, _ = doAt(t, "2", "GET", base+"/cookbook_artifacts/ghost/abc", "")
	if resp.StatusCode != 404 {
		t.Fatalf("missing artifact identifier = %d, want 404", resp.StatusCode)
	}
}

func TestUniverse(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"

	sum := uploadBlob(t, base, "package 'nginx'\n")
	// A manifest whose metadata declares a dependency.
	m := `{
		"cookbook_name": "nginx",
		"version": "1.0.0",
		"metadata": {"name": "nginx", "version": "1.0.0", "dependencies": {"apt": ">= 2.0.0"}},
		"all_files": [
			{"name": "recipes/default.rb", "path": "recipes/default.rb", "checksum": "` + sum + `", "specificity": "default"}
		]
	}`
	if resp, body := doAt(t, "2", "PUT", base+"/cookbooks/nginx/1.0.0", m); resp.StatusCode >= 300 {
		t.Fatalf("put cookbook = %d: %s", resp.StatusCode, body)
	}

	_, body := doAt(t, "2", "GET", base+"/universe", "")
	var universe map[string]map[string]struct {
		LocationType string         `json:"location_type"`
		LocationPath string         `json:"location_path"`
		DownloadURL  string         `json:"download_url"`
		Dependencies map[string]any `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(body), &universe); err != nil {
		t.Fatalf("decode universe: %v (%s)", err, body)
	}
	entry, ok := universe["nginx"]["1.0.0"]
	if !ok {
		t.Fatalf("universe missing nginx 1.0.0: %s", body)
	}
	if entry.LocationType != "chef_server" || entry.DownloadURL == "" {
		t.Fatalf("universe entry = %+v", entry)
	}
	if entry.Dependencies["apt"] != ">= 2.0.0" {
		t.Fatalf("universe dependencies = %+v", entry.Dependencies)
	}
}
