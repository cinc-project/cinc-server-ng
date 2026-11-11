package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// frozenManifest is manifest with "frozen?" set, as `knife cookbook upload
// --freeze` sends it.
func frozenManifest(name, version, checksum string, frozen bool) string {
	m := manifest(name, version, checksum)
	flag := `"frozen?": false,`
	if frozen {
		flag = `"frozen?": true,`
	}
	return strings.Replace(m, "{", "{"+flag, 1)
}

func frozenFlag(t *testing.T, body string) bool {
	t.Helper()
	var doc struct {
		Frozen bool `json:"frozen?"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return doc.Frozen
}

// erchef refuses to overwrite a frozen cookbook version with 409 unless the
// request carries ?force (any value but "false"), and "frozen?" can never be
// cleared once set (chef_wm_cookbook_version.erl is_conflict/from_json).
func TestFrozenCookbookVersionRefusesOverwrite(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	url := base + "/cookbooks/nginx/1.0.0"

	const content = "package 'nginx'\n"
	sum := md5hex(content)
	if resp, body := doAt(t, "2", "PUT", base+"/file_store/"+sum, content); resp.StatusCode != http.StatusOK {
		t.Fatalf("upload = %d: %s", resp.StatusCode, body)
	}

	// Baseline: an unfrozen version is overwritable.
	if resp, body := doAt(t, "2", "PUT", url, frozenManifest("nginx", "1.0.0", sum, false)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	if resp, body := doAt(t, "2", "PUT", url, frozenManifest("nginx", "1.0.0", sum, true)); resp.StatusCode != http.StatusOK {
		t.Fatalf("freeze = %d: %s", resp.StatusCode, body)
	}

	for _, q := range []string{"", "?force=false"} {
		resp, body := doAt(t, "2", "PUT", url+q, frozenManifest("nginx", "1.0.0", sum, false))
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("PUT%s to a frozen version = %d, want 409: %s", q, resp.StatusCode, body)
		}
		const want = `{"error":["The cookbook nginx at version 1.0.0 is frozen. Use the 'force' option to override."]}`
		if strings.TrimSpace(body) != want {
			t.Errorf("PUT%s body = %s, want %s", q, body, want)
		}
	}
	if _, body := doAt(t, "2", "GET", url, ""); !frozenFlag(t, body) {
		t.Errorf("refused PUT unfroze the version: %s", body)
	}

	// Forced: the update applies, but "frozen?" stays true.
	for _, q := range []string{"?force=true", "?force=1"} {
		resp, body := doAt(t, "2", "PUT", url+q, frozenManifest("nginx", "1.0.0", sum, false))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT%s = %d, want 200: %s", q, resp.StatusCode, body)
		}
		if !frozenFlag(t, body) {
			t.Errorf("PUT%s response unfroze the version: %s", q, body)
		}
		if _, body := doAt(t, "2", "GET", url, ""); !frozenFlag(t, body) {
			t.Errorf("PUT%s unfroze the stored version: %s", q, body)
		}
	}
}
