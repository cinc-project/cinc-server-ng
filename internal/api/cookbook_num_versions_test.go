package api

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// versionCounts decodes a "name -> {url, versions:[...]}" listing into
// name -> the versions it lists, in order.
func versionCounts(t *testing.T, body string) map[string][]string {
	t.Helper()
	var list map[string]struct {
		Versions []struct {
			Version string `json:"version"`
		} `json:"versions"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatalf("decode listing: %v (%s)", err, body)
	}
	out := map[string][]string{}
	for name, e := range list {
		vers := []string{}
		for _, v := range e.Versions {
			vers = append(vers, v.Version)
		}
		out[name] = vers
	}
	return out
}

func seedNumVersionsCookbooks(t *testing.T) string {
	t.Helper()
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	seedCookbook(t, base, "apache2", "1.0.0")
	seedCookbook(t, base, "apache2", "2.0.0")
	seedCookbook(t, base, "apache2", "10.0.0")
	seedCookbook(t, base, "nginx", "1.0.0")
	return base
}

// erchef (chef_wm_util:num_versions/2) lists only the newest version of each
// cookbook when num_versions is absent, on both the org-wide listing and an
// environment's listing; a single cookbook in an environment defaults to all.
func TestCookbookListingNumVersions(t *testing.T) {
	base := seedNumVersionsCookbooks(t)
	cases := []struct {
		path string
		want map[string][]string
	}{
		{"/cookbooks", map[string][]string{"apache2": {"10.0.0"}, "nginx": {"1.0.0"}}},
		{"/cookbooks?num_versions=all", map[string][]string{"apache2": {"10.0.0", "2.0.0", "1.0.0"}, "nginx": {"1.0.0"}}},
		{"/cookbooks?num_versions=2", map[string][]string{"apache2": {"10.0.0", "2.0.0"}, "nginx": {"1.0.0"}}},
		{"/cookbooks?num_versions=0", map[string][]string{"apache2": {}, "nginx": {}}},
		{"/cookbooks?num_versions=-0", map[string][]string{"apache2": {}, "nginx": {}}},
		{"/cookbooks?num_versions=%2B2", map[string][]string{"apache2": {"10.0.0", "2.0.0"}, "nginx": {"1.0.0"}}},
		{"/cookbooks?num_versions=99999999999999999999999", map[string][]string{"apache2": {"10.0.0", "2.0.0", "1.0.0"}, "nginx": {"1.0.0"}}},
		// chef_wm_cookbooks:to_json/3 always lists every version of one cookbook.
		{"/cookbooks/apache2", map[string][]string{"apache2": {"10.0.0", "2.0.0", "1.0.0"}}},
		{"/cookbooks/apache2?num_versions=1", map[string][]string{"apache2": {"10.0.0", "2.0.0", "1.0.0"}}},
		{"/environments/_default/cookbooks", map[string][]string{"apache2": {"10.0.0"}, "nginx": {"1.0.0"}}},
		{"/environments/_default/cookbooks?num_versions=all", map[string][]string{"apache2": {"10.0.0", "2.0.0", "1.0.0"}, "nginx": {"1.0.0"}}},
		{"/environments/_default/cookbooks?num_versions=0", map[string][]string{"apache2": {}, "nginx": {}}},
		{"/environments/_default/cookbooks/apache2", map[string][]string{"apache2": {"10.0.0", "2.0.0", "1.0.0"}}},
		{"/environments/_default/cookbooks/apache2?num_versions=1", map[string][]string{"apache2": {"10.0.0"}}},
	}
	for _, c := range cases {
		resp, body := doAt(t, "2", "GET", base+c.path, "")
		if resp.StatusCode != 200 {
			t.Errorf("GET %s = %d: %s", c.path, resp.StatusCode, body)
			continue
		}
		got := versionCounts(t, body)
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(c.want)
		if string(g) != string(w) {
			t.Errorf("GET %s versions = %s, want %s", c.path, g, w)
		}
	}
}

// chef_wm_util:parse_number/1 rejects anything that is not a non-negative
// integer or "all", on every route whose validate_request reads num_versions,
// before it looks up the cookbook or environment.
func TestCookbookListingRejectsInvalidNumVersions(t *testing.T) {
	base := seedNumVersionsCookbooks(t)
	const want = `{"error":["You have requested an invalid number of versions (x >= 0 || 'all')"]}`
	paths := []string{
		"/cookbooks",
		"/cookbooks/_latest",
		"/cookbooks/_recipes",
		"/cookbooks/apache2",
		"/cookbooks/ghost",
		"/environments/_default/cookbooks",
		"/environments/_default/cookbooks/apache2",
		"/environments/ghost/cookbooks",
	}
	for _, p := range paths {
		for _, nv := range []string{"-1", "abc", "", "1abc", "1.5", "ALL", " 1"} {
			u := base + p + "?num_versions=" + url.QueryEscape(nv)
			resp, body := doAt(t, "2", "GET", u, "")
			if resp.StatusCode != 400 || strings.TrimSpace(body) != want {
				t.Errorf("GET %s?num_versions=%q = %d %s, want 400 %s", p, nv, resp.StatusCode, body, want)
			}
		}
	}
}

// oc_chef_wm_named_cookbook_artifact never reads num_versions: artifact
// listings return every identifier, whatever the parameter says.
func TestCookbookArtifactListingIgnoresNumVersions(t *testing.T) {
	srv, _ := newTestAPI(t)
	base := srv.URL + "/organizations/acme"
	for _, id := range []string{"aaa111", "bbb222"} {
		if resp, body := doAt(t, "2", "PUT", base+"/cookbook_artifacts/apache/"+id, `{"name":"apache"}`); resp.StatusCode >= 300 {
			t.Fatalf("put artifact %s = %d: %s", id, resp.StatusCode, body)
		}
	}
	for _, p := range []string{"/cookbook_artifacts?num_versions=1", "/cookbook_artifacts?num_versions=abc", "/cookbook_artifacts/apache?num_versions=1"} {
		resp, body := doAt(t, "2", "GET", base+p, "")
		if resp.StatusCode != 200 {
			t.Errorf("GET %s = %d: %s", p, resp.StatusCode, body)
			continue
		}
		if n := len(versionCounts(t, body)["apache"]); n != 2 {
			t.Errorf("GET %s lists %d identifiers, want 2: %s", p, n, body)
		}
	}
}
